// Package acmecert gets browser-trusted certificates for the web UI from
// Let's Encrypt, for the server's public IP address (no domain needed) or
// for a domain name, and renews them automatically.
package acmecert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// ShortLived is the Let's Encrypt profile IP address certificates require.
// They last about six days, so they renew every few days.
const ShortLived = "shortlived"

// SubscriberAgreement is what users agree to when turning this on.
const SubscriberAgreement = "https://letsencrypt.org/repository/"

// retryAfter is the wait after a failed attempt. Let's Encrypt allows only a
// few failed validations per hour, so retrying sooner would lock us out.
const retryAfter = time.Hour

// Status describes the trusted certificate.
type Status struct {
	Enabled    bool      `json:"enabled"`
	Ready      bool      `json:"ready"`
	Identifier string    `json:"identifier"`
	NotAfter   time.Time `json:"notAfter"`
	// Error is why the last attempt failed, in words a user can act on.
	Error string `json:"error"`
	// Working is true while a certificate is being requested.
	Working bool `json:"working"`
}

// Manager requests, stores and renews one certificate.
type Manager struct {
	// Dir holds the Let's Encrypt account key and the certificate.
	Dir string
	// Email is an optional contact address. Let's Encrypt no longer sends
	// expiry notices (since 2025) and adds given addresses to its mailing
	// list, so iptable-ui leaves it empty.
	Email string
	// Identifier is the public IP address or domain name to certify.
	Identifier string
	// DirectoryURL is the ACME server; empty means Let's Encrypt.
	DirectoryURL string
	// ChallengeAddr is where Let's Encrypt's check is answered; ":80" in use.
	ChallengeAddr string
	// HTTPClient talks to the ACME server; nil uses the default.
	HTTPClient *http.Client
	// Preflight reports a problem that would make validation fail anyway,
	// such as port 80 being forwarded to another machine.
	Preflight func() error

	mu      sync.Mutex
	current *tls.Certificate
	status  Status
}

// Certificate is the trusted certificate, or nil while there is none.
func (m *Manager) Certificate() *tls.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil || time.Now().After(m.status.NotAfter) {
		return nil
	}
	return m.current
}

// Status describes the certificate and the last attempt.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := m.status
	status.Identifier = m.Identifier
	return status
}

// LoadSaved uses a saved certificate when it is still valid for the
// identifier, so restarts do not request a new one.
func (m *Manager) LoadSaved() bool {
	certPEM, err := os.ReadFile(m.certFile())
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(m.keyFile())
	if err != nil {
		return false
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || !m.covers(cert) {
		return false
	}
	m.use(cert)
	return true
}

// Run keeps a valid certificate until ctx is done: it requests one when
// there is none, renews it once two thirds of its lifetime have passed, and
// waits an hour after a failure.
func (m *Manager) Run(ctx context.Context) {
	for {
		wait := m.untilRenewal()
		if wait <= 0 {
			if err := m.Obtain(ctx); err != nil {
				wait = retryAfter
			} else {
				wait = m.untilRenewal()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (m *Manager) untilRenewal() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil || m.current.Leaf == nil {
		return 0
	}
	lifetime := m.current.Leaf.NotAfter.Sub(m.current.Leaf.NotBefore)
	renewAt := m.current.Leaf.NotAfter.Add(-lifetime / 3)
	return time.Until(renewAt)
}

// Obtain requests a new certificate now.
func (m *Manager) Obtain(ctx context.Context) error {
	m.setWorking(true)
	err := m.obtain(ctx)
	m.mu.Lock()
	m.status.Working = false
	if err != nil {
		m.status.Error = err.Error()
	} else {
		m.status.Error = ""
	}
	m.mu.Unlock()
	return err
}

func (m *Manager) obtain(ctx context.Context) error {
	if m.Identifier == "" {
		return errors.New("no public IP address or domain is known for this server; set one with --domain")
	}
	if m.Preflight != nil {
		if err := m.Preflight(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	accountKey, err := m.accountKey()
	if err != nil {
		return err
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: m.DirectoryURL, HTTPClient: m.HTTPClient}
	account := &acme.Account{}
	if m.Email != "" {
		account.Contact = []string{"mailto:" + m.Email}
	}
	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("could not reach Let's Encrypt: %w", err)
	}
	ip := net.ParseIP(m.Identifier)
	ids := acme.DomainIDs(m.Identifier)
	var options []acme.OrderOption
	if ip != nil {
		ids = acme.IPIDs(m.Identifier)
		options = append(options, acme.WithOrderIssuanceProfile(ShortLived))
	}
	order, err := client.AuthorizeOrder(ctx, ids, options...)
	if err != nil {
		return fmt.Errorf("Let's Encrypt refused to start: %w", err)
	}
	for _, url := range order.AuthzURLs {
		if err := m.authorize(ctx, client, url); err != nil {
			return err
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("Let's Encrypt did not finish the order: %w", err)
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	request := &x509.CertificateRequest{}
	if ip != nil {
		request.IPAddresses = []net.IP{ip}
	} else {
		request.DNSNames = []string{m.Identifier}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, request, certKey)
	if err != nil {
		return err
	}
	chain, _, err := client.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return fmt.Errorf("Let's Encrypt did not issue the certificate: %w", err)
	}
	return m.save(chain, certKey)
}

// authorize proves control of the identifier with the http-01 challenge:
// Let's Encrypt fetches a token from this server on port 80.
func (m *Manager) authorize(ctx context.Context, client *acme.Client, url string) error {
	authorization, err := client.GetAuthorization(ctx, url)
	if err != nil {
		return err
	}
	if authorization.Status == acme.StatusValid {
		return nil
	}
	var challenge *acme.Challenge
	for _, offered := range authorization.Challenges {
		if offered.Type == "http-01" {
			challenge = offered
		}
	}
	if challenge == nil {
		return errors.New("Let's Encrypt did not offer the port 80 check")
	}
	response, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return err
	}
	stop, err := serveChallenge(m.challengeAddr(), client.HTTP01ChallengePath(challenge.Token), response)
	if err != nil {
		return err
	}
	defer stop()
	if _, err := client.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("Let's Encrypt did not accept the check: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authorization.URI); err != nil {
		return fmt.Errorf("Let's Encrypt could not reach this server on port 80 (allow port 80 in your VPS provider's firewall, and do not forward port 80 elsewhere): %w", err)
	}
	return nil
}

// serveChallenge answers Let's Encrypt's request for path, and nothing else,
// until stop is called.
func serveChallenge(addr, path, response string) (stop func(), err error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("port 80 is already in use by another program, and Let's Encrypt needs it to check this server: %w", err)
	}
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(response))
	})}
	go func() { _ = server.Serve(listener) }()
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}, nil
}

func (m *Manager) save(chain [][]byte, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return err
	}
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.keyFile(), keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(m.certFile(), certPEM, 0o644); err != nil {
		return err
	}
	m.use(cert)
	return nil
}

func (m *Manager) use(cert tls.Certificate) {
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.current = &cert
	if cert.Leaf != nil {
		m.status.NotAfter = cert.Leaf.NotAfter
	}
	m.status.Ready = true
}

// covers reports whether cert is for the identifier and not yet due for
// renewal.
func (m *Manager) covers(cert tls.Certificate) bool {
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.VerifyHostname(m.Identifier) != nil {
		return false
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	return time.Now().Before(leaf.NotAfter.Add(-lifetime / 3))
}

func (m *Manager) setWorking(working bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.Working = working
}

func (m *Manager) accountKey() (*ecdsa.PrivateKey, error) {
	path := filepath.Join(m.Dir, "account.key")
	if raw, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(raw); block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (m *Manager) challengeAddr() string {
	if m.ChallengeAddr == "" {
		return ":80"
	}
	return m.ChallengeAddr
}

// File names include the identifier, so a new IP or domain gets its own.
func (m *Manager) certFile() string {
	return filepath.Join(m.Dir, safeName(m.Identifier)+".crt")
}

func (m *Manager) keyFile() string {
	return filepath.Join(m.Dir, safeName(m.Identifier)+".key")
}

func safeName(identifier string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, identifier)
}

// Controller turns the trusted certificate on and off, keeping a Manager
// renewing in the background while it is on.
type Controller struct {
	Manager *Manager
	// Save remembers the choice, so it lasts across restarts.
	Save func(on bool) error

	mu     sync.Mutex
	cancel context.CancelFunc
}

// Enabled reports whether a trusted certificate is wanted.
func (c *Controller) Enabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cancel != nil
}

// SetEnabled starts or stops getting and renewing the certificate. It
// returns at once; the certificate arrives in the background.
func (c *Controller) SetEnabled(on bool) error {
	c.mu.Lock()
	if on && c.cancel == nil {
		ctx, cancel := context.WithCancel(context.Background())
		c.cancel = cancel
		c.Manager.LoadSaved()
		go c.Manager.Run(ctx)
	} else if !on && c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	c.mu.Unlock()
	if c.Save != nil {
		return c.Save(on)
	}
	return nil
}

// Certificate is the trusted certificate while it is on and ready.
func (c *Controller) Certificate() *tls.Certificate {
	if !c.Enabled() {
		return nil
	}
	return c.Manager.Certificate()
}

// Status describes the certificate.
func (c *Controller) Status() Status {
	status := c.Manager.Status()
	status.Enabled = c.Enabled()
	return status
}

// Stop ends background renewal without changing the saved choice.
func (c *Controller) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
}
