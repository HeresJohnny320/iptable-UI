package web

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Runtime struct {
	mu       sync.Mutex
	token    string
	address  string
	services Services
	server   *http.Server
	listener net.Listener
	// linkHost is shown in links when the server listens on every address.
	linkHost string
	// savePort persists a port chosen in the UI.
	savePort func(int) error
	links    map[string]downloadLink
	// tlsConfig is set when the web UI serves HTTPS; fingerprint identifies
	// its certificate.
	tlsConfig *tls.Config
	// fallback is the self-signed (or your own) certificate; trusted, when
	// set and ready, is a browser-trusted one that replaces it.
	fallback tls.Certificate
	trusted  func() *tls.Certificate
}

type downloadLink struct {
	path, name string
	expires    time.Time
}

// LinkLifetime is how long a backup download link works.
const LinkLifetime = 10 * time.Minute

func NewRuntime(token, address string, services Services) *Runtime {
	return &Runtime{token: token, address: address, services: services, links: make(map[string]downloadLink)}
}

// SetLinkHost sets the host name or IP shown in links when the web UI
// listens on all addresses (0.0.0.0), usually the server's public IP.
func (r *Runtime) SetLinkHost(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.linkHost = host
}

// OnPortChange registers how to save a port chosen in the UI.
func (r *Runtime) OnPortChange(save func(int) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.savePort = save
}

// UseTLS makes the web UI serve HTTPS with the given certificate. Call it
// before the server starts.
func (r *Runtime) UseTLS(cert tls.Certificate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fallback = cert
	// The certificate is picked for every connection, so a trusted one that
	// arrives later is used at once, without restarting the web UI.
	r.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return r.servedCertificate(), nil
	}}
}

// SetCertificates lets the web UI turn the trusted certificate on and off.
// Call it before the server starts.
func (r *Runtime) SetCertificates(control CertificateControl) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.services.Certificates = control
}

// UseTrusted serves the certificate from source whenever it has one, such
// as a Let's Encrypt certificate, falling back to the UseTLS certificate.
func (r *Runtime) UseTrusted(source func() *tls.Certificate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trusted = source
}

// Trusted reports whether the web UI is serving a browser-trusted
// certificate from UseTrusted right now.
func (r *Runtime) Trusted() bool {
	r.mu.Lock()
	source := r.trusted
	r.mu.Unlock()
	return source != nil && source() != nil
}

func (r *Runtime) servedCertificate() *tls.Certificate {
	r.mu.Lock()
	source, fallback := r.trusted, r.fallback
	r.mu.Unlock()
	if source != nil {
		if cert := source(); cert != nil {
			return cert
		}
	}
	return &fallback
}

// Fingerprint is the SHA-256 fingerprint of the certificate being served,
// or "" when the web UI serves plain HTTP.
func (r *Runtime) Fingerprint() string {
	if !r.HTTPS() {
		return ""
	}
	return CertFingerprint(*r.servedCertificate())
}

// HTTPS reports whether the web UI serves HTTPS.
func (r *Runtime) HTTPS() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tlsConfig != nil
}

// serve starts a server on listener, wrapped in TLS when it is on. Call with
// r.mu held.
func (r *Runtime) serve(listener net.Listener) *http.Server {
	if r.tlsConfig != nil {
		listener = tls.NewListener(listener, r.tlsConfig)
	}
	// Browsers that reject the self-signed certificate cause handshake
	// errors; logging them would draw over the TUI.
	server := &http.Server{Handler: r.handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = server.Serve(listener) }()
	return server
}

func (r *Runtime) handler() http.Handler {
	services := r.services
	services.Downloads = r
	services.Port = r
	return Handler(r.token, services)
}

// Port is the TCP port the web UI uses (or will use when started).
func (r *Runtime) Port() int {
	_, port, _ := net.SplitHostPort(r.Address())
	number, _ := strconv.Atoi(port)
	return number
}

// SetPort moves the web UI to another port and saves it. A running server
// moves at once: the new port starts first, then the old one stops a moment
// later so the request that asked for the move still gets its answer.
func (r *Runtime) SetPort(port int) (string, error) {
	if port < 1 || port > 65535 {
		return "", errors.New("port must be between 1 and 65535")
	}
	r.mu.Lock()
	host, _, err := net.SplitHostPort(r.address)
	if err != nil {
		r.mu.Unlock()
		return "", fmt.Errorf("invalid web address: %w", err)
	}
	newAddress := net.JoinHostPort(host, strconv.Itoa(port))
	var old *http.Server
	if newAddress != r.address && r.server != nil {
		listener, err := net.Listen("tcp", newAddress)
		if err != nil {
			r.mu.Unlock()
			return "", fmt.Errorf("cannot use port %d: %w", port, err)
		}
		old = r.server
		r.server, r.listener = r.serve(listener), listener
	}
	r.address = newAddress
	save, url := r.savePort, r.baseURL()
	r.mu.Unlock()
	if old != nil {
		go func() {
			time.Sleep(time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = old.Shutdown(ctx)
		}()
	}
	if save != nil {
		if err := save(port); err != nil {
			return url, fmt.Errorf("the web UI moved to port %d, but it could not be saved for next time: %w", port, err)
		}
	}
	return url, nil
}

// DownloadLink returns a link that downloads a backup without signing in.
// It works once, expires after LinkLifetime, and needs the web UI running.
func (r *Runtime) DownloadLink(name string) (string, error) {
	if r.services.Backups == nil {
		return "", errors.New("backups are unavailable")
	}
	path, err := r.services.Backups.Path(name)
	if err != nil {
		return "", err
	}
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	token := hex.EncodeToString(secret)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.server == nil {
		return "", errors.New("the web UI is off; turn it on to get a download link")
	}
	now := time.Now()
	for key, link := range r.links {
		if now.After(link.expires) {
			delete(r.links, key)
		}
	}
	r.links[token] = downloadLink{path: path, name: name, expires: now.Add(LinkLifetime)}
	return r.baseURL() + "/download/" + token, nil
}

// Resolve finds the backup behind an unexpired download link.
func (r *Runtime) Resolve(token string) (path, name string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	link, found := r.links[token]
	if !found || time.Now().After(link.expires) {
		return "", "", false
	}
	// A link works once, so one that leaks (shell history, a shared screen)
	// cannot be used to download the backup again.
	delete(r.links, token)
	return link.path, link.name, true
}

// baseURL is the address people use to reach the web UI. Call with r.mu held.
func (r *Runtime) baseURL() string {
	host, port, _ := net.SplitHostPort(r.address)
	if address, err := netip.ParseAddr(host); err == nil && address.IsUnspecified() {
		host = r.linkHost
		if host == "" {
			host = "<this-server-ip>"
		}
	}
	scheme := "http://"
	if r.tlsConfig != nil {
		scheme = "https://"
	}
	return scheme + net.JoinHostPort(host, port)
}

func (r *Runtime) Toggle() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := r.server.Shutdown(ctx); err != nil {
			return true, fmt.Errorf("stop web UI: %w", err)
		}
		r.server = nil
		r.listener = nil
		return false, nil
	}
	listener, err := r.listen()
	if err != nil {
		return false, err
	}
	r.listener = listener
	r.server = r.serve(listener)
	return true, nil
}

func (r *Runtime) Enabled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.server != nil
}

func (r *Runtime) Address() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.address
}

func (r *Runtime) Token() string { return r.token }

func (r *Runtime) Close() error {
	if !r.Enabled() {
		return nil
	}
	_, err := r.Toggle()
	return err
}

func (r *Runtime) listen() (net.Listener, error) {
	host, _, err := net.SplitHostPort(r.address)
	if err != nil {
		return nil, fmt.Errorf("invalid web address: %w", err)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, errors.New("web UI bind address must be an IP address, such as 127.0.0.1 or 0.0.0.0")
	}
	listener, err := net.Listen("tcp", r.address)
	if err != nil {
		return nil, fmt.Errorf("listen for web UI: %w", err)
	}
	r.address = listener.Addr().String()
	return listener, nil
}

func (r *Runtime) StatusText() string {
	bindHost, _, _ := net.SplitHostPort(r.Address())
	bindIP := net.ParseIP(bindHost)
	publicBind := bindIP != nil && (bindIP.IsUnspecified() || !bindIP.IsLoopback())
	r.mu.Lock()
	url, secure := r.baseURL(), r.tlsConfig != nil
	r.mu.Unlock()
	if r.Enabled() {
		status := "ON at " + url
		if publicBind && !secure {
			status += " (plain HTTP)"
		}
		return status
	}
	status := "OFF; will use " + url + "; press W to start"
	if publicBind && !secure {
		status += " (restrict access)"
	}
	return status
}

// MaskedStatusText is StatusText with the IP address masked for display.
func (r *Runtime) MaskedStatusText() string {
	base := strings.TrimSuffix(r.URL(), "/")
	return strings.Replace(r.StatusText(), base, strings.TrimSuffix(MaskURL(base+"/"), "/"), 1)
}

// URL is the address to open the web UI at, with the server's IP in place
// of 0.0.0.0, so it can be clicked or typed into a browser.
func (r *Runtime) URL() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.baseURL() + "/"
}

// SignInURL opens the web UI already signed in. The token travels in the
// URL fragment, which browsers never send to the server.
func (r *Runtime) SignInURL() string {
	return r.URL() + "#token=" + r.token
}
