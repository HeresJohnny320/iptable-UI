package web

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"github.com/HeresJohnny320/iptable-ui/internal/backup"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func leaf(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestSelfSignedCertDefaultsAndReuse(t *testing.T) {
	dir := t.TempDir()
	hosts := []string{"localhost", "127.0.0.1", "203.0.113.5"}
	first, err := SelfSignedCert(dir, "", hosts)
	if err != nil {
		t.Fatal(err)
	}
	parsed := leaf(t, first)
	if !slices.Contains(parsed.EmailAddresses, DefaultCertEmail) {
		t.Fatalf("email = %v, want default %s", parsed.EmailAddresses, DefaultCertEmail)
	}
	for _, host := range hosts {
		if err := parsed.VerifyHostname(host); err != nil {
			t.Fatalf("certificate should cover %s: %v", host, err)
		}
	}
	again, err := SelfSignedCert(dir, DefaultCertEmail, hosts)
	if err != nil {
		t.Fatal(err)
	}
	if leaf(t, again).SerialNumber.Cmp(parsed.SerialNumber) != 0 {
		t.Fatal("an existing certificate that still fits should be reused")
	}
	changed, err := SelfSignedCert(dir, "me@example.com", hosts)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(leaf(t, changed).EmailAddresses, "me@example.com") {
		t.Fatal("a new email should make a new certificate")
	}
	moved, err := SelfSignedCert(dir, "me@example.com", []string{"198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	if leaf(t, moved).VerifyHostname("198.51.100.7") != nil {
		t.Fatal("a new IP should make a new certificate")
	}
}

func TestRuntimeServesHTTPS(t *testing.T) {
	cert, err := SelfSignedCert(t.TempDir(), "", []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime("session-secret", "127.0.0.1:0", Services{})
	runtime.UseTLS(cert)
	if _, err := runtime.Toggle(); err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if !strings.HasPrefix(runtime.URL(), "https://127.0.0.1:") || strings.Contains(runtime.StatusText(), "plain HTTP") {
		t.Fatalf("URL %s / status %s", runtime.URL(), runtime.StatusText())
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf(t, cert))
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	response, err := client.Get(runtime.URL())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("web root returned %d", response.StatusCode)
	}
	if plain, err := http.Get("http://" + runtime.Address() + "/"); err == nil && plain.StatusCode == http.StatusOK {
		t.Fatal("plain HTTP should not be served when HTTPS is on")
	}
}

func TestFingerprintMatchesWhatTheBrowserSees(t *testing.T) {
	cert, err := SelfSignedCert(t.TempDir(), "", []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime("session-secret", "127.0.0.1:0", Services{})
	if runtime.Fingerprint() != "" {
		t.Fatal("plain HTTP has no fingerprint")
	}
	runtime.UseTLS(cert)
	if _, err := runtime.Toggle(); err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	// Connect without trusting anything, like a browser on its first visit,
	// and fingerprint the certificate the server actually presents.
	connection, err := tls.Dial("tcp", runtime.Address(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	presented := connection.ConnectionState().PeerCertificates[0].Raw
	connection.Close()
	sum := sha256.Sum256(presented)
	want := strings.ToUpper(hex.EncodeToString(sum[:]))
	got := strings.ReplaceAll(runtime.Fingerprint(), ":", "")
	if got != want || len(runtime.Fingerprint()) != 95 {
		t.Fatalf("fingerprint %s does not match the presented certificate %s", runtime.Fingerprint(), want)
	}
}

func TestDownloadLinksWorkOnce(t *testing.T) {
	services, _, manager := newBackupServices(t)
	info, _, err := manager.Create(context.Background(), backup.Manual)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime("session-secret", "127.0.0.1:0", services)
	if _, err := runtime.Toggle(); err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	link, err := runtime.DownloadLink(info.Name)
	if err != nil {
		t.Fatal(err)
	}
	for attempt, want := range []int{http.StatusOK, http.StatusNotFound} {
		response, err := http.Get(link)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("attempt %d returned %d, want %d", attempt+1, response.StatusCode, want)
		}
	}
}

func TestTrustedCertificateReplacesSelfSignedWithoutRestart(t *testing.T) {
	selfSigned, err := SelfSignedCert(t.TempDir(), "", []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := SelfSignedCert(t.TempDir(), "other@example.org", []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime("session-secret", "127.0.0.1:0", Services{})
	runtime.UseTLS(selfSigned)
	var ready *tls.Certificate
	runtime.UseTrusted(func() *tls.Certificate { return ready })
	if _, err := runtime.Toggle(); err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	presented := func() string {
		connection, err := tls.Dial("tcp", runtime.Address(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		return CertFingerprint(tls.Certificate{Certificate: [][]byte{connection.ConnectionState().PeerCertificates[0].Raw}})
	}
	if runtime.Trusted() || presented() != CertFingerprint(selfSigned) || runtime.Fingerprint() != CertFingerprint(selfSigned) {
		t.Fatal("until the trusted certificate is ready, the self-signed one is served")
	}
	ready = &trusted
	if !runtime.Trusted() || presented() != CertFingerprint(trusted) || runtime.Fingerprint() != CertFingerprint(trusted) {
		t.Fatal("once ready, the trusted certificate is served on the next connection")
	}
}
