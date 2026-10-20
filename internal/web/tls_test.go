package web

import (
	"crypto/tls"
	"crypto/x509"
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
