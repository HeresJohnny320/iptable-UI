package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// DefaultCertEmail is put in the self-signed certificate when no email is given.
const DefaultCertEmail = "admin@admin.com"

// certLifetime is how long a generated certificate is valid. It is renewed
// automatically once less than certRenewBefore is left.
const (
	certLifetime    = 2 * 365 * 24 * time.Hour
	certRenewBefore = 30 * 24 * time.Hour
)

// LoadCert reads a certificate and key the user supplied (PEM files).
func LoadCert(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load TLS certificate: %w", err)
	}
	return cert, nil
}

// SelfSignedCert loads the self-signed certificate saved in dir, or makes a
// new one when there is none, it is about to expire, or it no longer matches
// the email or hosts (for example after the server's IP changed). hosts are
// IP addresses or names the certificate must cover.
func SelfSignedCert(dir, email string, hosts []string) (tls.Certificate, error) {
	if email == "" {
		email = DefaultCertEmail
	}
	certFile, keyFile := filepath.Join(dir, "web-tls.crt"), filepath.Join(dir, "web-tls.key")
	if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil && certFits(cert, email, hosts) {
		return cert, nil
	}
	certPEM, keyPEM, err := newSelfSigned(email, hosts)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate folder: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("save TLS key: %w", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return tls.Certificate{}, fmt.Errorf("save TLS certificate: %w", err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func certFits(cert tls.Certificate, email string, hosts []string) bool {
	if len(cert.Certificate) == 0 {
		return false
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || time.Until(parsed.NotAfter) < certRenewBefore || !slices.Contains(parsed.EmailAddresses, email) {
		return false
	}
	for _, host := range hosts {
		if parsed.VerifyHostname(host) != nil {
			return false
		}
	}
	return true
}

func newSelfSigned(email string, hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate TLS key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "iptable-ui", Organization: []string{"iptable-ui"}},
		EmailAddresses:        []string{email},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if host != "" {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create TLS certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode TLS key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// CertFingerprint is the certificate's SHA-256 fingerprint in the format
// browsers show in their certificate details ("AB:CD:..."). Comparing it
// there with the one iptable-ui prints over SSH proves the browser is talking
// to this server and not to someone in between.
func CertFingerprint(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Certificate[0])
	parts := make([]string, len(sum))
	for index, value := range sum {
		parts[index] = fmt.Sprintf("%02X", value)
	}
	return strings.Join(parts, ":")
}
