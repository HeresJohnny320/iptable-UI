package acmecert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestObtainFromPebble runs the whole Let's Encrypt flow against Pebble, the
// Let's Encrypt test server. Run it with PEBBLE_BIN (the pebble binary) and
// PEBBLE_DIR (its source folder, for the test certificates) set.
func TestObtainFromPebble(t *testing.T) {
	binary, source := os.Getenv("PEBBLE_BIN"), os.Getenv("PEBBLE_DIR")
	if binary == "" || source == "" {
		t.Skip("set PEBBLE_BIN and PEBBLE_DIR to run against the Pebble ACME test server")
	}
	config := filepath.Join(t.TempDir(), "pebble.json")
	if err := os.WriteFile(config, []byte(`{"pebble": {
		"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
		"certificate": "`+source+`/test/certs/localhost/cert.pem", "privateKey": "`+source+`/test/certs/localhost/key.pem",
		"httpPort": 5002, "tlsPort": 5001, "keyAlgorithm": "ecdsa",
		"profiles": {"default": {"description": "default", "validityPeriod": 7776000},
		             "shortlived": {"description": "short", "validityPeriod": 518400}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	server := exec.Command(binary, "-config", config)
	server.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1")
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Process.Kill()
	roots := x509.NewCertPool()
	minica, err := os.ReadFile(filepath.Join(source, "test/certs/pebble.minica.pem"))
	if err != nil || !roots.AppendCertsFromPEM(minica) {
		t.Fatalf("read Pebble's test CA: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	for start := time.Now(); ; time.Sleep(100 * time.Millisecond) {
		if response, err := client.Get("https://127.0.0.1:14000/dir"); err == nil {
			response.Body.Close()
			break
		}
		if time.Since(start) > 10*time.Second {
			t.Fatal("Pebble did not start")
		}
	}

	dir := t.TempDir()
	manager := &Manager{Dir: dir, Identifier: "127.0.0.1", DirectoryURL: "https://127.0.0.1:14000/dir",
		ChallengeAddr: "127.0.0.1:5002", HTTPClient: client, Email: "admin@example.org"}
	if err := manager.Obtain(context.Background()); err != nil {
		t.Fatalf("obtain: %v", err)
	}
	cert := manager.Certificate()
	if cert == nil || cert.Leaf == nil || len(cert.Leaf.IPAddresses) != 1 || !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected a certificate for 127.0.0.1, got %+v", cert)
	}
	if lifetime := cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore); lifetime > 7*24*time.Hour {
		t.Fatalf("an IP certificate must use the short-lived profile, got %v", lifetime)
	}
	if status := manager.Status(); !status.Ready || status.Error != "" || status.Working {
		t.Fatalf("status after obtaining: %+v", status)
	}
	if wait := manager.untilRenewal(); wait < 3*24*time.Hour || wait > 5*24*time.Hour {
		t.Fatalf("a six-day certificate should renew after about four days, got %v", wait)
	}
	reloaded := &Manager{Dir: dir, Identifier: "127.0.0.1"}
	if !reloaded.LoadSaved() || reloaded.Certificate() == nil {
		t.Fatal("the saved certificate should be reused after a restart")
	}
	if other := (&Manager{Dir: dir, Identifier: "127.0.0.2"}); other.LoadSaved() {
		t.Fatal("a certificate for another IP must not be reused")
	}
}

func TestPreflightProblemIsReported(t *testing.T) {
	manager := &Manager{Dir: t.TempDir(), Identifier: "203.0.113.5", Preflight: func() error {
		return errors.New("port 80 is forwarded to 10.66.0.2 by rule #3")
	}}
	err := manager.Obtain(context.Background())
	if err == nil || !strings.Contains(manager.Status().Error, "rule #3") || manager.Certificate() != nil {
		t.Fatalf("a preflight problem must stop the request and show why: %v %+v", err, manager.Status())
	}
}

func TestMissingIdentifierIsExplained(t *testing.T) {
	if err := (&Manager{Dir: t.TempDir()}).Obtain(context.Background()); err == nil || !strings.Contains(err.Error(), "--domain") {
		t.Fatalf("got %v", err)
	}
}

func TestChallengeServerAnswersOnlyItsToken(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serveChallenge(busy.Addr().String(), "/x", "y"); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("a busy port should be explained, got %v", err)
	}
	addr := busy.Addr().String()
	busy.Close()
	stop, err := serveChallenge(addr, "/.well-known/acme-challenge/token", "token.key")
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for path, want := range map[string]int{"/.well-known/acme-challenge/token": http.StatusOK, "/": http.StatusNotFound, "/.well-known/acme-challenge/other": http.StatusNotFound} {
		response, err := http.Get("http://" + addr + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != want {
			t.Errorf("%s returned %d, want %d", path, response.StatusCode, want)
		}
	}
}

func TestControllerSwitchesAndSaves(t *testing.T) {
	saved := []bool{}
	controller := &Controller{
		Manager: &Manager{Dir: t.TempDir(), Identifier: "203.0.113.5", Preflight: func() error { return errors.New("not in tests") }},
		Save:    func(on bool) error { saved = append(saved, on); return nil },
	}
	if controller.Enabled() || controller.Certificate() != nil {
		t.Fatal("off by default")
	}
	if err := controller.SetEnabled(true); err != nil || !controller.Enabled() {
		t.Fatalf("turning on: %v", err)
	}
	for start := time.Now(); controller.Status().Error == "" && time.Since(start) < 2*time.Second; time.Sleep(10 * time.Millisecond) {
	}
	if status := controller.Status(); !status.Enabled || status.Ready || !strings.Contains(status.Error, "not in tests") {
		t.Fatalf("the background attempt should run and report its problem: %+v", status)
	}
	if err := controller.SetEnabled(false); err != nil || controller.Enabled() {
		t.Fatalf("turning off: %v", err)
	}
	if len(saved) != 2 || !saved[0] || saved[1] {
		t.Fatalf("each change should be saved: %v", saved)
	}
}
