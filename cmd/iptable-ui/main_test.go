package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/backup"
	"github.com/HeresJohnny320/iptable-ui/internal/firewall"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/web"
)

func TestNewTokenRotatesWithStrongRandomValue(t *testing.T) {
	first, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 64 || first == second {
		t.Fatalf("expected distinct 256-bit tokens, got %q and %q", first, second)
	}
	if _, err := hex.DecodeString(first); err != nil {
		t.Fatalf("token is not hexadecimal: %v", err)
	}
}

func TestParseOptionsWebControls(t *testing.T) {
	defaultWeb, err := parseOptions("tui", []string{"--public-if", "ens3"})
	if err != nil || !defaultWeb.webEnabled || defaultWeb.webAddress != "0.0.0.0:8787" {
		t.Fatalf("web UI should default to an active wildcard listener: %+v, %v", defaultWeb, err)
	}
	webEnabled, err := parseOptions("tui", []string{"--public-if", "ens3", "--web"})
	if err != nil || !webEnabled.webEnabled {
		t.Fatalf("--web should enable the web UI: %+v, %v", webEnabled, err)
	}
	webDisabled, err := parseOptions("tui", []string{"--public-if", "ens3", "--no-web"})
	if err != nil || webDisabled.webEnabled {
		t.Fatalf("--no-web should leave the web UI off: %+v, %v", webDisabled, err)
	}
	if _, err := parseOptions("tui", []string{"--public-if", "ens3", "--web", "--no-web"}); err == nil {
		t.Fatal("using both web toggles should be rejected")
	}
	loopback, err := parseOptions("tui", []string{"--public-if", "ens3", "--web-address", "127.0.0.1:8787"})
	if err != nil || loopback.webAddress != "127.0.0.1:8787" {
		t.Fatalf("loopback override should be honored: %+v, %v", loopback, err)
	}
}

func TestPublicWebBindDetection(t *testing.T) {
	if isPublicWebBind("127.0.0.1:8787") {
		t.Fatal("loopback bind should not be considered public")
	}
	if !isPublicWebBind("0.0.0.0:8787") || !isPublicWebBind("[::]:8787") {
		t.Fatal("wildcard binds should be considered public")
	}
}

func TestNeedsRoot(t *testing.T) {
	tests := []struct {
		args []string
		want bool
	}{
		{nil, true},
		{[]string{"--web-address", "127.0.0.1:8787"}, true},
		{[]string{"setup"}, true},
		{[]string{"reconcile"}, true},
		{[]string{"install"}, true},
		{[]string{"wireguard", "install"}, true},
		{[]string{"list"}, false},
		{[]string{"wireguard", "status"}, false},
		{[]string{"--help"}, false},
		{[]string{"setup", "-h"}, false},
	}
	for _, test := range tests {
		if got := needsRoot(test.args); got != test.want {
			t.Errorf("needsRoot(%q) = %v, want %v", test.args, got, test.want)
		}
	}
}

func TestSavedWebPortIsUsedUnlessFlagGiven(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if got := savedWebAddress(database, "0.0.0.0:8787"); got != "0.0.0.0:8787" {
		t.Fatalf("without a saved port the default stays, got %q", got)
	}
	_ = database.SetSetting(context.Background(), webPortSetting, "9443")
	if got := savedWebAddress(database, "0.0.0.0:8787"); got != "0.0.0.0:9443" {
		t.Fatalf("saved port should apply, got %q", got)
	}
	_ = database.SetSetting(context.Background(), webPortSetting, "nonsense")
	if got := savedWebAddress(database, "0.0.0.0:8787"); got != "0.0.0.0:8787" {
		t.Fatalf("a bad saved port must be ignored, got %q", got)
	}
	explicit, err := parseOptions("tui", []string{"--public-if", "ens3", "--web-address", "127.0.0.1:9000"})
	if err != nil || !explicit.webAddressSet {
		t.Fatalf("--web-address should be detected as explicit: %+v %v", explicit, err)
	}
	implicit, err := parseOptions("tui", []string{"--public-if", "ens3"})
	if err != nil || implicit.webAddressSet {
		t.Fatalf("no --web-address means the saved port may apply: %+v %v", implicit, err)
	}
}

func TestDefaultBackupFolderUsesTheSudoUsersHome(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	t.Setenv("SUDO_USER", current.Username)
	if got := defaultBackupFolder(); got != filepath.Join(current.HomeDir, "iptable-ui-backups") {
		t.Fatalf("got %q, want the sudo user's home", got)
	}
	t.Setenv("SUDO_USER", "")
	t.Setenv("HOME", "/tmp/somebody")
	if got := defaultBackupFolder(); got != "/tmp/somebody/iptable-ui-backups" {
		t.Fatalf("without sudo the current user's home is used, got %q", got)
	}
}

func TestBackupFolderIsMovedOnceThenRemembered(t *testing.T) {
	directory := t.TempDir()
	database, err := store.Open(filepath.Join(directory, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager := &backup.Manager{Store: database, Dir: filepath.Join(directory, "db-backups"),
		SaveFolder: func(dir string) error { return database.SetSetting(context.Background(), backup.FolderSetting, dir) }}
	old, _, err := manager.Create(context.Background(), backup.Manual)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUDO_USER", "")
	t.Setenv("HOME", filepath.Join(directory, "home"))
	if err := os.MkdirAll(filepath.Join(directory, "home"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := useBackupFolder(database, manager); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(directory, "home", "iptable-ui-backups")
	if manager.Folder() != want {
		t.Fatalf("folder %q, want %q", manager.Folder(), want)
	}
	if _, err := os.Stat(filepath.Join(want, old.Name)); err != nil {
		t.Fatal("existing backups should move to the new folder")
	}
	// Next start: the saved folder is used as is.
	again := &backup.Manager{Store: database, Dir: filepath.Join(directory, "db-backups")}
	if err := useBackupFolder(database, again); err != nil || again.Folder() != want {
		t.Fatalf("saved folder not reused: %q %v", again.Folder(), err)
	}
}

func TestTakeoverNotice(t *testing.T) {
	legacy := []firewall.ExistingRule{
		{Rule: store.Rule{PublicPort: 25565, DestIP: "10.66.0.2", DestPort: 25565, Protocol: "tcp"}, Legacy: true, AnyCount: 1},
		{Rule: store.Rule{PublicPort: 8080, DestIP: "10.66.0.3", DestPort: 80, Protocol: "tcp"}, Legacy: true, Count: 1},
	}
	discovered := append([]firewall.ExistingRule{{Rule: store.Rule{PublicPort: 443, DestIP: "10.66.0.4", DestPort: 443, Protocol: "tcp"}}}, legacy...)
	if got := legacyRules(discovered); len(got) != 2 {
		t.Fatalf("only other tools' forwards are legacy: %+v", got)
	}
	if kept := withoutLegacy(discovered); len(kept) != 1 || kept[0].Rule.PublicPort != 443 {
		t.Fatalf("declining must keep only iptable-ui's own forwards: %+v", kept)
	}

	var first strings.Builder
	takeoverNotice(&first, true, legacy, "ens3", "/var/lib/iptable-ui/backups")
	for _, expected := range []string{
		"Before iptable-ui starts",
		"older scripts that manage those forwards will not find them",
		"remove rules by line number may remove the",
		"Docker, ufw or Tailscale",
		"/var/lib/iptable-ui/backups",
		"Found 2 port forward(s) made by another tool",
		"25565/tcp -> 10.66.0.2:25565 (any adapter)",
		"8080/tcp -> 10.66.0.3:80 (on ens3)",
	} {
		if !strings.Contains(first.String(), expected) {
			t.Errorf("first-run notice missing %q:\n%s", expected, first.String())
		}
	}

	var later strings.Builder
	takeoverNotice(&later, false, legacy[:1], "ens3", "/var/lib/iptable-ui/backups")
	if strings.Contains(later.String(), "Before iptable-ui starts") || !strings.Contains(later.String(), "Found 1 new port forward(s)") {
		t.Fatalf("later runs should only mention the new forwards:\n%s", later.String())
	}

	var empty strings.Builder
	takeoverNotice(&empty, true, nil, "ens3", "/var/lib/iptable-ui/backups")
	if !strings.Contains(empty.String(), "nothing will be imported") {
		t.Fatalf("with nothing found the notice should say so:\n%s", empty.String())
	}
}

func TestAskCertEmail(t *testing.T) {
	cases := map[string]string{
		"\n":                         web.DefaultCertEmail,
		"":                           web.DefaultCertEmail,
		"me@example.com\n":           "me@example.com",
		"nope\n  me@example.com \n":  "me@example.com",
		"nope\n\n":                   web.DefaultCertEmail,
		"Me <me@example.com>\nx@y\n": "x@y",
	}
	for input, want := range cases {
		var out strings.Builder
		if got := askCertEmail(strings.NewReader(input), &out); got != want {
			t.Errorf("askCertEmail(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestUseTLSSavesEmail(t *testing.T) {
	dir := t.TempDir()
	database, err := store.Open(filepath.Join(dir, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	config := options{database: filepath.Join(dir, "rules.db"), webAddress: "127.0.0.1:0", tlsEmail: "me@example.com"}
	runtime := web.NewRuntime("token", config.webAddress, web.Services{})
	if err := useTLS(runtime, database, config); err != nil {
		t.Fatal(err)
	}
	if !runtime.HTTPS() {
		t.Fatal("HTTPS should be on")
	}
	config.tlsEmail = ""
	if err := useTLS(runtime, database, config); err != nil {
		t.Fatal(err)
	}
	if saved, _ := database.Setting(context.Background(), webTLSEmailSetting); saved != "me@example.com" {
		t.Fatalf("saved email = %q", saved)
	}
	config.tlsEmail = "not an email"
	if err := useTLS(runtime, database, config); err == nil {
		t.Fatal("an invalid --tls-email should be refused")
	}
}

func TestExplainCertificateSaysWhenItIsNew(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var first, again, changed, own strings.Builder
	if err := explainCertificate(&first, database, "AA:BB", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(first.String(), "AA:BB") || !strings.Contains(first.String(), "This certificate is new") {
		t.Fatalf("first start should explain the new certificate:\n%s", first.String())
	}
	_ = explainCertificate(&again, database, "AA:BB", false)
	if !strings.Contains(again.String(), "Same certificate as last time") || !strings.Contains(again.String(), "do not") {
		t.Fatalf("a known certificate should say an unexpected warning means trouble:\n%s", again.String())
	}
	_ = explainCertificate(&changed, database, "CC:DD", false)
	if !strings.Contains(changed.String(), "This certificate is new") {
		t.Fatalf("a replaced certificate should be announced:\n%s", changed.String())
	}
	_ = explainCertificate(&own, database, "EE:FF", true)
	if !strings.Contains(own.String(), "EE:FF") || strings.Contains(own.String(), "warn") {
		t.Fatalf("your own trusted certificate needs no warning:\n%s", own.String())
	}
}

type noFirewall struct{}

func (noFirewall) Reconcile(context.Context, []store.Rule) error { return nil }

func TestLetsEncryptPreflight(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	service := app.Service{Store: database, Firewall: noFirewall{}}
	if err := letsEncryptPreflight(service, "203.0.113.5")(); err != nil {
		t.Fatalf("a public IP with nothing on port 80 is fine: %v", err)
	}
	for _, private := range []string{"10.0.0.5", "192.168.1.20", "127.0.0.1"} {
		if err := letsEncryptPreflight(service, private)(); err == nil || !strings.Contains(err.Error(), "--domain") {
			t.Errorf("%s should be refused with advice, got %v", private, err)
		}
	}
	if _, err := service.Add(context.Background(), store.Rule{PublicPort: 80, DestIP: "10.66.0.3", DestPort: 8080, Protocol: "udp"}); err != nil {
		t.Fatal(err)
	}
	if err := letsEncryptPreflight(service, "203.0.113.5")(); err != nil {
		t.Fatalf("a UDP-only rule on port 80 does not get in the way: %v", err)
	}
	web, err := service.Add(context.Background(), store.Rule{PublicPort: 80, DestIP: "10.66.0.2", DestPort: 80, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if err := letsEncryptPreflight(service, "203.0.113.5")(); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("rule #%d", web.ID)) {
		t.Fatalf("a forward on port 80 should be named, got %v", err)
	}
	if _, err := service.SetEnabled(context.Background(), web.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := letsEncryptPreflight(service, "203.0.113.5")(); err != nil {
		t.Fatalf("a switched-off forward does not get in the way: %v", err)
	}
}

func TestLetsEncryptFlags(t *testing.T) {
	on, err := parseOptions("tui", []string{"--public-if", "ens3", "--letsencrypt", "--domain", "vps.example.org"})
	if err != nil || on.letsEncrypt != "on" || on.domain != "vps.example.org" {
		t.Fatalf("%+v %v", on, err)
	}
	if off, err := parseOptions("tui", []string{"--public-if", "ens3", "--no-letsencrypt"}); err != nil || off.letsEncrypt != "off" {
		t.Fatalf("%+v %v", off, err)
	}
	if unset, _ := parseOptions("tui", []string{"--public-if", "ens3"}); unset.letsEncrypt != "" {
		t.Fatal("without a flag the saved choice applies")
	}
	for _, args := range [][]string{{"--letsencrypt", "--no-letsencrypt"}, {"--letsencrypt", "--http"}, {"--letsencrypt", "--tls-cert", "a", "--tls-key", "b"}} {
		if _, err := parseOptions("tui", append([]string{"--public-if", "ens3"}, args...)); err == nil {
			t.Errorf("%v should be refused", args)
		}
	}
}
