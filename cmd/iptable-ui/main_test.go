package main

import (
	"context"
	"encoding/hex"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/backup"
	"github.com/HeresJohnny320/iptable-ui/internal/firewall"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
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
