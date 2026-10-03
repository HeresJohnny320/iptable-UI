package main

import (
	"context"
	"encoding/hex"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/backup"
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
