package main

import (
	"encoding/hex"
	"testing"
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
