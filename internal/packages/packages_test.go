package packages

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func only(name string) func(string) (string, error) {
	return func(candidate string) (string, error) {
		if candidate == name {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
}

func TestCommandsPerDistro(t *testing.T) {
	tests := []struct {
		manager string
		want    []string
	}{
		{"apt-get", []string{"apt-get update", "apt-get install -y wireguard-tools whiptail conntrack"}},
		{"dnf", []string{"dnf install -y wireguard-tools newt conntrack-tools"}},
		{"pacman", []string{"pacman -S --noconfirm --needed wireguard-tools libnewt conntrack-tools"}},
		{"zypper", []string{"zypper --non-interactive install wireguard-tools newt conntrack-tools"}},
		{"apk", []string{"apk update", "apk add wireguard-tools newt conntrack-tools"}},
	}
	for _, test := range tests {
		manager, ok := Detect(only(test.manager))
		if !ok || manager.Name != test.manager {
			t.Fatalf("%s not detected", test.manager)
		}
		commands := manager.Commands(WireGuard, Whiptail, Conntrack)
		got := make([]string, len(commands))
		for index, command := range commands {
			got[index] = strings.Join(command, " ")
		}
		if strings.Join(got, "\n") != strings.Join(test.want, "\n") {
			t.Errorf("%s: got %q, want %q", test.manager, got, test.want)
		}
	}
	if _, ok := Detect(only("brew")); ok {
		t.Fatal("unsupported package managers must not be detected")
	}
}

func TestOSName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := OSName(path); got != "Ubuntu 24.04.1 LTS" {
		t.Fatalf("got %q", got)
	}
	if got := OSName(filepath.Join(t.TempDir(), "missing")); got != "Linux" {
		t.Fatalf("missing file should give Linux, got %q", got)
	}
}
