// Package packages installs software with whichever package manager the
// Linux distribution uses, translating logical names to each distro's.
package packages

import (
	"bufio"
	"os"
	"strings"
)

// Manager is a distro package manager.
type Manager struct {
	Name string
	// update refreshes the package index before installing, when needed.
	update []string
	// install is the command prefix; package names are appended.
	install []string
	names   map[string]string
}

// Logical package names understood by Package.
const (
	WireGuard = "wireguard"
	Whiptail  = "whiptail"
	Conntrack = "conntrack"
	Curl      = "curl"
	IPTables  = "iptables"
)

var managers = []Manager{
	{Name: "apt-get", update: []string{"apt-get", "update"}, install: []string{"apt-get", "install", "-y"},
		names: map[string]string{WireGuard: "wireguard-tools", Whiptail: "whiptail", Conntrack: "conntrack"}},
	{Name: "dnf", install: []string{"dnf", "install", "-y"},
		names: map[string]string{WireGuard: "wireguard-tools", Whiptail: "newt", Conntrack: "conntrack-tools"}},
	{Name: "yum", install: []string{"yum", "install", "-y"},
		names: map[string]string{WireGuard: "wireguard-tools", Whiptail: "newt", Conntrack: "conntrack-tools"}},
	{Name: "pacman", install: []string{"pacman", "-S", "--noconfirm", "--needed"},
		names: map[string]string{WireGuard: "wireguard-tools", Whiptail: "libnewt", Conntrack: "conntrack-tools"}},
	{Name: "zypper", install: []string{"zypper", "--non-interactive", "install"},
		names: map[string]string{WireGuard: "wireguard-tools", Whiptail: "newt", Conntrack: "conntrack-tools"}},
	{Name: "apk", update: []string{"apk", "update"}, install: []string{"apk", "add"},
		names: map[string]string{WireGuard: "wireguard-tools", Whiptail: "newt", Conntrack: "conntrack-tools"}},
}

// Detect finds the first supported package manager on PATH.
func Detect(lookPath func(string) (string, error)) (Manager, bool) {
	for _, manager := range managers {
		if _, err := lookPath(manager.Name); err == nil {
			return manager, true
		}
	}
	return Manager{}, false
}

// Package translates a logical name to this distro's package name.
func (m Manager) Package(logical string) string {
	if name, ok := m.names[logical]; ok {
		return name
	}
	return logical
}

// Commands returns the commands that install the logical packages.
func (m Manager) Commands(logical ...string) [][]string {
	commands := make([][]string, 0, 2)
	if len(m.update) > 0 {
		commands = append(commands, m.update)
	}
	install := append([]string(nil), m.install...)
	for _, name := range logical {
		install = append(install, m.Package(name))
	}
	return append(commands, install)
}

// OSName reads the distro's display name from an os-release file.
func OSName(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return "Linux"
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if value, ok := strings.CutPrefix(scanner.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(value, `"'`)
		}
	}
	return "Linux"
}
