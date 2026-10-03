// Package system manages the host settings a VPS port-forwarding gateway needs
// beyond its iptables rules: IPv4 packet forwarding, the VPN tunnel interface,
// and restoring saved rules after a reboot.
package system

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	RestoreUnit       = "iptable-ui-restore.service"
	forwardKey        = "net.ipv4.ip_forward"
	forwardDropIn     = "/etc/sysctl.d/99-iptable-ui-forward.conf"
	sysctlConf        = "/etc/sysctl.conf"
	procForward       = "/proc/sys/net/ipv4/ip_forward"
	sysClassNet       = "/sys/class/net"
	unitDir           = "/etc/systemd/system"
	unitWantsDir      = "/etc/systemd/system/multi-user.target.wants"
	managedFileHeader = "# Managed by iptable-ui. Remove this file to stop managing IPv4 forwarding.\n"
)

// sysctlDirs are read at boot in this priority order; a file in an earlier
// directory hides a same-named file in a later one.
var sysctlDirs = []string{"/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"}

var unitArgPattern = regexp.MustCompile(`^[A-Za-z0-9/._:@+=,-]+$`)

type Runner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type Status struct {
	Forwarding      bool   `json:"forwarding"`
	PublicInterface string `json:"publicInterface"`
	VPNInterface    string `json:"vpnInterface"`
	VPNUp           bool   `json:"vpnUp"`
	// VPNKind names the VPN (WireGuard, Tailscale, NetBird, ...) and
	// VPNAddress is this server's IPv4 address on it.
	VPNKind     string `json:"vpnKind"`
	VPNAddress  string `json:"vpnAddress"`
	BootRestore bool   `json:"bootRestore"`
}

type Host struct {
	// Root prefixes every host path; empty means "/". Tests point it at a temp dir.
	Root            string
	Runner          Runner
	PublicInterface string
	VPNInterface    string
	// IPv4Lookup reports whether an interface has an IPv4 address; nil asks
	// the live system. Tests replace it.
	IPv4Lookup func(name string) bool
	// IPv4Address returns an interface's IPv4 address; nil asks the live system.
	IPv4Address func(name string) string
	// RestoreCommand is the ExecStart command line of the boot restore unit.
	RestoreCommand []string
}

func (h Host) Status(context.Context) Status {
	return Status{
		Forwarding:      h.forwardingEnabled(),
		PublicInterface: h.PublicInterface,
		VPNInterface:    h.VPNInterface,
		VPNUp:           h.interfaceUp(h.VPNInterface),
		VPNKind:         VPNKind(h.VPNInterface, h.isWireGuard(h.VPNInterface)),
		VPNAddress:      h.ipv4Address(h.VPNInterface),
		BootRestore:     h.bootRestoreEnabled(),
	}
}

// SetForwarding applies IPv4 forwarding now and persists it across reboots.
// It returns an error when another sysctl file would undo the setting at boot.
func (h Host) SetForwarding(_ context.Context, enabled bool) error {
	value := "0"
	if enabled {
		value = "1"
	}
	if err := os.MkdirAll(h.path(filepath.Dir(forwardDropIn)), 0755); err != nil {
		return fmt.Errorf("create sysctl directory: %w", err)
	}
	if err := os.WriteFile(h.path(forwardDropIn), []byte(managedFileHeader+forwardKey+" = "+value+"\n"), 0644); err != nil {
		return fmt.Errorf("save forwarding setting: %w", err)
	}
	if err := h.neutralizeSysctlConf(value); err != nil {
		return err
	}
	if err := os.WriteFile(h.path(procForward), []byte(value+"\n"), 0644); err != nil {
		return fmt.Errorf("apply forwarding setting: %w", err)
	}
	if bootValue, source := h.bootForwardValue(); bootValue != value {
		return fmt.Errorf("IPv4 forwarding changed for now, but %s sets %s = %s at boot; edit that file to keep this setting", source, forwardKey, bootValue)
	}
	return nil
}

// SetBootRestore installs or removes a systemd unit that re-applies the saved
// rules at boot, since iptables keeps rules only in memory.
func (h Host) SetBootRestore(ctx context.Context, enabled bool) error {
	if h.Runner == nil {
		return errors.New("command runner is not configured")
	}
	if !enabled {
		if _, err := os.Stat(h.path(unitPath())); errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if _, err := h.Runner.Run(ctx, "systemctl", "disable", RestoreUnit); err != nil {
			return fmt.Errorf("disable boot restore: %w", err)
		}
		if err := os.Remove(h.path(unitPath())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove boot restore unit: %w", err)
		}
		_, err := h.Runner.Run(ctx, "systemctl", "daemon-reload")
		return err
	}
	if err := h.writeUnit(); err != nil {
		return err
	}
	if _, err := h.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd: %w", err)
	}
	if _, err := h.Runner.Run(ctx, "systemctl", "enable", RestoreUnit); err != nil {
		return fmt.Errorf("enable boot restore: %w", err)
	}
	return nil
}

// SyncBootRestore rewrites an installed restore unit whose command line no
// longer matches this run (for example after the binary or interfaces moved).
func (h Host) SyncBootRestore(ctx context.Context) (bool, error) {
	current, err := os.ReadFile(h.path(unitPath()))
	if err != nil {
		return false, nil
	}
	expected, err := h.unitContent()
	if err != nil || string(current) == expected {
		return false, err
	}
	if h.Runner == nil {
		return false, errors.New("command runner is not configured")
	}
	if err := h.writeUnit(); err != nil {
		return false, err
	}
	if _, err := h.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return false, fmt.Errorf("reload systemd: %w", err)
	}
	return true, nil
}

func (h Host) path(name string) string {
	if h.Root == "" {
		return name
	}
	return filepath.Join(h.Root, name)
}

func (h Host) forwardingEnabled() bool {
	value, err := os.ReadFile(h.path(procForward))
	return err == nil && strings.TrimSpace(string(value)) == "1"
}

// interfaceUp reports whether an interface is administratively up and has a link.
func (h Host) interfaceUp(name string) bool {
	if name == "" || strings.ContainsAny(name, "/") || name == "." || name == ".." {
		return false
	}
	raw, err := os.ReadFile(h.path(filepath.Join(sysClassNet, name, "flags")))
	if err != nil {
		return false
	}
	flags, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"), 16, 32)
	if err != nil || flags&0x1 == 0 {
		return false
	}
	// IFF_UP alone is not enough: an unplugged NIC or idle Wi-Fi is "up"
	// without a link. The kernel reports carrier=1 only when it can pass
	// traffic (virtual tunnels report it while running).
	carrier, err := os.ReadFile(h.path(filepath.Join(sysClassNet, name, "carrier")))
	return err == nil && strings.TrimSpace(string(carrier)) == "1"
}

// bootForwardValue returns the ip_forward value the host would load at boot
// and the file that sets it, following systemd-sysctl and procps ordering.
func (h Host) bootForwardValue() (string, string) {
	chosen := make(map[string]string)
	for _, dir := range sysctlDirs {
		matches, _ := filepath.Glob(filepath.Join(h.path(dir), "*.conf"))
		for _, match := range matches {
			base := filepath.Base(match)
			if _, exists := chosen[base]; !exists {
				chosen[base] = match
			}
		}
	}
	names := make([]string, 0, len(chosen))
	for name := range chosen {
		names = append(names, name)
	}
	sort.Strings(names)
	files := make([]string, 0, len(names)+1)
	for _, name := range names {
		files = append(files, chosen[name])
	}
	files = append(files, h.path(sysctlConf))

	value, source := "0", "the kernel default"
	for _, file := range files {
		if fileValue, ok := forwardValueIn(file); ok {
			value, source = fileValue, strings.TrimPrefix(file, h.Root)
		}
	}
	return value, source
}

func forwardValueIn(file string) (string, bool) {
	contents, err := os.ReadFile(file)
	if err != nil {
		return "", false
	}
	value, found := "", false
	for _, line := range strings.Split(string(contents), "\n") {
		if key, lineValue, ok := parseSysctlLine(line); ok && key == forwardKey {
			value, found = lineValue, true
		}
	}
	return value, found
}

func parseSysctlLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == ';' {
		return "", "", false
	}
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	key = strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(key), "-"), "/", ".")
	return key, strings.TrimSpace(value), true
}

// neutralizeSysctlConf comments out ip_forward lines in /etc/sysctl.conf that
// conflict with the wanted value, because that file is read last at boot.
func (h Host) neutralizeSysctlConf(wanted string) error {
	path := h.path(sysctlConf)
	contents, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", sysctlConf, err)
	}
	lines := strings.Split(string(contents), "\n")
	changed := false
	for index, line := range lines {
		if key, value, ok := parseSysctlLine(line); ok && key == forwardKey && value != wanted {
			lines[index] = "# disabled by iptable-ui: " + strings.TrimSpace(line)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		return fmt.Errorf("update %s: %w", sysctlConf, err)
	}
	return nil
}

func unitPath() string { return filepath.Join(unitDir, RestoreUnit) }

func (h Host) bootRestoreEnabled() bool {
	if _, err := os.Stat(h.path(unitPath())); err != nil {
		return false
	}
	_, err := os.Lstat(h.path(filepath.Join(unitWantsDir, RestoreUnit)))
	return err == nil
}

func (h Host) unitContent() (string, error) {
	if len(h.RestoreCommand) == 0 {
		return "", errors.New("boot restore command is not configured")
	}
	for _, arg := range h.RestoreCommand {
		if !unitArgPattern.MatchString(arg) {
			return "", fmt.Errorf("cannot use %q in a systemd unit; move the binary or database to a path without spaces or special characters", arg)
		}
	}
	return "[Unit]\n" +
		"Description=Restore iptable-ui port forwards\n" +
		"Wants=network-online.target\n" +
		"After=network-online.target\n\n" +
		"[Service]\n" +
		"Type=oneshot\n" +
		"ExecStart=" + strings.Join(h.RestoreCommand, " ") + "\n\n" +
		"[Install]\n" +
		"WantedBy=multi-user.target\n", nil
}

func (h Host) writeUnit() error {
	content, err := h.unitContent()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(h.path(unitDir), 0755); err != nil {
		return fmt.Errorf("create systemd unit directory: %w", err)
	}
	if err := os.WriteFile(h.path(unitPath()), []byte(content), 0644); err != nil {
		return fmt.Errorf("write boot restore unit: %w", err)
	}
	return nil
}
