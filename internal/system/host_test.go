package system

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordingRunner struct {
	calls []string
	root  string
}

// Run records the command and mimics `systemctl enable/disable` creating or
// removing the multi-user.target.wants symlink.
func (r *recordingRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	wants := filepath.Join(r.root, unitWantsDir, RestoreUnit)
	if len(args) == 3 && args[0] == "systemctl" && args[1] == "enable" {
		_ = os.MkdirAll(filepath.Dir(wants), 0755)
		_ = os.Symlink(filepath.Join(r.root, unitPath()), wants)
	}
	if len(args) == 3 && args[0] == "systemctl" && args[1] == "disable" {
		_ = os.Remove(wants)
	}
	return nil, nil
}

func writeFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, root, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestSetForwardingPersistsAndNeutralizesSysctlConf(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, procForward, "0\n")
	writeFile(t, root, sysctlConf, "vm.swappiness = 10\nnet.ipv4.ip_forward=0\n#net.ipv4.ip_forward=1\n")
	host := Host{Root: root}

	if err := host.SetForwarding(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !host.Status(context.Background()).Forwarding {
		t.Fatal("forwarding should be enabled at runtime")
	}
	if got := readFile(t, root, forwardDropIn); !strings.Contains(got, "net.ipv4.ip_forward = 1") {
		t.Fatalf("drop-in not written: %q", got)
	}
	conf := readFile(t, root, sysctlConf)
	if !strings.Contains(conf, "# disabled by iptable-ui: net.ipv4.ip_forward=0") || !strings.Contains(conf, "vm.swappiness = 10") {
		t.Fatalf("conflicting sysctl.conf line not neutralized: %q", conf)
	}

	if err := host.SetForwarding(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if host.Status(context.Background()).Forwarding {
		t.Fatal("forwarding should be disabled at runtime")
	}
}

func TestSetForwardingReportsOverridingFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, procForward, "0\n")
	writeFile(t, root, "/etc/sysctl.d/99-zz-hardening.conf", "net/ipv4/ip_forward = 0\n")
	err := Host{Root: root}.SetForwarding(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), "/etc/sysctl.d/99-zz-hardening.conf") {
		t.Fatalf("expected an error naming the overriding file, got %v", err)
	}
	if readFile(t, root, procForward) != "1\n" {
		t.Fatal("forwarding should still be applied for the current boot")
	}
}

func TestBootForwardValueHonorsDirectoryPriority(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/usr/lib/sysctl.d/50-default.conf", "net.ipv4.ip_forward = 1\n")
	writeFile(t, root, "/etc/sysctl.d/50-default.conf", "net.ipv4.ip_forward = 0\n")
	if value, source := (Host{Root: root}).bootForwardValue(); value != "0" || source != "/etc/sysctl.d/50-default.conf" {
		t.Fatalf("/etc should hide the same-named vendor file, got %s from %s", value, source)
	}
}

func TestStatusReportsVPNLink(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, filepath.Join(sysClassNet, "wg0", "flags"), "0x91\n")
	writeFile(t, root, filepath.Join(sysClassNet, "wg0", "carrier"), "1\n")
	writeFile(t, root, filepath.Join(sysClassNet, "wg1", "flags"), "0x90\n")
	writeFile(t, root, filepath.Join(sysClassNet, "wlan0", "flags"), "0x1003\n")
	writeFile(t, root, filepath.Join(sysClassNet, "wlan0", "carrier"), "0\n")
	if !(Host{Root: root, VPNInterface: "wg0"}).Status(context.Background()).VPNUp {
		t.Fatal("wg0 has IFF_UP set and should be reported up")
	}
	if (Host{Root: root, VPNInterface: "wg1"}).Status(context.Background()).VPNUp {
		t.Fatal("wg1 is administratively down")
	}
	if (Host{Root: root, VPNInterface: "wlan0"}).Status(context.Background()).VPNUp {
		t.Fatal("an interface without carrier has no link and is not up")
	}
	if (Host{Root: root, VPNInterface: "missing"}).Status(context.Background()).VPNUp {
		t.Fatal("a missing interface is not up")
	}
}

func TestBootRestoreInstallSyncAndRemove(t *testing.T) {
	root := t.TempDir()
	runner := &recordingRunner{root: root}
	host := Host{Root: root, Runner: runner, RestoreCommand: []string{"/usr/local/bin/iptable-ui", "reconcile", "--wg-if", "wg0"}}

	if err := host.SetBootRestore(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !host.Status(context.Background()).BootRestore {
		t.Fatal("boot restore should be reported enabled")
	}
	if unit := readFile(t, root, unitPath()); !strings.Contains(unit, "ExecStart=/usr/local/bin/iptable-ui reconcile --wg-if wg0\n") || !strings.Contains(unit, "After=network-online.target") {
		t.Fatalf("unexpected unit:\n%s", unit)
	}

	if changed, err := host.SyncBootRestore(context.Background()); err != nil || changed {
		t.Fatalf("unchanged unit should not be rewritten: changed=%v err=%v", changed, err)
	}
	host.RestoreCommand = []string{"/opt/iptable-ui", "reconcile", "--wg-if", "tailscale0"}
	if changed, err := host.SyncBootRestore(context.Background()); err != nil || !changed {
		t.Fatalf("stale unit should be rewritten: changed=%v err=%v", changed, err)
	}
	if unit := readFile(t, root, unitPath()); !strings.Contains(unit, "ExecStart=/opt/iptable-ui reconcile --wg-if tailscale0\n") {
		t.Fatalf("unit not refreshed:\n%s", unit)
	}

	if err := host.SetBootRestore(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if host.Status(context.Background()).BootRestore {
		t.Fatal("boot restore should be reported disabled")
	}
	if _, err := os.Stat(filepath.Join(root, unitPath())); !os.IsNotExist(err) {
		t.Fatal("unit file should be removed")
	}
	if err := host.SetBootRestore(context.Background(), false); err != nil {
		t.Fatalf("disabling twice should be a no-op: %v", err)
	}
}

func TestBootRestoreRejectsUnsafeUnitArguments(t *testing.T) {
	root := t.TempDir()
	host := Host{Root: root, Runner: &recordingRunner{root: root}, RestoreCommand: []string{"/home/me/my tools/iptable-ui", "reconcile"}}
	if err := host.SetBootRestore(context.Background(), true); err == nil || !strings.Contains(err.Error(), "without spaces") {
		t.Fatalf("expected unsafe path to be rejected, got %v", err)
	}
}

func TestSyncBootRestoreIgnoresMissingUnit(t *testing.T) {
	host := Host{Root: t.TempDir(), RestoreCommand: []string{"/usr/local/bin/iptable-ui"}}
	if changed, err := host.SyncBootRestore(context.Background()); err != nil || changed {
		t.Fatalf("missing unit should be ignored: changed=%v err=%v", changed, err)
	}
}
