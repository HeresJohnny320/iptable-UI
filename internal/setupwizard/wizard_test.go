package setupwizard

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/system"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
)

// fakeSystem tracks which binaries exist; running an install command makes
// the binaries it provides appear, like a real package manager.
type fakeSystem struct {
	binaries map[string]bool
	provides map[string][]string // command prefix -> binaries it installs
	outputs  map[string]string
	commands []string
}

func (f *fakeSystem) lookPath(name string) (string, error) {
	if f.binaries[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (f *fakeSystem) Run(_ context.Context, args ...string) error {
	command := strings.Join(args, " ")
	f.commands = append(f.commands, command)
	for prefix, binaries := range f.provides {
		if strings.HasPrefix(command, prefix) {
			for _, binary := range binaries {
				f.binaries[binary] = true
			}
		}
	}
	return nil
}

func (f *fakeSystem) Output(_ context.Context, args ...string) (string, error) {
	return f.outputs[strings.Join(args, " ")], nil
}

func newSystem(binaries ...string) *fakeSystem {
	system := &fakeSystem{binaries: map[string]bool{}, provides: map[string][]string{}, outputs: map[string]string{}}
	for _, binary := range binaries {
		system.binaries[binary] = true
	}
	return system
}

type fakeKeys struct{ calls int }

func (k *fakeKeys) Generate(context.Context) (string, string, error) {
	k.calls++
	key := func(seed byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 32)) }
	return key(byte(k.calls * 2)), key(byte(k.calls*2 + 1)), nil
}

type fakeHost struct{ forwarding bool }

func (h *fakeHost) Status(context.Context) system.Status {
	return system.Status{Forwarding: h.forwarding}
}
func (h *fakeHost) SetForwarding(_ context.Context, on bool) error {
	h.forwarding = on
	return nil
}

func newWizard(t *testing.T, fake *fakeSystem, input string, host Forwarding) (*Wizard, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	keys := &fakeKeys{}
	osRelease := filepath.Join(t.TempDir(), "os-release")
	_ = os.WriteFile(osRelease, []byte(`PRETTY_NAME="Test Linux 1.0"`+"\n"), 0644)
	return &Wizard{
		In: strings.NewReader(input), Out: out, Commands: fake, LookPath: fake.lookPath, OSRelease: osRelease,
		WireGuard: wgsetup.SetupManager{ConfigDir: t.TempDir(), Keys: keys}, Keys: keys,
		HomeDir: t.TempDir(), PublicIPv4: "203.0.113.5", Host: host,
	}, out
}

func assertCommands(t *testing.T, fake *fakeSystem, expected ...string) {
	t.Helper()
	got := strings.Join(fake.commands, "\n")
	for _, command := range expected {
		if !strings.Contains(got, command) {
			t.Errorf("missing command %q in:\n%s", command, got)
		}
	}
}

func TestWireGuardOnUbuntu(t *testing.T) {
	fake := newSystem("apt-get", "iptables", "systemctl", "ufw")
	fake.provides["apt-get install"] = []string{"wg", "conntrack", "whiptail"}
	fake.outputs["ufw status"] = "Status: active\n"
	host := &fakeHost{}
	// 1=WireGuard, conntrack yes, whiptail y, interface default, an invalid
	// port then 51820, Enter through the other WireGuard defaults, allow in
	// ufw, start tunnel, forwarding, apply on boot.
	wizard, out := newWizard(t, fake, "1\n\ny\n\nabc\n51820\n\n\n\n\n\n\n\n\n", host)
	result, err := wizard.Run(context.Background())
	if err != nil || result.VPN != WireGuard || !result.ApplyOnBoot || !host.forwarding {
		t.Fatalf("result %+v, forwarding %v, err %v\n%s", result, host.forwarding, err, out)
	}
	assertCommands(t, fake, "apt-get update", "apt-get install -y wireguard-tools conntrack whiptail", "ufw allow 51820/udp", "systemctl enable --now wg-quick@wg0")
	config, err := os.ReadFile(filepath.Join(wizard.WireGuard.ConfigDir, "wg0.conf"))
	if err != nil || !strings.Contains(string(config), "ListenPort = 51820") || !strings.Contains(string(config), "AllowedIPs = 10.66.0.2/32, 192.168.1.0/24") {
		t.Fatalf("VPS config not written correctly: %v\n%s", err, config)
	}
	home, err := os.ReadFile(filepath.Join(wizard.HomeDir, "wg0-home-peer.conf"))
	if err != nil || strings.Contains(string(home), "<HOME_PRIVATE_KEY>") || !strings.Contains(string(home), "Endpoint = 203.0.113.5:51820") {
		t.Fatalf("home config should be complete with the detected endpoint: %v\n%s", err, home)
	}
	if info, _ := os.Stat(filepath.Join(wizard.HomeDir, "wg0-home-peer.conf")); info.Mode().Perm() != 0600 {
		t.Fatalf("home config holds a private key and must be 0600, got %v", info.Mode().Perm())
	}
	if !strings.Contains(out.String(), "Test Linux 1.0 (installs with apt-get)") || !strings.Contains(out.String(), "Forwards should point at 10.66.0.2") || !strings.Contains(out.String(), "Please enter a port from 1 to 65535") {
		t.Fatalf("missing guidance in output:\n%s", out)
	}
}

func TestTailscaleOnArchInstallsCurlFirst(t *testing.T) {
	fake := newSystem("pacman", "iptables", "systemctl", "conntrack")
	fake.provides["pacman -S --noconfirm --needed curl"] = []string{"curl"}
	fake.provides["sh -c curl -fsSL https://tailscale.com/install.sh | sh"] = []string{"tailscale"}
	// 2=Tailscale, no whiptail, install yes, blank auth key, forwarding, boot.
	wizard, out := newWizard(t, fake, "2\nn\n\n\n\n\n", &fakeHost{})
	result, err := wizard.Run(context.Background())
	if err != nil || result.VPN != Tailscale {
		t.Fatalf("result %+v, err %v\n%s", result, err, out)
	}
	assertCommands(t, fake, "pacman -S --noconfirm --needed curl", "sh -c curl -fsSL https://tailscale.com/install.sh | sh", "systemctl enable --now tailscaled", "tailscale up")
	if !strings.Contains(out.String(), "sign in with a browser link") || !strings.Contains(out.String(), "tailscale ip -4") {
		t.Fatalf("missing sign-in guidance:\n%s", out)
	}
}

func TestNetBirdOnFedoraWithSetupKey(t *testing.T) {
	fake := newSystem("dnf", "iptables", "curl", "systemctl")
	fake.provides["sh -c curl -fsSL https://pkgs.netbird.io/install.sh | sh"] = []string{"netbird"}
	// 3=NetBird, no conntrack, no whiptail, install yes, setup key.
	wizard, _ := newWizard(t, fake, "3\nn\nn\n\nABC-123\n\n\n", &fakeHost{forwarding: true})
	result, err := wizard.Run(context.Background())
	if err != nil || result.VPN != NetBird {
		t.Fatalf("result %+v, err %v", result, err)
	}
	assertCommands(t, fake, "netbird up --setup-key=ABC-123")
	for _, command := range fake.commands {
		if strings.HasPrefix(command, "dnf") {
			t.Fatalf("nothing needed installing with dnf, but ran %q", command)
		}
	}
}

func TestClosedTerminalChangesNothing(t *testing.T) {
	fake := newSystem("apt-get", "systemctl")
	host := &fakeHost{}
	wizard, _ := newWizard(t, fake, "", host)
	result, err := wizard.Run(context.Background())
	if err != nil || result.VPN != "" || result.ApplyOnBoot || host.forwarding || len(fake.commands) != 0 {
		t.Fatalf("with no input nothing may change: result %+v, forwarding %v, commands %v", result, host.forwarding, fake.commands)
	}
}

func TestNoPackageManagerExplainsWhatToInstall(t *testing.T) {
	fake := newSystem("iptables")
	wizard, out := newWizard(t, fake, "1\n\n\n", nil)
	if _, err := wizard.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Install these yourself with your package manager: wireguard, conntrack") || len(fake.commands) != 0 {
		t.Fatalf("expected manual install advice and no commands:\n%s\n%v", out, fake.commands)
	}
}

func TestExistingWireGuardConfigIsKept(t *testing.T) {
	fake := newSystem("apt-get", "iptables", "wg", "conntrack", "whiptail", "systemctl")
	wizard, out := newWizard(t, fake, "1\n\nn\nn\nn\n", nil)
	existing := filepath.Join(wizard.WireGuard.ConfigDir, "wg0.conf")
	if err := os.WriteFile(existing, []byte("[Interface]\n# mine\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := wizard.Run(context.Background())
	if err != nil || result.VPN != WireGuard || result.ApplyOnBoot {
		t.Fatalf("result %+v, err %v\n%s", result, err, out)
	}
	if content, _ := os.ReadFile(existing); string(content) != "[Interface]\n# mine\n" {
		t.Fatal("an existing config must never be overwritten")
	}
	if len(fake.commands) != 0 {
		t.Fatalf("declining to start the tunnel should run nothing, ran %v", fake.commands)
	}
}
