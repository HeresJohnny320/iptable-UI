// Package setupwizard walks a new user through installing a VPN (WireGuard,
// Tailscale or NetBird) and the tools iptable-ui uses, on any common Linux
// distribution, asking before every change.
package setupwizard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/HeresJohnny320/iptable-ui/internal/packages"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
)

// Commands runs system commands.
type Commands interface {
	// Run attaches the command to the terminal, so installs show progress
	// and VPN logins can print their sign-in link.
	Run(ctx context.Context, args ...string) error
	// Output runs a command quietly and returns what it printed.
	Output(ctx context.Context, args ...string) (string, error)
}

// TerminalCommands runs commands on the real system.
type TerminalCommands struct{}

func (TerminalCommands) Run(ctx context.Context, args ...string) error {
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}

func (TerminalCommands) Output(ctx context.Context, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	return string(output), err
}

// Forwarding is the part of the host settings the wizard changes.
type Forwarding interface {
	Status(context.Context) system.Status
	SetForwarding(context.Context, bool) error
}

// VPN names returned in Result.
const (
	WireGuard = "wireguard"
	Tailscale = "tailscale"
	NetBird   = "netbird"
)

// Result is what the wizard set up.
type Result struct {
	VPN string
	// ApplyOnBoot is true when the user asked to re-apply rules after a
	// reboot. The caller enables it once the VPN interface is known.
	ApplyOnBoot bool
}

type Wizard struct {
	In        io.Reader
	Out       io.Writer
	Commands  Commands
	LookPath  func(string) (string, error)
	OSRelease string
	// WireGuard writes the VPS config; Keys generates the home peer's keys.
	WireGuard wgsetup.SetupManager
	Keys      wgsetup.KeyGenerator
	// HomeDir is where the home peer's config is saved for copying.
	HomeDir string
	// PublicIPv4 is suggested as the WireGuard endpoint.
	PublicIPv4 string
	Host       Forwarding

	reader *bufio.Reader
	eof    bool
}

func (w *Wizard) Run(ctx context.Context) (Result, error) {
	w.reader = bufio.NewReader(w.In)
	manager, hasManager := packages.Detect(w.LookPath)
	w.printf("\n=== iptable-ui setup wizard ===\n")
	w.printf("Nothing is installed or changed without asking first. Press Enter to accept the [default].\n\n")
	if hasManager {
		w.printf("System: %s (installs with %s)\n\n", packages.OSName(w.OSRelease), manager.Name)
	} else {
		w.printf("System: %s (no supported package manager found; you will be told what to install)\n\n", packages.OSName(w.OSRelease))
	}

	vpns := []string{WireGuard, Tailscale, NetBird, ""}
	choice := vpns[w.choose("Which VPN should connect this server to your home server?", []string{
		"WireGuard  self-hosted and fastest; this wizard writes the configs for both ends",
		"Tailscale  easiest; sign in on both machines with a Tailscale account",
		"NetBird    open source; sign in with a NetBird account or your own server",
		"Skip       I will set up the VPN myself",
	})]

	var install []string
	if w.missing("iptables") && w.confirm("iptables is required to forward ports. Install it?", true) {
		install = append(install, packages.IPTables)
	}
	switch choice {
	case WireGuard:
		if w.missing("wg") {
			install = append(install, packages.WireGuard)
		}
	case Tailscale, NetBird:
		if w.missing(choice) && w.missing("curl") {
			install = append(install, packages.Curl)
		}
	}
	if w.missing("conntrack") && w.confirm("Install conntrack? It lets iptable-ui close open connections the moment you remove a rule (recommended).", true) {
		install = append(install, packages.Conntrack)
	}
	if w.missing("whiptail") && w.confirm("Install whiptail? Optional classic blue menus (press U in the TUI).", false) {
		install = append(install, packages.Whiptail)
	}
	if len(install) > 0 {
		w.install(ctx, manager, hasManager, install)
	}

	result := Result{}
	switch choice {
	case WireGuard:
		if w.setupWireGuard(ctx) {
			result.VPN = WireGuard
		}
	case Tailscale:
		if w.setupAccountVPN(ctx, Tailscale, "https://tailscale.com/install.sh", "tailscaled", "--auth-key=", "Tailscale auth key") {
			result.VPN = Tailscale
		}
	case NetBird:
		if w.setupAccountVPN(ctx, NetBird, "https://pkgs.netbird.io/install.sh", "", "--setup-key=", "NetBird setup key") {
			result.VPN = NetBird
		}
	}

	if w.Host != nil && !w.Host.Status(ctx).Forwarding && w.confirm("Turn on IPv4 forwarding? It must be on for any forward to work.", true) {
		if err := w.Host.SetForwarding(ctx, true); err != nil {
			w.printf("Could not turn on forwarding: %v\n", err)
		} else {
			w.printf("IPv4 forwarding is on and saved for reboots.\n")
		}
	}
	result.ApplyOnBoot = w.confirm("Re-apply your rules automatically after a reboot (apply on boot)?", true)
	w.printf("\nSetup finished. Next: add a forward that points at your home server's VPN address.\n\n")
	return result, nil
}

func (w *Wizard) setupWireGuard(ctx context.Context) bool {
	if w.missing("wg") {
		w.printf("WireGuard tools are not installed, so the tunnel was not configured.\n")
		return false
	}
	configDir := w.WireGuard.ConfigDir
	if configDir == "" {
		configDir = "/etc/wireguard"
	}
	for {
		name := w.ask("Tunnel interface name", "wg0")
		if _, err := os.Stat(filepath.Join(configDir, name+".conf")); err == nil {
			w.printf("%s already exists, so it is kept as is.\n", filepath.Join(configDir, name+".conf"))
			w.startWireGuard(ctx, name)
			return true
		}
		port := w.askPort("WireGuard port on this VPS (UDP)", 51820)
		listenPort := strconv.Itoa(int(port))
		endpoint := ""
		if w.PublicIPv4 != "" {
			endpoint = net.JoinHostPort(w.PublicIPv4, listenPort)
		}
		request := wgsetup.SetupRequest{
			InterfaceName:  name,
			ServerAddress:  w.ask("This VPS's tunnel address", "10.66.0.1/24"),
			PeerAddress:    w.ask("Home server's tunnel address (forwards will point here)", "10.66.0.2"),
			HomeLAN:        w.ask("Home network to reach through the tunnel", "192.168.1.0/24"),
			PublicEndpoint: w.ask("Address the home server connects to (this VPS's public IP:port)", endpoint),
			ListenPort:     port,
		}
		created, homeConfig, err := w.createWireGuard(ctx, request)
		if err != nil {
			w.printf("Could not create the WireGuard config: %v\n", err)
			if w.confirm("Try again?", true) {
				continue
			}
			return false
		}
		saved := w.saveHomeConfig(name, homeConfig)
		w.printf("\nVPS config written to %s.\n", created.ConfigPath)
		w.printf("\nHome server config (it contains the home private key, keep it secret):\n\n%s\n", homeConfig)
		if saved != "" {
			w.printf("Also saved to %s. Copy it to the home server, for example:\n  scp root@<this VPS>:%s /etc/wireguard/%s.conf\n", saved, saved, name)
		}
		w.printf("Then on the home server run: sudo wg-quick up %s\n", name)
		w.printf("Forwards should point at %s.\n\n", request.PeerAddress)
		w.openFirewallPort(ctx, listenPort)
		w.startWireGuard(ctx, name)
		return true
	}
}

// createWireGuard writes the VPS config and returns a complete home config,
// generating the home key pair so nothing has to be pasted between machines.
func (w *Wizard) createWireGuard(ctx context.Context, request wgsetup.SetupRequest) (wgsetup.SetupResult, string, error) {
	keys := w.Keys
	if keys == nil {
		keys = wgsetup.WGKeyGenerator{}
	}
	homePrivate, homePublic, err := keys.Generate(ctx)
	if err != nil {
		return wgsetup.SetupResult{}, "", err
	}
	request.PeerPublicKey = homePublic
	created, err := w.WireGuard.Configure(ctx, request)
	if err != nil {
		return wgsetup.SetupResult{}, "", err
	}
	return created, strings.Replace(created.PeerConfig, "<HOME_PRIVATE_KEY>", homePrivate, 1), nil
}

func (w *Wizard) saveHomeConfig(name, content string) string {
	if w.HomeDir == "" {
		return ""
	}
	path := filepath.Join(w.HomeDir, name+"-home-peer.conf")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		path = filepath.Join(w.HomeDir, fmt.Sprintf("%s-home-peer-%d.conf", name, time.Now().Unix()))
		file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	}
	if err != nil {
		w.printf("Could not save the home config: %v\n", err)
		return ""
	}
	defer file.Close()
	if _, err := file.WriteString(content); err != nil {
		w.printf("Could not save the home config: %v\n", err)
		return ""
	}
	return path
}

// openFirewallPort lets WireGuard in through ufw or firewalld when one is active.
func (w *Wizard) openFirewallPort(ctx context.Context, port string) {
	if !w.missing("ufw") {
		if status, _ := w.Commands.Output(ctx, "ufw", "status"); strings.Contains(status, "Status: active") &&
			w.confirm(fmt.Sprintf("ufw is active. Allow WireGuard on UDP port %s?", port), true) {
			w.run(ctx, "ufw", "allow", port+"/udp")
		}
	}
	if !w.missing("firewall-cmd") {
		if state, _ := w.Commands.Output(ctx, "firewall-cmd", "--state"); strings.TrimSpace(state) == "running" &&
			w.confirm(fmt.Sprintf("firewalld is running. Allow WireGuard on UDP port %s?", port), true) {
			w.run(ctx, "firewall-cmd", "--permanent", "--add-port="+port+"/udp")
			w.run(ctx, "firewall-cmd", "--reload")
		}
	}
	w.printf("If your VPS provider has its own firewall, allow UDP port %s there too.\n", port)
}

func (w *Wizard) startWireGuard(ctx context.Context, name string) {
	if !w.confirm(fmt.Sprintf("Start %s now and on every boot?", name), true) {
		return
	}
	if !w.missing("systemctl") {
		w.run(ctx, "systemctl", "enable", "--now", "wg-quick@"+name)
		return
	}
	w.run(ctx, "wg-quick", "up", name)
}

// setupAccountVPN installs and signs in to an account-based VPN (Tailscale,
// NetBird) using its official installer, which supports every major distro.
func (w *Wizard) setupAccountVPN(ctx context.Context, binary, installer, service, keyFlag, keyName string) bool {
	if w.missing(binary) {
		if !w.confirm(fmt.Sprintf("Install %s with its official installer (%s)?", binary, installer), true) {
			return false
		}
		if w.missing("curl") {
			w.printf("curl is needed to download the installer and could not be installed.\n")
			return false
		}
		w.run(ctx, "sh", "-c", "curl -fsSL "+installer+" | sh")
		if w.missing(binary) {
			w.printf("%s did not install; see the messages above.\n", binary)
			return false
		}
	}
	if service != "" && !w.missing("systemctl") {
		w.run(ctx, "systemctl", "enable", "--now", service)
	}
	key := w.ask(keyName+" (leave blank to sign in with a browser link)", "")
	args := []string{binary, "up"}
	if key != "" {
		args = append(args, keyFlag+key)
	} else {
		w.printf("Open the link printed below to sign in; setup continues once you have.\n")
	}
	if !w.run(ctx, args...) {
		return false
	}
	w.printf("\n%s is connected. Install it on your home server too and sign in to the same account.\n", binary)
	w.printf("Forwards should point at the home server's %s address (run \"%s ip -4\" or \"%s status\" there).\n\n", binary, binary, binary)
	return true
}

func (w *Wizard) install(ctx context.Context, manager packages.Manager, hasManager bool, logical []string) {
	if !hasManager {
		w.printf("Install these yourself with your package manager: %s\n", strings.Join(logical, ", "))
		return
	}
	for _, command := range manager.Commands(logical...) {
		if !w.run(ctx, command...) {
			return
		}
	}
}

// run shows and runs a command, reporting failure without stopping the wizard.
func (w *Wizard) run(ctx context.Context, args ...string) bool {
	w.printf("$ %s\n", strings.Join(args, " "))
	if err := w.Commands.Run(ctx, args...); err != nil {
		w.printf("That command failed: %v\n", err)
		return false
	}
	return true
}

func (w *Wizard) missing(binary string) bool {
	_, err := w.LookPath(binary)
	return err != nil
}

func (w *Wizard) printf(format string, args ...any) {
	fmt.Fprintf(w.Out, format, args...)
}

// ask reads one answer; an empty answer (or end of input) picks the default.
func (w *Wizard) ask(question, defaultValue string) string {
	if defaultValue != "" {
		w.printf("%s [%s]: ", question, defaultValue)
	} else {
		w.printf("%s: ", question)
	}
	answer, err := w.reader.ReadString('\n')
	if err != nil {
		w.eof = true
		w.printf("\n")
	}
	if answer = strings.TrimSpace(answer); answer == "" {
		return defaultValue
	}
	return answer
}

func (w *Wizard) askPort(question string, defaultPort uint16) uint16 {
	for {
		answer := w.ask(question, strconv.Itoa(int(defaultPort)))
		if port, err := strconv.ParseUint(answer, 10, 16); err == nil && port > 0 {
			return uint16(port)
		}
		if w.eof {
			return defaultPort
		}
		w.printf("Please enter a port from 1 to 65535.\n")
	}
}

func (w *Wizard) confirm(question string, defaultYes bool) bool {
	hint := "y/N"
	if defaultYes {
		hint = "Y/n"
	}
	answer := strings.ToLower(w.ask(question+" ["+hint+"]", ""))
	switch {
	case answer == "y" || answer == "yes":
		return true
	case answer == "n" || answer == "no" || w.eof:
		// Input ended (closed terminal): never install or change anything.
		return false
	default:
		return defaultYes
	}
}

// choose asks for one of the numbered options. On end of input it picks the
// last option, which is always the safe "skip".
func (w *Wizard) choose(question string, options []string) int {
	w.printf("%s\n", question)
	for index, option := range options {
		w.printf("  %d) %s\n", index+1, option)
	}
	for {
		answer := w.ask(fmt.Sprintf("Choose 1-%d [1]", len(options)), "")
		if answer == "" && !w.eof {
			return 0
		}
		if number, err := strconv.Atoi(answer); err == nil && number >= 1 && number <= len(options) {
			return number - 1
		}
		if w.eof {
			return len(options) - 1
		}
		w.printf("Please enter a number from 1 to %d.\n", len(options))
	}
}
