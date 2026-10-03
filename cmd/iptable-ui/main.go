package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/firewall"
	"github.com/HeresJohnny320/iptable-ui/internal/packages"
	"github.com/HeresJohnny320/iptable-ui/internal/setupwizard"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
	"github.com/HeresJohnny320/iptable-ui/internal/tui"
	"github.com/HeresJohnny320/iptable-ui/internal/web"
	"github.com/HeresJohnny320/iptable-ui/internal/whiptail"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
	"github.com/charmbracelet/x/term"
)

type options struct {
	database string
	publicIF string
	wgIF     string
	// Why each interface was auto-detected; empty when set by flag.
	publicReason string
	wgReason     string
	// wgNotFound means no VPN interface exists, so the wizard is offered.
	wgNotFound bool
	noWizard   bool
	webEnabled bool
	webAddress string
	whiptail   bool
}

func main() {
	if os.Geteuid() != 0 && needsRoot(os.Args[1:]) {
		// Only returns when sudo/doas could not be started.
		if err := elevate(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
	}
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return // the flag package already printed the usage
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

// needsRoot reports whether a command changes the firewall or the system.
// Read-only commands and help run as the current user.
func needsRoot(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "-help" || arg == "--help" {
			return false
		}
	}
	if len(args) == 0 {
		return true
	}
	switch args[0] {
	case "list":
		return false
	case "wireguard":
		return len(args) > 1 && args[1] == "install"
	default:
		return true
	}
}

// elevate re-runs iptable-ui through sudo (or doas), so users do not need to
// remember to type sudo. It replaces this process and only returns an error
// when neither tool can be started.
func elevate(args []string) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate iptable-ui binary: %w", err)
	}
	for _, tool := range []string{"sudo", "doas"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "iptable-ui changes the firewall, so it needs root. Re-running with %s...\n", tool)
		return syscall.Exec(path, append([]string{tool, executable}, args...), os.Environ())
	}
	return errors.New("iptable-ui needs root, and neither sudo nor doas is installed; run it as root (for example: su -c iptable-ui)")
}

// installSelf copies this binary to /usr/local/bin/iptable-ui, executable,
// so it can be started from anywhere and the boot service has a stable path.
func installSelf() error {
	const target = "/usr/local/bin/iptable-ui"
	source, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate iptable-ui binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(source); err == nil {
		source = resolved
	}
	if source == target {
		fmt.Println("iptable-ui is already installed at", target)
		return nil
	}
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read %s: %w", source, err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".iptable-ui-*")
	if err != nil {
		return fmt.Errorf("install to %s: %w", target, err)
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return fmt.Errorf("install to %s: %w", target, err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporary.Name(), 0755); err != nil {
		return err
	}
	if err := os.Rename(temporary.Name(), target); err != nil {
		return fmt.Errorf("install to %s: %w", target, err)
	}
	fmt.Printf("Installed %s. Start it from anywhere with: iptable-ui\n", target)
	return nil
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "wireguard" {
		return runWireGuard(args[1:])
	}
	if len(args) > 0 && args[0] == "install" {
		return installSelf()
	}
	command := "tui"
	if len(args) > 0 && (args[0] == "list" || args[0] == "reconcile") {
		command, args = args[0], args[1:]
	}
	// "setup" runs the setup wizard, then continues into the TUI.
	forceWizard := len(args) > 0 && args[0] == "setup"
	if forceWizard {
		args = args[1:]
	}
	config, err := parseOptions(command, args)
	if err != nil {
		return err
	}
	if command != "list" && os.Geteuid() != 0 {
		return errors.New("run the TUI and firewall operations as root (for example: sudo iptable-ui); list is read-only")
	}
	if command == "reconcile" && os.Geteuid() != 0 {
		return errors.New("reconcile requires root privileges")
	}
	service, database, manager, closeStore, err := openService(&config)
	if err != nil {
		return err
	}
	defer closeStore()
	var discovered []firewall.ExistingRule
	if os.Geteuid() == 0 && config.publicIF != "" {
		discovered, err = manager.Discover(context.Background())
		if err != nil {
			return err
		}
		foundRules := make([]store.Rule, 0, len(discovered))
		for _, existing := range discovered {
			foundRules = append(foundRules, existing.Rule)
		}
		imported, importErr := database.ImportMissing(context.Background(), foundRules)
		if importErr != nil {
			return importErr
		}
		if imported > 0 {
			fmt.Fprintf(os.Stderr, "Imported %d existing iptables rule(s) into the database.\n", imported)
		}
	}
	// Detect the VPN interface after importing, so rules adopted from other
	// tools count when choosing the interface their destinations route through.
	if config.wgIF == "" {
		if err := detectVPNInterface(&config, database); err != nil {
			return err
		}
	}
	applyOnBoot := false
	if command == "tui" && (forceWizard || (config.wgNotFound && !config.noWizard && term.IsTerminal(os.Stdin.Fd()))) {
		if forceWizard || confirmPrompt("No VPN tunnel (WireGuard, Tailscale, NetBird, ...) was found. Run the setup wizard to install one?") {
			result, err := runSetupWizard(config)
			if err != nil {
				return err
			}
			applyOnBoot = result.ApplyOnBoot
			if result.VPN != "" && config.wgReason != "" {
				// Pick up the tunnel the wizard just created.
				config.wgIF = ""
				if err := detectVPNInterface(&config, database); err != nil {
					return err
				}
			}
		} else {
			fmt.Println("Skipped. Run \"iptable-ui setup\" any time, or pass --no-wizard to stop this question.")
		}
	}
	manager.WGInterface = config.wgIF
	service.Firewall = manager
	if command == "tui" {
		printInterface("Public interface", config.publicIF, config.publicReason)
		printInterface("VPN interface", config.wgIF, config.wgReason)
	}
	if command == "list" {
		return printRules(service)
	}
	if command == "reconcile" {
		if err := service.Reconcile(context.Background()); err != nil {
			return err
		}
		if err := manager.RemoveLegacy(context.Background(), discovered); err != nil {
			return err
		}
		fmt.Println("Enabled rules restored to the managed iptables chains.")
		return nil
	}
	if err := migrateLegacyRules(context.Background(), service, manager, discovered); err != nil {
		return err
	}
	token, err := newToken()
	if err != nil {
		return fmt.Errorf("generate web session token: %w", err)
	}
	host, err := newHost(config)
	if err != nil {
		return err
	}
	if applyOnBoot {
		if err := host.SetBootRestore(context.Background(), true); err != nil {
			fmt.Fprintln(os.Stderr, "WARNING: could not turn on apply on boot:", err)
		} else {
			fmt.Println("Apply on boot is on: your saved rules come back automatically after a reboot.")
		}
	}
	if changed, err := host.SyncBootRestore(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "WARNING: could not refresh the boot restore unit:", err)
	} else if changed {
		fmt.Fprintln(os.Stderr, "Updated the boot restore unit to match this run's binary and interfaces.")
	}
	setup := wgsetup.SetupManager{ConfigDir: "/etc/wireguard"}
	webRuntime := web.NewRuntime(token, config.webAddress, service, setup, host)
	if config.webEnabled {
		if _, err := webRuntime.Toggle(); err != nil {
			return err
		}
	}
	fmt.Printf("Temporary web token (valid only for this run): %s\n", token)
	fmt.Println("Web UI:", webRuntime.StatusText())
	if isPublicWebBind(config.webAddress) {
		fmt.Fprintln(os.Stderr, "WARNING: this exposes the admin UI over plain HTTP. Restrict the port with a firewall and use a TLS reverse proxy for untrusted networks.")
	}
	defer webRuntime.Close()
	return runInterface(config.whiptail, service, webRuntime, setup, host)
}

// runInterface shows the full TUI or whiptail menus, switching between them
// whenever the user asks, until they quit.
func runInterface(startInWhiptail bool, service app.Service, webRuntime *web.Runtime, setup wgsetup.SetupManager, host system.Host) error {
	whiptailPath, findErr := whiptail.Find()
	if startInWhiptail && findErr != nil {
		return findErr
	}
	useWhiptail := startInWhiptail
	for {
		if useWhiptail {
			dialog := whiptail.Whiptail{Path: whiptailPath, Backtitle: "iptable-ui  |  web token " + webRuntime.Token()}
			switchToTUI, err := whiptail.Run(dialog, service, webRuntime, host)
			if err != nil || !switchToTUI {
				return err
			}
			useWhiptail = false
			continue
		}
		switchToWhiptail, err := tui.Run(service, webRuntime, setup, host, findErr == nil)
		if err != nil || !switchToWhiptail {
			return err
		}
		useWhiptail = true
	}
}

// newHost builds the host settings control. Its boot restore unit re-runs
// this binary's reconcile command with the same database and interfaces.
func newHost(config options) (system.Host, error) {
	executable, err := os.Executable()
	if err != nil {
		return system.Host{}, fmt.Errorf("locate iptable-ui binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	database, err := filepath.Abs(config.database)
	if err != nil {
		return system.Host{}, fmt.Errorf("resolve database path: %w", err)
	}
	return system.Host{
		Runner:          firewall.ExecRunner{},
		PublicInterface: config.publicIF,
		VPNInterface:    config.wgIF,
		RestoreCommand:  []string{executable, "reconcile", "--db", database, "--public-if", config.publicIF, "--wg-if", config.wgIF},
	}, nil
}

func parseOptions(command string, args []string) (options, error) {
	defaultDB, err := defaultDatabase()
	if err != nil {
		return options{}, err
	}
	config := options{database: defaultDB, webEnabled: true, webAddress: "0.0.0.0:8787"}
	flags := flag.NewFlagSet("iptable-ui", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.StringVar(&config.database, "db", config.database, "SQLite database path")
	flags.StringVar(&config.publicIF, "public-if", "", "public network interface (auto-detected when empty)")
	flags.StringVar(&config.wgIF, "wg-if", "", "VPN interface used for forwarded traffic, such as wg0 or tailscale0 (auto-detected when empty)")
	webOn := flags.Bool("web", false, "enable the web UI on this run (enabled by default)")
	webOff := flags.Bool("no-web", false, "disable the web UI on this run")
	flags.BoolVar(&config.noWizard, "no-wizard", false, "do not offer the setup wizard when no VPN is found")
	flags.BoolVar(&config.whiptail, "whiptail", false, "start in whiptail menu mode instead of the full TUI (press U in the TUI to switch)")
	flags.StringVar(&config.webAddress, "web-address", config.webAddress, "web UI bind IP and port (default 0.0.0.0:8787; use 127.0.0.1:8787 for loopback only)")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *webOn && *webOff {
		return options{}, errors.New("--web and --no-web cannot be used together")
	}
	config.webEnabled = !*webOff
	if config.publicIF == "" {
		if detected, err := (system.Host{Runner: firewall.ExecRunner{}}).DetectPublicInterface(context.Background()); err == nil {
			config.publicIF, config.publicReason = detected.Name, detected.Reason
		}
	}
	if command != "list" && config.publicIF == "" {
		return options{}, errors.New("could not detect the public interface; specify --public-if")
	}
	return config, nil
}

func isPublicWebBind(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	bindIP, err := netip.ParseAddr(host)
	return err == nil && (bindIP.IsUnspecified() || !bindIP.IsLoopback())
}

// printInterface shows which interface is in use so users on other setups can
// spot a wrong guess and override it with a flag.
func printInterface(label, name, reason string) {
	if reason == "" {
		fmt.Printf("%s: %s\n", label, name)
		return
	}
	fmt.Printf("%s: %s (auto-detected: %s)\n", label, name, reason)
}

// detectVPNInterface picks the VPN interface from the routes to the saved
// rule destinations.
func detectVPNInterface(config *options, database *store.Store) error {
	rules, err := database.List(context.Background())
	if err != nil {
		return err
	}
	destinations := make([]string, 0, len(rules))
	for _, rule := range rules {
		destinations = append(destinations, rule.DestIP)
	}
	detected := (system.Host{Runner: firewall.ExecRunner{}}).DetectVPNInterface(context.Background(), config.publicIF, destinations)
	config.wgIF, config.wgReason, config.wgNotFound = detected.Name, detected.Reason, detected.NotFound
	return nil
}

// runSetupWizard installs and configures a VPN interactively.
func runSetupWizard(config options) (setupwizard.Result, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	wizard := setupwizard.Wizard{
		In: os.Stdin, Out: os.Stdout, Commands: setupwizard.TerminalCommands{}, LookPath: exec.LookPath,
		OSRelease: "/etc/os-release", WireGuard: wgsetup.SetupManager{ConfigDir: "/etc/wireguard"},
		HomeDir: home, PublicIPv4: interfaceIPv4(config.publicIF), Host: system.Host{},
	}
	return wizard.Run(context.Background())
}

// interfaceIPv4 returns the first IPv4 address on an interface, as a
// suggested WireGuard endpoint.
func interfaceIPv4(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && network.IP.To4() != nil && network.IP.IsGlobalUnicast() {
			return network.IP.String()
		}
	}
	return ""
}

func confirmPrompt(question string) bool {
	fmt.Printf("%s [Y/n] ", question)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && answer == "" {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "" || answer == "y" || answer == "yes"
}

// openService opens the rule database. The firewall manager's VPN interface
// is filled in by the caller once it is known.
func openService(config *options) (app.Service, *store.Store, firewall.Manager, func(), error) {
	dataDir := filepath.Dir(config.database)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return app.Service{}, nil, firewall.Manager{}, nil, fmt.Errorf("create data directory: %w", err)
	}
	database, err := store.Open(config.database)
	if err != nil {
		return app.Service{}, nil, firewall.Manager{}, nil, err
	}
	if err := os.Chmod(config.database, 0600); err != nil {
		database.Close()
		return app.Service{}, nil, firewall.Manager{}, nil, fmt.Errorf("protect database file: %w", err)
	}
	manager := firewall.Manager{Runner: firewall.ExecRunner{}, PublicIF: config.publicIF, WGInterface: config.wgIF, BackupDir: filepath.Join(dataDir, "backups")}
	return app.Service{Store: database, Firewall: manager}, database, manager, func() { _ = database.Close() }, nil
}

func migrateLegacyRules(ctx context.Context, service app.Service, manager firewall.Manager, discovered []firewall.ExistingRule) error {
	legacyFound := false
	for _, existing := range discovered {
		legacyFound = legacyFound || existing.Legacy
	}
	if !legacyFound {
		return nil
	}
	if err := service.Reconcile(ctx); err != nil {
		return fmt.Errorf("adopt existing port forwards: %w", err)
	}
	if err := manager.RemoveLegacy(ctx, discovered); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Moved recognized legacy DNAT rules into the iptable-ui managed chains.")
	return nil
}

func defaultDatabase() (string, error) {
	if os.Geteuid() == 0 {
		return "/var/lib/iptable-ui/rules.db", nil
	}
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "iptable-ui", "rules.db"), nil
}

func printRules(service app.Service) error {
	rules, err := service.List(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("%-4s %-8s %-12s %-22s %-8s %s\n", "ID", "STATE", "PUBLIC", "DESTINATION", "PROTO", "LABEL")
	for _, rule := range rules {
		state := "disabled"
		if rule.Enabled {
			state = "enabled"
		}
		fmt.Printf("%-4d %-8s %-12d %-22s %-8s %s\n", rule.ID, state, rule.PublicPort, fmt.Sprintf("%s:%d", rule.DestIP, rule.DestPort), strings.ToUpper(rule.Protocol), rule.Name)
	}
	return nil
}

func newToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func runWireGuard(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: iptable-ui wireguard status|install|guide [--yes]")
	}
	switch args[0] {
	case "status":
		return wireGuardStatus()
	case "guide":
		fmt.Print(wireGuardGuide)
		return nil
	case "install":
		return installWireGuard(args[1:])
	default:
		return fmt.Errorf("unknown WireGuard command %q", args[0])
	}
}

func wireGuardStatus() error {
	wgPath, err := exec.LookPath("wg")
	if err != nil {
		fmt.Println("WireGuard tools are not installed. Run: sudo iptable-ui wireguard install")
	} else {
		fmt.Printf("WireGuard tools: %s\n", wgPath)
		output, showErr := exec.Command("wg", "show").CombinedOutput()
		if showErr != nil || strings.TrimSpace(string(output)) == "" {
			fmt.Println("No active WireGuard interfaces found.")
		} else {
			fmt.Print(string(output))
		}
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return errors.New("iproute2 is missing; install it with your system package manager")
	}
	if output, err := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output(); err == nil {
		state := "disabled"
		if strings.TrimSpace(string(output)) == "1" {
			state = "enabled"
		}
		fmt.Printf("IPv4 forwarding: %s\n", state)
	}
	if err := exec.Command("ip", "link", "show", "wg0").Run(); err != nil {
		fmt.Println("Interface wg0 is not active. See: iptable-ui wireguard guide")
	} else {
		fmt.Println("Interface wg0 is active.")
	}
	return nil
}

func installWireGuard(args []string) error {
	flags := flag.NewFlagSet("wireguard install", flag.ContinueOnError)
	assumeYes := flags.Bool("yes", false, "skip the confirmation prompt")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("WireGuard installation requires root privileges")
	}
	manager, ok := packages.Detect(exec.LookPath)
	if !ok {
		return errors.New("unsupported package manager; install wireguard-tools manually and run wireguard status")
	}
	fmt.Printf("This will install %s using %s. No WireGuard interface or peer config will be changed.\n", manager.Package(packages.WireGuard), manager.Name)
	if !*assumeYes {
		fmt.Print("Continue? [y/N] ")
		var answer string
		if _, err := fmt.Scanln(&answer); err != nil || (answer != "y" && answer != "Y") {
			return errors.New("installation cancelled")
		}
	}
	for _, command := range manager.Commands(packages.WireGuard) {
		if err := runCommand(command[0], command[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func runCommand(name string, args ...string) error {
	command := exec.Command(name, args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

const wireGuardGuide = `WireGuard guided setup (manual review required)

iptable-ui manages port-forward rules; it does not create keys, peer configs, or
change routes. Install the tools first with: sudo iptable-ui wireguard install

1. On the VPS and the home peer, generate separate keys:
   umask 077
   wg genkey | tee privatekey | wg pubkey > publickey

2. Create /etc/wireguard/wg0.conf on the VPS (replace every placeholder):
   [Interface]
   Address = 10.66.0.1/24
   ListenPort = 51820
   PrivateKey = <VPS_PRIVATE_KEY>

   [Peer]
   PublicKey = <HOME_PUBLIC_KEY>
   AllowedIPs = 10.66.0.2/32, 192.168.0.0/24

3. Create the reciprocal home-peer config. Set its Address to 10.66.0.2/24,
   its PrivateKey to the home key, then add:
   [Peer]
   PublicKey = <VPS_PUBLIC_KEY>
   Endpoint = <VPS_PUBLIC_IP>:51820
   AllowedIPs = 10.66.0.0/24
   PersistentKeepalive = 25

4. Replace the example LAN and endpoint values. Enable IPv4 forwarding on both
	the VPS and the home peer; on Linux, review and run:
	sudo sysctl -w net.ipv4.ip_forward=1
	Persist it with a sysctl configuration file after reviewing network policy.

	Permit UDP 51820 on the VPS provider firewall. The VPS peer's AllowedIPs
	must include the home LAN so destination traffic routes through WireGuard.
	For return traffic, route the VPN subnet (10.66.0.0/24) on the home LAN
	gateway through the home peer, or configure that peer to masquerade forwarded
	traffic onto its LAN. Verify this route before exposing a service.

	Review both files before bringing up the interface:
   sudo chmod 600 /etc/wireguard/wg0.conf
   sudo wg-quick up wg0
   sudo systemctl enable wg-quick@wg0

Check with: sudo iptable-ui wireguard status
The port-forward destination must be reachable through the VPS routes. Keep a
recovery console available before changing firewall or routing configuration.
`
