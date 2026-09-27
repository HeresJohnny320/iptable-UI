package main

import (
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

	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/firewall"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/tui"
	"github.com/HeresJohnny320/iptable-ui/internal/web"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
)

type options struct {
	database   string
	publicIF   string
	wgIF       string
	webEnabled bool
	webAddress string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "wireguard" {
		return runWireGuard(args[1:])
	}
	command := "tui"
	if len(args) > 0 && (args[0] == "list" || args[0] == "reconcile") {
		command, args = args[0], args[1:]
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
	service, database, manager, closeStore, err := openService(config)
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
	setup := wgsetup.SetupManager{ConfigDir: "/etc/wireguard"}
	webRuntime := web.NewRuntime(token, config.webAddress, service, setup)
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
	return tui.Run(service, webRuntime, setup)
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
	flags.StringVar(&config.wgIF, "wg-if", "wg0", "WireGuard network interface used for forwarded traffic")
	webOn := flags.Bool("web", false, "enable the web UI on this run (enabled by default)")
	webOff := flags.Bool("no-web", false, "disable the web UI on this run")
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
		config.publicIF = detectPublicInterface()
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

func openService(config options) (app.Service, *store.Store, firewall.Manager, func(), error) {
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

func detectPublicInterface() string {
	output, err := exec.Command("ip", "-o", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(output))
	for index, field := range fields {
		if field == "dev" && index+1 < len(fields) {
			return fields[index+1]
		}
	}
	return ""
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
	manager, packageName := findPackageManager()
	if manager == "" {
		return errors.New("unsupported package manager; install wireguard-tools manually and run wireguard status")
	}
	fmt.Printf("This will install %s using %s. No WireGuard interface or peer config will be changed.\n", packageName, manager)
	if !*assumeYes {
		fmt.Print("Continue? [y/N] ")
		var answer string
		if _, err := fmt.Scanln(&answer); err != nil || (answer != "y" && answer != "Y") {
			return errors.New("installation cancelled")
		}
	}
	if manager == "apt-get" {
		if err := runCommand("apt-get", "update"); err != nil {
			return err
		}
	}
	return runCommand(manager, packageInstallArgs(manager, packageName)...)
}

func findPackageManager() (string, string) {
	for _, item := range [][2]string{{"apt-get", "wireguard"}, {"dnf", "wireguard-tools"}, {"yum", "wireguard-tools"}, {"pacman", "wireguard-tools"}, {"zypper", "wireguard-tools"}} {
		if _, err := exec.LookPath(item[0]); err == nil {
			return item[0], item[1]
		}
	}
	return "", ""
}

func packageInstallArgs(manager, packageName string) []string {
	switch manager {
	case "apt-get":
		return []string{"install", "-y", packageName}
	case "dnf", "yum", "zypper":
		return []string{"install", "-y", packageName}
	case "pacman":
		return []string{"-S", "--noconfirm", packageName}
	default:
		return nil
	}
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
