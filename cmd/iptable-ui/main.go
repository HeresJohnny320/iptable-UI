package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/HeresJohnny320/iptable-ui/internal/acmecert"
	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/backup"
	"github.com/HeresJohnny320/iptable-ui/internal/firewall"
	"github.com/HeresJohnny320/iptable-ui/internal/packages"
	"github.com/HeresJohnny320/iptable-ui/internal/setupwizard"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
	"github.com/HeresJohnny320/iptable-ui/internal/traffic"
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
	// webAddressSet is true when --web-address was given, which overrides
	// the port saved in the database.
	webAddressSet bool
	// webHTTP serves the web UI over plain HTTP instead of HTTPS.
	webHTTP bool
	// tlsEmail goes in the self-signed certificate; tlsCert and tlsKey
	// are the user's own certificate instead.
	tlsEmail string
	tlsCert  string
	tlsKey   string
	// letsEncrypt turns the trusted certificate on ("on"), off ("off") or
	// leaves the saved choice ("") ; domain is certified instead of the IP.
	letsEncrypt string
	domain      string
	whiptail    bool
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
	// Back up before anything below (importing, combining TCP+UDP pairs)
	// changes the database, so those changes can be undone.
	var backups *backup.Manager
	if command == "tui" {
		backups = &backup.Manager{
			Store: database,
			Dir:   filepath.Join(filepath.Dir(config.database), "db-backups"),
			SaveFolder: func(dir string) error {
				return database.SetSetting(context.Background(), backup.FolderSetting, dir)
			},
			Apply: func(ctx context.Context, rules []store.Rule, settings map[string]string) error {
				if err := database.ReplaceAll(ctx, rules, settings); err != nil {
					return err
				}
				return service.Reconcile(ctx)
			},
		}
		if err := useBackupFolder(database, backups); err != nil {
			fmt.Fprintln(os.Stderr, "WARNING:", err)
		}
		fmt.Println("Database backups:", backups.Folder())
		if _, _, err := backups.Create(context.Background(), backup.Startup); err != nil {
			fmt.Fprintln(os.Stderr, "WARNING: could not back up the database:", err)
		}
	}
	var discovered []firewall.ExistingRule
	needsReapply := false
	if os.Geteuid() == 0 && config.publicIF != "" {
		discovered, err = manager.Discover(context.Background())
		if err != nil {
			return err
		}
		// Say what is about to happen before anything is imported or removed:
		// the full explanation on the first run, and newly found forwards later.
		if command == "tui" {
			seen, err := database.Setting(context.Background(), introSetting)
			if err != nil {
				return err
			}
			firstRun := seen == ""
			if legacy := legacyRules(discovered); firstRun || len(legacy) > 0 {
				takeoverNotice(os.Stdout, firstRun, legacy, config.publicIF, manager.BackupDir)
				question := "Take them over?"
				if firstRun {
					question = "Continue?"
				}
				if term.IsTerminal(os.Stdin.Fd()) && !confirmPrompt(question) {
					if firstRun {
						fmt.Println("Nothing was changed. Run iptable-ui again when you are ready.")
						return nil
					}
					fmt.Println("Leaving those forwards alone for now. They will be offered again next time.")
					discovered = withoutLegacy(discovered)
				}
				if firstRun {
					if err := database.SetSetting(context.Background(), introSetting, "1"); err != nil {
						return err
					}
				}
			}
		}
		foundRules := make([]store.Rule, 0, len(discovered))
		for _, existing := range discovered {
			foundRules = append(foundRules, existing.Rule)
		}
		imported, importErr := database.ImportMissing(context.Background(), store.CombineProtocols(foundRules))
		if importErr != nil {
			return importErr
		}
		if imported > 0 {
			fmt.Fprintf(os.Stderr, "Imported %d existing iptables rule(s) into the database.\n", imported)
		}
		merged, mergeErr := database.MergeProtocolPairs(context.Background())
		if mergeErr != nil {
			return mergeErr
		}
		if merged > 0 {
			fmt.Fprintf(os.Stderr, "Combined %d matching TCP and UDP rule pair(s) into single TCP+UDP rules.\n", merged)
			needsReapply = true
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
	if needsReapply {
		if err := service.Reconcile(context.Background()); err != nil {
			return err
		}
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
	service.BeforeDeleteAll = func(ctx context.Context) error {
		_, _, err := backups.Create(ctx, backup.PreClear)
		return err
	}
	backupContext, stopBackups := context.WithCancel(context.Background())
	defer stopBackups()
	go backups.Run(backupContext, nil)
	monitor := &traffic.Monitor{Runner: firewall.ExecRunner{}, Adapters: func() []string { return []string{config.publicIF, config.wgIF} }}
	go monitor.Run(backupContext)
	setup := wgsetup.SetupManager{ConfigDir: "/etc/wireguard"}
	if !config.webAddressSet {
		config.webAddress = savedWebAddress(database, config.webAddress)
	}
	webRuntime := web.NewRuntime(token, config.webAddress, web.Services{Rules: service, WireGuard: setup, Host: host, Backups: backups, Settings: database, Traffic: monitor})
	webRuntime.SetLinkHost(interfaceIPv4(config.publicIF))
	webRuntime.OnPortChange(func(port int) error {
		return database.SetSetting(context.Background(), webPortSetting, strconv.Itoa(port))
	})
	var certificates *acmecert.Controller
	if !config.webHTTP {
		if err := useTLS(webRuntime, database, config); err != nil {
			return err
		}
		if config.tlsCert == "" {
			if certificates, err = trustedCertificates(database, service, config); err != nil {
				return err
			}
			defer certificates.Stop()
			webRuntime.UseTrusted(certificates.Certificate)
			webRuntime.SetCertificates(certificates)
			if status := certificates.Status(); net.ParseIP(status.Identifier) == nil && status.Identifier != "" {
				webRuntime.SetLinkHost(status.Identifier) // links must use the certified name
			}
		}
	}
	if config.webEnabled {
		if _, err := webRuntime.Toggle(); err != nil {
			return err
		}
	}
	// The IP and token are masked on screen (screenshots, screen sharing);
	// the link still opens the full address, and the TUI can copy or show it.
	fmt.Printf("Temporary web token (valid only for this run): %s\n", web.MaskToken(token))
	fmt.Println("Web UI:", webRuntime.MaskedStatusText())
	if webRuntime.Enabled() {
		fmt.Println("Open it signed in:", terminalLink(webRuntime.SignInURL(), web.MaskURL(webRuntime.URL())), " (in the TUI: C copies the link, V shows it)")
	}
	if webRuntime.HTTPS() {
		if err := explainCertificate(os.Stdout, database, webRuntime.Fingerprint(), config.tlsCert != "" || webRuntime.Trusted()); err != nil {
			return err
		}
	}
	if config.webHTTP && isPublicWebBind(config.webAddress) {
		fmt.Fprintln(os.Stderr, "WARNING: this exposes the admin UI over plain HTTP. Restrict the port with a firewall and use a TLS reverse proxy for untrusted networks.")
	}
	defer webRuntime.Close()
	var certificateControl tui.CertificateControl
	if certificates != nil {
		certificateControl = certificates
	}
	return runInterface(config.whiptail, service, webRuntime, setup, host, backups, monitor, database, certificateControl)
}

// runInterface shows the full TUI or whiptail menus, switching between them
// whenever the user asks, until they quit.
func runInterface(startInWhiptail bool, service app.Service, webRuntime *web.Runtime, setup wgsetup.SetupManager, host system.Host, backups *backup.Manager, monitor *traffic.Monitor, settings *store.Store, certificates tui.CertificateControl) error {
	whiptailPath, findErr := whiptail.Find()
	if startInWhiptail && findErr != nil {
		return findErr
	}
	useWhiptail := startInWhiptail
	for {
		if useWhiptail {
			dialog := whiptail.Whiptail{Path: whiptailPath, Backtitle: "iptable-ui  |  web token " + web.MaskToken(webRuntime.Token())}
			switchToTUI, err := whiptail.Run(dialog, service, webRuntime, host)
			if err != nil || !switchToTUI {
				return err
			}
			useWhiptail = false
			continue
		}
		switchToWhiptail, err := tui.Run(tui.Options{Service: service, Web: webRuntime, WireGuard: setup, Host: host, Backups: backups,
			Traffic: monitor, Settings: settings, Certificates: certificates, AllowWhiptail: findErr == nil})
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
	flags.BoolVar(&config.webHTTP, "http", false, "serve the web UI over plain HTTP instead of HTTPS")
	flags.StringVar(&config.tlsEmail, "tls-email", "", "email put in the self-signed HTTPS certificate (saved; default "+web.DefaultCertEmail+")")
	flags.StringVar(&config.tlsCert, "tls-cert", "", "your own HTTPS certificate (PEM) instead of the self-signed one; needs --tls-key")
	flags.StringVar(&config.tlsKey, "tls-key", "", "private key (PEM) for --tls-cert")
	letsEncryptOn := flags.Bool("letsencrypt", false, "get a browser-trusted HTTPS certificate from Let's Encrypt (saved; needs port 80)")
	letsEncryptOff := flags.Bool("no-letsencrypt", false, "stop using Let's Encrypt (saved)")
	flags.StringVar(&config.domain, "domain", "", "domain name for the Let's Encrypt certificate instead of the public IP (saved)")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	flags.Visit(func(set *flag.Flag) { config.webAddressSet = config.webAddressSet || set.Name == "web-address" })
	if *webOn && *webOff {
		return options{}, errors.New("--web and --no-web cannot be used together")
	}
	config.webEnabled = !*webOff
	if (config.tlsCert == "") != (config.tlsKey == "") {
		return options{}, errors.New("--tls-cert and --tls-key must be used together")
	}
	if config.webHTTP && (config.tlsCert != "" || config.tlsEmail != "") {
		return options{}, errors.New("--http cannot be used with --tls-cert, --tls-key or --tls-email")
	}
	switch {
	case *letsEncryptOn && *letsEncryptOff:
		return options{}, errors.New("--letsencrypt and --no-letsencrypt cannot be used together")
	case *letsEncryptOn:
		config.letsEncrypt = "on"
	case *letsEncryptOff:
		config.letsEncrypt = "off"
	}
	if *letsEncryptOn && (config.webHTTP || config.tlsCert != "") {
		return options{}, errors.New("--letsencrypt cannot be used with --http or --tls-cert")
	}
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

const (
	webPortSetting     = "web.port"
	webTLSEmailSetting = "web.tls_email"
)

const (
	letsEncryptSetting = "web.letsencrypt"
	domainSetting      = "web.domain"
)

// trustedCertificates prepares the Let's Encrypt certificate for the public
// IP (or --domain), turned on or off by flag or by the saved choice.
func trustedCertificates(database *store.Store, service app.Service, config options) (*acmecert.Controller, error) {
	ctx := context.Background()
	domain := strings.TrimSpace(config.domain)
	if domain != "" {
		if err := database.SetSetting(ctx, domainSetting, domain); err != nil {
			return nil, err
		}
	} else if saved, err := database.Setting(ctx, domainSetting); err == nil {
		domain = saved
	}
	identifier := domain
	if identifier == "" {
		identifier = interfaceIPv4(config.publicIF)
	}
	controller := &acmecert.Controller{
		// No contact email is sent: Let's Encrypt ended expiry emails in 2025
		// and now only adds given addresses to its mailing list.
		Manager: &acmecert.Manager{Dir: filepath.Join(filepath.Dir(config.database), "letsencrypt"),
			Identifier: identifier, Preflight: letsEncryptPreflight(service, identifier)},
		Save: func(on bool) error {
			return database.SetSetting(context.Background(), letsEncryptSetting, map[bool]string{true: "on", false: "off"}[on])
		},
	}
	wanted := config.letsEncrypt
	if wanted == "" {
		wanted, _ = database.Setting(ctx, letsEncryptSetting)
	}
	if wanted == "on" {
		if err := controller.SetEnabled(true); err != nil {
			return nil, err
		}
		if status := controller.Status(); status.Ready {
			fmt.Printf("Trusted certificate from Let's Encrypt for %s, valid until %s. Browsers will not warn.\n", identifier, status.NotAfter.Local().Format("2006-01-02"))
		} else {
			fmt.Printf("Requesting a trusted certificate from Let's Encrypt for %s in the background (needs port 80 open). Until it arrives, the self-signed one is used.\n", identifier)
		}
	} else if config.letsEncrypt == "off" {
		if err := controller.SetEnabled(false); err != nil {
			return nil, err
		}
	}
	return controller, nil
}

// letsEncryptPreflight catches setups where Let's Encrypt's check on port 80
// would fail anyway, and says why, instead of wasting the few attempts per
// hour Let's Encrypt allows.
func letsEncryptPreflight(service app.Service, identifier string) func() error {
	return func() error {
		if ip := net.ParseIP(identifier); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return fmt.Errorf("this server's address %s is private (your provider maps a public IP in front of it), so Let's Encrypt cannot check it; point a domain at the public IP and start with --domain", identifier)
		}
		rules, err := service.List(context.Background())
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if rule.Enabled && rule.PublicPort == 80 && rule.Protocol != "udp" {
				return fmt.Errorf("port 80 is forwarded to %s:%d by rule #%d, so Let's Encrypt's check would reach that machine instead of iptable-ui; turn that rule off while the certificate is requested, or keep the self-signed certificate", rule.DestIP, rule.DestPort, rule.ID)
			}
		}
		return nil
	}
}

// fingerprintSetting remembers the last certificate shown, to tell the user
// when the browser is about to see a new one.
const fingerprintSetting = "web.tls_fingerprint"

// explainCertificate prints the HTTPS certificate's fingerprint and how to
// use it. Over SSH this is a trustworthy channel, so comparing it with the
// browser's certificate details exposes anyone intercepting the connection.
func explainCertificate(out io.Writer, database *store.Store, fingerprint string, ownCert bool) error {
	fmt.Fprintln(out, "Web UI certificate (SHA-256):", fingerprint)
	if ownCert {
		return nil
	}
	saved, err := database.Setting(context.Background(), fingerprintSetting)
	if err != nil {
		return err
	}
	if saved != fingerprint {
		fmt.Fprintln(out, "This certificate is new, so your browser will warn about it once. Before you accept it,")
		fmt.Fprintln(out, "open the certificate details in the browser and check its SHA-256 fingerprint matches")
		fmt.Fprintln(out, "the one above. If it does not match, someone may be intercepting the connection: stop.")
		return database.SetSetting(context.Background(), fingerprintSetting, fingerprint)
	}
	fmt.Fprintln(out, "Same certificate as last time. If your browser warns about it again anyway, do not")
	fmt.Fprintln(out, "continue: someone may be intercepting the connection.")
	return nil
}

// useTLS turns on HTTPS for the web UI, with the user's certificate or a
// self-signed one kept next to the database. The certificate's email comes
// from --tls-email, the database, or (on first run) a question; whichever
// is used is saved, so later runs keep the same certificate.
func useTLS(webRuntime *web.Runtime, database *store.Store, config options) error {
	if config.tlsCert != "" {
		cert, err := web.LoadCert(config.tlsCert, config.tlsKey)
		if err != nil {
			return err
		}
		webRuntime.UseTLS(cert)
		return nil
	}
	email := strings.TrimSpace(config.tlsEmail)
	if email != "" {
		if !validEmail(email) {
			return fmt.Errorf("--tls-email %q is not a valid email address", email)
		}
	} else {
		saved, err := database.Setting(context.Background(), webTLSEmailSetting)
		if err != nil {
			return err
		}
		email = saved
	}
	if email == "" {
		email = web.DefaultCertEmail
		if term.IsTerminal(os.Stdin.Fd()) {
			email = askCertEmail(os.Stdin, os.Stdout)
		}
	}
	if err := database.SetSetting(context.Background(), webTLSEmailSetting, email); err != nil {
		return err
	}
	cert, err := web.SelfSignedCert(filepath.Dir(config.database), email, certHosts(config))
	if err != nil {
		return err
	}
	webRuntime.UseTLS(cert)
	return nil
}

// certHosts are the addresses a self-signed certificate covers: loopback,
// the machine's name, the public IP and the bind IP.
func certHosts(config options) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if name, err := os.Hostname(); err == nil && name != "" {
		hosts = append(hosts, name)
	}
	if ip := interfaceIPv4(config.publicIF); ip != "" {
		hosts = append(hosts, ip)
	}
	if host, _, err := net.SplitHostPort(config.webAddress); err == nil {
		if address, err := netip.ParseAddr(host); err == nil && !address.IsUnspecified() && !address.IsLoopback() {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

// terminalLink shows text that opens target when clicked, in terminals that
// support links (OSC 8); others, and non-terminals, just show the text.
func terminalLink(target, text string) string {
	if !term.IsTerminal(os.Stdout.Fd()) || os.Getenv("TERM") == "dumb" {
		return text
	}
	return "\x1b]8;;" + target + "\x1b\\" + text + "\x1b]8;;\x1b\\"
}

// useBackupFolder points backups at the saved folder, or on first run at
// ~/iptable-ui-backups of the user who ran sudo (moving any backups from the
// old location), where they can be downloaded without root.
func useBackupFolder(database *store.Store, backups *backup.Manager) error {
	saved, err := database.Setting(context.Background(), backup.FolderSetting)
	if err != nil {
		return err
	}
	if saved != "" {
		backups.Dir = saved
		return nil
	}
	return backups.MoveTo(defaultBackupFolder())
}

func defaultBackupFolder() string {
	home := ""
	if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
		if account, err := user.Lookup(name); err == nil {
			home = account.HomeDir
		}
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if home == "" {
		home = "/root"
	}
	return filepath.Join(home, "iptable-ui-backups")
}

// savedWebAddress applies the web UI port saved in the database (chosen in
// the UI) to the default bind address.
func savedWebAddress(database *store.Store, address string) string {
	saved, err := database.Setting(context.Background(), webPortSetting)
	if err != nil || saved == "" {
		return address
	}
	port, err := strconv.Atoi(saved)
	host, _, splitErr := net.SplitHostPort(address)
	if err != nil || port < 1 || port > 65535 || splitErr != nil {
		return address
	}
	return net.JoinHostPort(host, saved)
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

// askCertEmail asks for the email to put in the web UI's HTTPS certificate,
// until it gets a valid one; a blank answer uses the default.
func askCertEmail(in io.Reader, out io.Writer) string {
	reader := bufio.NewReader(in)
	for {
		fmt.Fprintf(out, "Email for the web UI's HTTPS certificate [%s]: ", web.DefaultCertEmail)
		answer, err := reader.ReadString('\n')
		answer = strings.TrimSpace(answer)
		if answer == "" {
			return web.DefaultCertEmail
		}
		if validEmail(answer) {
			return answer
		}
		if err != nil {
			return web.DefaultCertEmail
		}
		fmt.Fprintln(out, "That doesn't look like an email address; try again or press Enter for the default.")
	}
}

// validEmail accepts a bare address such as you@example.com.
func validEmail(email string) bool {
	address, err := mail.ParseAddress(email)
	return err == nil && address.Address == email && address.Name == ""
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
