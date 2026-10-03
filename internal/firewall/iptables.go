package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HeresJohnny320/iptable-ui/internal/store"
)

const (
	dnatChain    = "IPTUI_DNAT"
	forwardChain = "IPTUI_FWD"
	snatChain    = "IPTUI_SNAT"
	mssChain     = "IPTUI_MSS"
)

// ErrNoConntrack means the conntrack tool is missing, so open connections
// cannot be closed right away.
var ErrNoConntrack = errors.New("conntrack is not installed")

type Runner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("missing command")
	}
	output, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", args[0], strings.Join(args[1:], " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

type Manager struct {
	Runner      Runner
	PublicIF    string
	WGInterface string
	BackupDir   string
}

type ExistingRule struct {
	Rule   store.Rule
	Legacy bool
	// Count is how many copies match on the public interface (-i); AnyCount
	// is how many match without an interface, as other proxy scripts write them.
	Count    int
	AnyCount int
	// Helpers are delete arguments for the legacy MASQUERADE and FORWARD
	// rules that served this forward, removed once it is adopted.
	Helpers [][]string
}

func (m Manager) Discover(ctx context.Context) ([]ExistingRule, error) {
	if m.Runner == nil {
		return nil, errors.New("firewall command runner is not configured")
	}
	if !validInterface(m.PublicIF) {
		return nil, errors.New("public interface must be a valid Linux interface name")
	}
	output, err := m.Runner.Run(ctx, "iptables-save")
	if err != nil {
		return nil, fmt.Errorf("read current iptables rules: %w", err)
	}
	return ParseExistingRules(string(output), m.PublicIF), nil
}

func (m Manager) RemoveLegacy(ctx context.Context, rules []ExistingRule) error {
	for _, existing := range rules {
		if !existing.Legacy {
			continue
		}
		dnat := []string{"-p", existing.Rule.Protocol, "--dport", fmt.Sprint(existing.Rule.PublicPort), "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", existing.Rule.DestIP, existing.Rule.DestPort)}
		for count := 0; count < existing.AnyCount; count++ {
			if err := m.run(ctx, append([]string{"-t", "nat", "-D", "PREROUTING"}, dnat...)...); err != nil {
				return fmt.Errorf("remove adopted legacy DNAT rule on port %d: %w", existing.Rule.PublicPort, err)
			}
		}
		for _, helper := range existing.Helpers {
			if err := m.run(ctx, helper...); err != nil {
				return fmt.Errorf("remove adopted legacy helper rule for %s:%d: %w", existing.Rule.DestIP, existing.Rule.DestPort, err)
			}
		}
		for count := 0; count < existing.Count; count++ {
			if err := m.run(ctx, append([]string{"-t", "nat", "-D", "PREROUTING", "-i", m.PublicIF}, dnat...)...); err != nil {
				return fmt.Errorf("remove adopted legacy DNAT rule on port %d: %w", existing.Rule.PublicPort, err)
			}
			forwardRule := []string{"iptables", "-C", "FORWARD", "-d", existing.Rule.DestIP, "-p", existing.Rule.Protocol, "--dport", fmt.Sprint(existing.Rule.DestPort), "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED", "-j", "ACCEPT"}
			if _, err := m.Runner.Run(ctx, forwardRule...); err == nil {
				forwardRule[1] = "-D"
				if _, err := m.Runner.Run(ctx, forwardRule...); err != nil {
					return fmt.Errorf("remove adopted legacy FORWARD rule for %s:%d: %w", existing.Rule.DestIP, existing.Rule.DestPort, err)
				}
			}
		}
	}
	return nil
}

func ParseExistingRules(ruleset, publicInterface string) []ExistingRule {
	if !validInterface(publicInterface) {
		return nil
	}
	type key struct {
		port     uint16
		protocol string
	}
	type candidate struct {
		existing  ExistingRule
		ambiguous bool
	}
	found := make(map[key]candidate)
	// Destinations still used by a DNAT rule that will not be adopted; their
	// helper rules must stay.
	keepBackends := make(map[backend]bool)
	var helperLines []helperRule
	table := ""
	for _, line := range strings.Split(ruleset, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			table = strings.TrimPrefix(line, "*")
			continue
		}
		if line == "COMMIT" {
			table = ""
			continue
		}
		if helper, ok := parseHelperRule(table, line); ok {
			helperLines = append(helperLines, helper)
			continue
		}
		if table != "nat" {
			continue
		}
		existing, anyInterface, ok := parseDNATRule(line, publicInterface)
		if !ok {
			if target, isDNAT := dnatBackend(line); isDNAT {
				keepBackends[target] = true
			}
			continue
		}
		if existing.Legacy {
			if anyInterface {
				existing.AnyCount = 1
			} else {
				existing.Count = 1
			}
		}
		id := key{port: existing.Rule.PublicPort, protocol: existing.Rule.Protocol}
		previous, exists := found[id]
		if !exists {
			found[id] = candidate{existing: existing}
			continue
		}
		if previous.existing.Rule.DestIP != existing.Rule.DestIP || previous.existing.Rule.DestPort != existing.Rule.DestPort {
			previous.ambiguous = true
			found[id] = previous
			continue
		}
		previous.existing.Legacy = previous.existing.Legacy || existing.Legacy
		previous.existing.Count += existing.Count
		previous.existing.AnyCount += existing.AnyCount
		found[id] = previous
	}
	result := make([]ExistingRule, 0, len(found))
	for _, candidate := range found {
		if candidate.ambiguous {
			keepBackends[ruleBackend(candidate.existing.Rule)] = true
			continue
		}
		result = append(result, candidate.existing)
	}
	sort.Slice(result, func(a, b int) bool {
		if result[a].Rule.PublicPort != result[b].Rule.PublicPort {
			return result[a].Rule.PublicPort < result[b].Rule.PublicPort
		}
		return result[a].Rule.Protocol < result[b].Rule.Protocol
	})
	// Attach each helper to one adopted legacy forward for its destination, so
	// it is deleted exactly once.
	for _, helper := range helperLines {
		if keepBackends[helper.backend] {
			continue
		}
		for index := range result {
			if result[index].Legacy && ruleBackend(result[index].Rule) == helper.backend {
				result[index].Helpers = append(result[index].Helpers, helper.deleteArgs)
				break
			}
		}
	}
	return result
}

type backend struct {
	ip       string
	port     uint16
	protocol string
}

type helperRule struct {
	backend    backend
	deleteArgs []string
}

func ruleBackend(rule store.Rule) backend {
	return backend{ip: rule.DestIP, port: rule.DestPort, protocol: rule.Protocol}
}

// parseHelperRule recognizes the per-forward rules other proxy scripts add
// next to a DNAT rule:
//
//	nat:    -A POSTROUTING -d IP/32 -o VPN -p tcp -m tcp --dport PORT -j MASQUERADE
//	filter: -A FORWARD     -d IP/32 -o VPN -p tcp -m tcp --dport PORT -j ACCEPT
//
// Anything else (extra matches, negations, comments) is left alone.
func parseHelperRule(table, line string) (helperRule, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "-A" || strings.ContainsAny(line, "!\"'") {
		return helperRule{}, false
	}
	wantTarget := map[string]string{"nat": "MASQUERADE", "filter": "ACCEPT"}[table]
	wantChain := map[string]string{"nat": "POSTROUTING", "filter": "FORWARD"}[table]
	if wantTarget == "" || fields[1] != wantChain {
		return helperRule{}, false
	}
	values := make(map[string]string)
	for index := 2; index+1 < len(fields); index += 2 {
		option, value := fields[index], fields[index+1]
		if option == "-m" {
			if value != "tcp" && value != "udp" {
				return helperRule{}, false
			}
			continue
		}
		if option != "-d" && option != "-o" && option != "-p" && option != "--dport" && option != "-j" {
			return helperRule{}, false
		}
		values[option] = value
	}
	if len(fields)%2 != 0 || values["-j"] != wantTarget || !validInterface(values["-o"]) {
		return helperRule{}, false
	}
	address, err := netip.ParsePrefix(values["-d"])
	if err != nil || !address.Addr().Is4() || address.Bits() != 32 {
		return helperRule{}, false
	}
	port, err := strconv.ParseUint(values["--dport"], 10, 16)
	protocol := values["-p"]
	if err != nil || port == 0 || (protocol != "tcp" && protocol != "udp") {
		return helperRule{}, false
	}
	deleteArgs := append([]string{"-t", table, "-D", wantChain}, fields[2:]...)
	return helperRule{backend: backend{ip: address.Addr().String(), port: uint16(port), protocol: protocol}, deleteArgs: deleteArgs}, true
}

// dnatBackend extracts the destination of any PREROUTING DNAT rule, adopted or not.
func dnatBackend(line string) (backend, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "-A" || fields[1] != "PREROUTING" {
		return backend{}, false
	}
	var target backend
	isDNAT := false
	for index := 2; index+1 < len(fields); index++ {
		switch fields[index] {
		case "-p", "--protocol":
			target.protocol = fields[index+1]
		case "-j", "--jump":
			isDNAT = fields[index+1] == "DNAT"
		case "--to-destination", "--to":
			address, port, ok := strings.Cut(fields[index+1], ":")
			if !ok {
				return backend{}, false
			}
			parsedPort, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return backend{}, false
			}
			target.ip, target.port = address, uint16(parsedPort)
		}
	}
	return target, isDNAT && target.ip != ""
}

// parseDNATRule reads a DNAT rule on the public interface. A PREROUTING rule
// with no interface at all (anyInterface) is also adopted, since common proxy
// scripts write them that way.
func parseDNATRule(line, publicInterface string) (existing ExistingRule, anyInterface bool, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "-A" || (fields[1] != "PREROUTING" && fields[1] != dnatChain) {
		return ExistingRule{}, false, false
	}
	var inputInterface, protocol, destination, target string
	var publicPort uint16
	for index := 2; index < len(fields); index++ {
		field := fields[index]
		if field == "-m" {
			if index+1 >= len(fields) {
				return ExistingRule{}, false, false
			}
			module := fields[index+1]
			if module != "tcp" && module != "udp" {
				return ExistingRule{}, false, false
			}
			index++
			continue
		}
		if field != "-i" && field != "--in-interface" && field != "-p" && field != "--protocol" && field != "--dport" && field != "--destination-port" && field != "-j" && field != "--jump" && field != "--to-destination" && field != "--to" {
			return ExistingRule{}, false, false
		}
		if index+1 >= len(fields) {
			return ExistingRule{}, false, false
		}
		value := fields[index+1]
		index++
		switch field {
		case "-i", "--in-interface":
			inputInterface = value
		case "-p", "--protocol":
			protocol = value
		case "--dport", "--destination-port":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port == 0 {
				return ExistingRule{}, false, false
			}
			publicPort = uint16(port)
		case "-j", "--jump":
			target = value
		case "--to-destination", "--to":
			destination = value
		}
	}
	anyInterface = inputInterface == "" && fields[1] == "PREROUTING"
	if (inputInterface != publicInterface && !anyInterface) || (protocol != "tcp" && protocol != "udp") || publicPort == 0 || target != "DNAT" {
		return ExistingRule{}, false, false
	}
	separator := strings.LastIndex(destination, ":")
	if separator < 1 || separator == len(destination)-1 {
		return ExistingRule{}, false, false
	}
	address, err := netip.ParseAddr(destination[:separator])
	if err != nil || !address.Is4() || (anyInterface && address.IsLoopback()) {
		return ExistingRule{}, false, false
	}
	destinationPort, err := strconv.ParseUint(destination[separator+1:], 10, 16)
	if err != nil || destinationPort == 0 {
		return ExistingRule{}, false, false
	}
	return ExistingRule{
		Rule:   store.Rule{PublicPort: publicPort, DestIP: address.String(), DestPort: uint16(destinationPort), Protocol: protocol, Enabled: true},
		Legacy: fields[1] == "PREROUTING",
	}, anyInterface, true
}

func (m Manager) Reconcile(ctx context.Context, rules []store.Rule) error {
	if m.Runner == nil {
		return errors.New("firewall command runner is not configured")
	}
	if strings.TrimSpace(m.PublicIF) == "" {
		return errors.New("public interface is required")
	}
	if !validInterface(m.PublicIF) || !validInterface(m.WGInterface) {
		return errors.New("public and WireGuard interfaces must be valid Linux interface names")
	}
	for _, rule := range rules {
		address, err := netip.ParseAddr(rule.DestIP)
		if err != nil || !address.Is4() || rule.PublicPort == 0 || rule.DestPort == 0 {
			return fmt.Errorf("rule %d has invalid forwarding data", rule.ID)
		}
		if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "both" {
			return fmt.Errorf("rule %d has invalid protocol %q", rule.ID, rule.Protocol)
		}
	}
	restorer, ok := m.Runner.(InputRunner)
	if !ok {
		return errors.New("firewall command runner cannot feed iptables-restore")
	}
	current, err := m.Runner.Run(ctx, "iptables-save")
	if err != nil {
		return fmt.Errorf("read current iptables rules: %w", err)
	}
	if err := m.saveBackup(current); err != nil {
		return err
	}
	// One iptables-restore call replaces every managed chain at once: fast no
	// matter how many rules there are, and never half-applied.
	if _, err := restorer.RunInput(ctx, m.restorePayload(rules, string(current)), "iptables-restore", "--noflush"); err != nil {
		return fmt.Errorf("apply firewall rules: %w", err)
	}
	return nil
}

// InputRunner runs a command with text on its standard input.
type InputRunner interface {
	RunInput(ctx context.Context, input string, args ...string) ([]byte, error)
}

func (ExecRunner) RunInput(ctx context.Context, input string, args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("missing command")
	}
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	command.Stdin = strings.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

type managedChain struct{ table, parent, name string }

var managedChains = []managedChain{
	{"nat", "PREROUTING", dnatChain},
	{"nat", "POSTROUTING", snatChain},
	{"filter", "FORWARD", forwardChain},
	{"mangle", "FORWARD", mssChain},
}

// restorePayload is the iptables-restore input for all managed chains.
// With --noflush, declaring a user chain empties it and leaves every other
// chain alone; hooks into the built-in chains are added only when missing.
func (m Manager) restorePayload(rules []store.Rule, current string) string {
	byTable := map[string][]string{
		// Tunnels have a smaller MTU than the internet side, so full-size TCP
		// segments would be dropped and large transfers would stall.
		"mangle": {"-A " + mssChain + " -o " + m.WGInterface + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"},
	}
	for _, rule := range rules {
		for _, protocol := range protocols(rule.Protocol) {
			for _, command := range m.ruleCommands(rule, protocol) {
				byTable[command.table] = append(byTable[command.table], strings.Join(command.args, " "))
			}
		}
	}
	hooks := existingHooks(current)
	var payload strings.Builder
	for _, table := range []string{"nat", "filter", "mangle"} {
		payload.WriteString("*" + table + "\n")
		for _, chain := range managedChains {
			if chain.table == table {
				payload.WriteString(":" + chain.name + " - [0:0]\n")
			}
		}
		for _, chain := range managedChains {
			if chain.table == table && !hooks[table+" "+chain.parent+" "+chain.name] {
				payload.WriteString("-I " + chain.parent + " 1 -j " + chain.name + "\n")
			}
		}
		for _, line := range byTable[table] {
			payload.WriteString(line + "\n")
		}
		payload.WriteString("COMMIT\n")
	}
	return payload.String()
}

// existingHooks finds jumps from built-in chains to managed chains in
// iptables-save output, keyed "table PARENT CHAIN".
func existingHooks(ruleset string) map[string]bool {
	hooks := make(map[string]bool)
	table := ""
	for _, line := range strings.Split(ruleset, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			table = strings.TrimPrefix(line, "*")
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 4 && fields[0] == "-A" && fields[2] == "-j" && strings.HasPrefix(fields[3], "IPTUI_") {
			hooks[table+" "+fields[1]+" "+fields[3]] = true
		}
	}
	return hooks
}

type tableCommand struct {
	table string
	args  []string
}

// ruleCommands builds the managed-chain rules for one forward and protocol.
func (m Manager) ruleCommands(rule store.Rule, protocol string) []tableCommand {
	publicPort, destPort := fmt.Sprint(rule.PublicPort), fmt.Sprint(rule.DestPort)
	if !rule.Enabled {
		// Without this, connections opened before the rule was disabled keep
		// flowing, because conntrack remembers their NAT mapping.
		return []tableCommand{{"filter", []string{"-A", forwardChain, "-p", protocol, "-m", "conntrack", "--ctstate", "DNAT", "--ctorigdstport", publicPort, "--ctreplsrc", rule.DestIP, "-j", "DROP"}}}
	}
	commands := []tableCommand{
		{"nat", []string{"-A", dnatChain, "-i", m.PublicIF, "-p", protocol, "--dport", publicPort, "-j", "DNAT", "--to-destination", rule.DestIP + ":" + destPort}},
		// Internet -> tunnel, for the whole connection, so it also works when
		// the FORWARD policy is DROP (Docker, ufw).
		{"filter", []string{"-A", forwardChain, "-i", m.PublicIF, "-o", m.WGInterface, "-d", rule.DestIP, "-p", protocol, "--dport", destPort, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "--ctorigdstport", publicPort, "-j", "ACCEPT"}},
		// Tunnel -> internet, replies only.
		{"filter", []string{"-A", forwardChain, "-i", m.WGInterface, "-o", m.PublicIF, "-s", rule.DestIP, "-p", protocol, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "--ctorigdstport", publicPort, "-j", "ACCEPT"}},
	}
	if !rule.KeepClientIP {
		commands = append(commands, tableCommand{"nat", []string{"-A", snatChain, "-o", m.WGInterface, "-d", rule.DestIP, "-p", protocol, "--dport", destPort, "-m", "conntrack", "--ctorigdstport", publicPort, "-j", "MASQUERADE"}})
	}
	return commands
}

// LiveRulesCommand is what LiveRules runs, shown to the user alongside the output.
var LiveRulesCommand = []string{"iptables", "-t", "nat", "-L", dnatChain, "-n", "-v", "--line-numbers"}

// LiveRules returns the port forwards as the kernel has them right now, with
// packet and byte counters.
func (m Manager) LiveRules(ctx context.Context) (string, error) {
	if m.Runner == nil {
		return "", errors.New("firewall command runner is not configured")
	}
	output, err := m.Runner.Run(ctx, LiveRulesCommand...)
	if err != nil {
		return "", fmt.Errorf("read live firewall rules (has iptable-ui applied its rules yet?): %w", err)
	}
	return string(output), nil
}

// Disconnect closes tracked connections for a forward so a removed or
// changed rule stops passing traffic at once, not when its clients go idle.
// It returns how many connections were closed.
func (m Manager) Disconnect(ctx context.Context, rule store.Rule) (int, error) {
	if m.Runner == nil {
		return 0, errors.New("firewall command runner is not configured")
	}
	closed := 0
	for _, protocol := range protocols(rule.Protocol) {
		output, err := m.Runner.Run(ctx, "conntrack", "-D", "-p", protocol, "--orig-port-dst", fmt.Sprint(rule.PublicPort), "--reply-src", rule.DestIP)
		if errors.Is(err, exec.ErrNotFound) {
			return closed, ErrNoConntrack
		}
		// conntrack exits non-zero when nothing matched, so trust its summary.
		match := deletedFlows.FindStringSubmatch(string(output))
		if match == nil {
			if err != nil {
				return closed, fmt.Errorf("close open connections: %w", err)
			}
			continue
		}
		count, _ := strconv.Atoi(match[1])
		closed += count
	}
	return closed, nil
}

var deletedFlows = regexp.MustCompile(`(\d+) flow entr(?:y|ies) ha(?:s|ve) been deleted`)

// OtherForwards reports whether a DNAT rule outside iptable-ui's chains
// still forwards the public port, for example one added by another script.
func (m Manager) OtherForwards(ctx context.Context, port uint16, protocol string) (bool, error) {
	if m.Runner == nil {
		return false, errors.New("firewall command runner is not configured")
	}
	output, err := m.Runner.Run(ctx, "iptables-save", "-t", "nat")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "-A" || fields[1] == dnatChain || !strings.Contains(line, "-j DNAT") {
			continue
		}
		var linePort, lineProtocol string
		for index := 2; index+1 < len(fields); index++ {
			switch fields[index] {
			case "--dport", "--destination-port":
				linePort = fields[index+1]
			case "-p", "--protocol":
				lineProtocol = fields[index+1]
			}
		}
		if linePort == fmt.Sprint(port) && (protocol == "both" || lineProtocol == protocol) {
			return true, nil
		}
	}
	return false, nil
}

// maxBackups bounds the snapshot directory; every change writes one.
const maxBackups = 50

// saveBackup stores a snapshot of the firewall taken before a change and
// prunes the oldest snapshots.
func (m Manager) saveBackup(ruleset []byte) error {
	if err := os.MkdirAll(m.BackupDir, 0700); err != nil {
		return fmt.Errorf("create firewall backup directory: %w", err)
	}
	name := "iptables-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".v4"
	if err := os.WriteFile(filepath.Join(m.BackupDir, name), ruleset, 0600); err != nil {
		return fmt.Errorf("save firewall backup: %w", err)
	}
	backups, err := filepath.Glob(filepath.Join(m.BackupDir, "iptables-*.v4"))
	if err != nil || len(backups) <= maxBackups {
		return nil
	}
	sort.Strings(backups) // timestamps sort oldest first
	for _, old := range backups[:len(backups)-maxBackups] {
		_ = os.Remove(old)
	}
	return nil
}

func (m Manager) run(ctx context.Context, args ...string) error {
	_, err := m.Runner.Run(ctx, append([]string{"iptables"}, args...)...)
	return err
}

func protocols(protocol string) []string {
	if protocol == "both" {
		return []string{"tcp", "udp"}
	}
	return []string{protocol}
}

func validInterface(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	for _, char := range name {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '.' || char == '-') {
			return false
		}
	}
	return true
}
