package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/HeresJohnny320/iptable-ui/internal/store"
)

const (
	dnatChain    = "IPTUI_DNAT"
	forwardChain = "IPTUI_FWD"
	snatChain    = "IPTUI_SNAT"
)

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
	Count  int
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
		for count := 0; count < existing.Count; count++ {
			if err := m.run(ctx, "-t", "nat", "-D", "PREROUTING", "-i", m.PublicIF, "-p", existing.Rule.Protocol, "--dport", fmt.Sprint(existing.Rule.PublicPort), "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", existing.Rule.DestIP, existing.Rule.DestPort)); err != nil {
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
	inNAT := false
	for _, line := range strings.Split(ruleset, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			inNAT = line == "*nat"
			continue
		}
		if line == "COMMIT" {
			inNAT = false
			continue
		}
		if !inNAT {
			continue
		}
		existing, ok := parseDNATRule(line, publicInterface)
		if !ok {
			continue
		}
		id := key{port: existing.Rule.PublicPort, protocol: existing.Rule.Protocol}
		previous, exists := found[id]
		if !exists {
			if existing.Legacy {
				existing.Count = 1
			}
			found[id] = candidate{existing: existing}
			continue
		}
		if previous.existing.Rule.DestIP != existing.Rule.DestIP || previous.existing.Rule.DestPort != existing.Rule.DestPort {
			previous.ambiguous = true
			found[id] = previous
			continue
		}
		if existing.Legacy {
			previous.existing.Legacy = true
			previous.existing.Count++
		}
		found[id] = previous
	}
	result := make([]ExistingRule, 0, len(found))
	for _, candidate := range found {
		if !candidate.ambiguous {
			result = append(result, candidate.existing)
		}
	}
	return result
}

func parseDNATRule(line, publicInterface string) (ExistingRule, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "-A" || (fields[1] != "PREROUTING" && fields[1] != dnatChain) {
		return ExistingRule{}, false
	}
	var inputInterface, protocol, destination, target string
	var publicPort uint16
	for index := 2; index < len(fields); index++ {
		field := fields[index]
		if field == "-m" {
			if index+1 >= len(fields) {
				return ExistingRule{}, false
			}
			module := fields[index+1]
			if module != "tcp" && module != "udp" {
				return ExistingRule{}, false
			}
			index++
			continue
		}
		if field != "-i" && field != "--in-interface" && field != "-p" && field != "--protocol" && field != "--dport" && field != "--destination-port" && field != "-j" && field != "--jump" && field != "--to-destination" && field != "--to" {
			return ExistingRule{}, false
		}
		if index+1 >= len(fields) {
			return ExistingRule{}, false
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
				return ExistingRule{}, false
			}
			publicPort = uint16(port)
		case "-j", "--jump":
			target = value
		case "--to-destination", "--to":
			destination = value
		}
	}
	if inputInterface != publicInterface || (protocol != "tcp" && protocol != "udp") || publicPort == 0 || target != "DNAT" {
		return ExistingRule{}, false
	}
	separator := strings.LastIndex(destination, ":")
	if separator < 1 || separator == len(destination)-1 {
		return ExistingRule{}, false
	}
	address, err := netip.ParseAddr(destination[:separator])
	if err != nil || !address.Is4() {
		return ExistingRule{}, false
	}
	destinationPort, err := strconv.ParseUint(destination[separator+1:], 10, 16)
	if err != nil || destinationPort == 0 {
		return ExistingRule{}, false
	}
	return ExistingRule{
		Rule:   store.Rule{PublicPort: publicPort, DestIP: address.String(), DestPort: uint16(destinationPort), Protocol: protocol, Enabled: true},
		Legacy: fields[1] == "PREROUTING",
	}, true
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
		if !rule.Enabled {
			continue
		}
		address, err := netip.ParseAddr(rule.DestIP)
		if err != nil || !address.Is4() || rule.PublicPort == 0 || rule.DestPort == 0 {
			return fmt.Errorf("rule %d has invalid forwarding data", rule.ID)
		}
		if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "both" {
			return fmt.Errorf("rule %d has invalid protocol %q", rule.ID, rule.Protocol)
		}
	}
	if err := m.backup(ctx); err != nil {
		return err
	}
	if err := m.ensureChain(ctx, "nat", dnatChain); err != nil {
		return err
	}
	if err := m.ensureChain(ctx, "", forwardChain); err != nil {
		return err
	}
	if err := m.ensureChain(ctx, "nat", snatChain); err != nil {
		return err
	}
	if err := m.ensureHook(ctx, "nat", "PREROUTING", dnatChain); err != nil {
		return err
	}
	if err := m.ensureHook(ctx, "", "FORWARD", forwardChain); err != nil {
		return err
	}
	if err := m.ensureHook(ctx, "nat", "POSTROUTING", snatChain); err != nil {
		return err
	}
	if err := m.run(ctx, "-t", "nat", "-F", dnatChain); err != nil {
		return err
	}
	if err := m.run(ctx, "-F", forwardChain); err != nil {
		return err
	}
	if err := m.run(ctx, "-t", "nat", "-F", snatChain); err != nil {
		return err
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, protocol := range protocols(rule.Protocol) {
			if err := m.run(ctx, "-t", "nat", "-A", dnatChain, "-i", m.PublicIF, "-p", protocol, "--dport", fmt.Sprint(rule.PublicPort), "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", rule.DestIP, rule.DestPort)); err != nil {
				return err
			}
			if err := m.run(ctx, "-A", forwardChain, "-d", rule.DestIP, "-p", protocol, "--dport", fmt.Sprint(rule.DestPort), "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"); err != nil {
				return err
			}
			if err := m.run(ctx, "-A", forwardChain, "-s", rule.DestIP, "-p", protocol, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "--ctorigdstport", fmt.Sprint(rule.PublicPort), "-j", "ACCEPT"); err != nil {
				return err
			}
			if err := m.run(ctx, "-t", "nat", "-A", snatChain, "-o", m.WGInterface, "-d", rule.DestIP, "-p", protocol, "--dport", fmt.Sprint(rule.DestPort), "-j", "MASQUERADE"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m Manager) backup(ctx context.Context) error {
	output, err := m.Runner.Run(ctx, "iptables-save")
	if err != nil {
		return fmt.Errorf("backup current iptables rules: %w", err)
	}
	if err := os.MkdirAll(m.BackupDir, 0700); err != nil {
		return fmt.Errorf("create firewall backup directory: %w", err)
	}
	name := "iptables-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".v4"
	if err := os.WriteFile(filepath.Join(m.BackupDir, name), output, 0600); err != nil {
		return fmt.Errorf("save firewall backup: %w", err)
	}
	return nil
}

func (m Manager) ensureChain(ctx context.Context, table, chain string) error {
	args := []string{"-S", chain}
	if table != "" {
		args = append([]string{"-t", table}, args...)
	}
	if _, err := m.Runner.Run(ctx, append([]string{"iptables"}, args...)...); err == nil {
		return nil
	}
	args = []string{"-N", chain}
	if table != "" {
		args = append([]string{"-t", table}, args...)
	}
	return m.run(ctx, args...)
}

func (m Manager) ensureHook(ctx context.Context, table, parent, chain string) error {
	check := []string{"-C", parent, "-j", chain}
	if table != "" {
		check = append([]string{"-t", table}, check...)
	}
	if _, err := m.Runner.Run(ctx, append([]string{"iptables"}, check...)...); err == nil {
		return nil
	}
	insert := []string{"-I", parent, "1", "-j", chain}
	if table != "" {
		insert = append([]string{"-t", table}, insert...)
	}
	return m.run(ctx, insert...)
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
