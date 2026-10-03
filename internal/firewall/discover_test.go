package firewall

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/store"
)

func TestParseExistingRulesImportsOnlySupportedUnambiguousDNAT(t *testing.T) {
	ruleset := `*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -i ens3 -p tcp -m tcp --dport 25565 -j DNAT --to-destination 192.168.0.10:25565
-A PREROUTING -i ens3 -p udp -m udp --dport 25565 -j DNAT --to-destination 192.168.0.10:25565
-A PREROUTING -i ens3 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 192.168.0.20:80
-A PREROUTING -i ens3 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 192.168.0.21:80
-A PREROUTING -i ens4 -p tcp -m tcp --dport 9000 -j DNAT --to-destination 192.168.0.30:90
-A PREROUTING -i ens3 -p tcp -m tcp --dport 7000 -j DNAT --to-destination 192.168.0.31:70-71
-A IPTUI_DNAT -i ens3 -p tcp -m tcp --dport 8443 -j DNAT --to-destination 192.168.0.40:443
COMMIT
*filter
-A PREROUTING -i ens3 -p tcp -m tcp --dport 5000 -j DNAT --to-destination 192.168.0.50:5000
COMMIT
`
	got := ParseExistingRules(ruleset, "ens3")
	if len(got) != 3 {
		t.Fatalf("expected 3 supported rules, got %d: %+v", len(got), got)
	}
	for _, existing := range got {
		if existing.Rule.PublicPort == 25565 && existing.Count != 1 {
			t.Fatalf("unexpected duplicate count: %+v", existing)
		}
	}
	var tcp, udp, managed bool
	for _, existing := range got {
		switch {
		case existing.Rule.PublicPort == 25565 && existing.Rule.Protocol == "tcp":
			tcp = existing.Legacy && existing.Rule.DestIP == "192.168.0.10"
		case existing.Rule.PublicPort == 25565 && existing.Rule.Protocol == "udp":
			udp = existing.Legacy && existing.Rule.DestPort == 25565
		case existing.Rule.PublicPort == 8443 && existing.Rule.Protocol == "tcp":
			managed = !existing.Legacy && existing.Rule.DestPort == 443
		}
	}
	if !tcp || !udp || !managed {
		t.Fatalf("missing or misclassified supported rules: %+v", got)
	}
}

func TestRemoveLegacyUsesExactDiscoveredRule(t *testing.T) {
	runner := &matchingRunner{}
	manager := Manager{Runner: runner, PublicIF: "ens3"}
	err := manager.RemoveLegacy(context.Background(), []ExistingRule{
		{Rule: testRule(25565, "192.168.0.10", 25565, "tcp"), Legacy: true, Count: 1},
		{Rule: testRule(8443, "192.168.0.40", 443, "tcp"), Legacy: false, Count: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(runner.commands, "\n")
	if !strings.Contains(commands, "-D PREROUTING -i ens3 -p tcp --dport 25565 -j DNAT --to-destination 192.168.0.10:25565") || !strings.Contains(commands, "-D FORWARD -d 192.168.0.10 -p tcp --dport 25565 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT") || strings.Contains(commands, "8443") {
		t.Fatalf("unexpected cleanup commands: %s", commands)
	}
}

// friendRuleset is what the "Universal iptables proxy manager" script leaves
// behind: DNAT without an interface plus per-forward MASQUERADE and FORWARD
// helpers on the VPN interface.
const friendRuleset = `*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -j IPTUI_DNAT
-A PREROUTING -p tcp -m tcp --dport 25565 -j DNAT --to-destination 100.64.0.5:25565
-A PREROUTING -p udp -m udp --dport 25565 -j DNAT --to-destination 100.64.0.5:25565
-A PREROUTING -p tcp -m tcp --dport 2222 -j DNAT --to-destination 100.64.0.9:22
-A PREROUTING -i ens4 -p tcp -m tcp --dport 2223 -j DNAT --to-destination 100.64.0.9:22
-A PREROUTING -p tcp -m tcp --dport 8080 -j DNAT --to-destination 127.0.0.1:80
-A POSTROUTING -d 100.64.0.5/32 -o tailscale0 -p tcp -m tcp --dport 25565 -j MASQUERADE
-A POSTROUTING -d 100.64.0.5/32 -o tailscale0 -p udp -m udp --dport 25565 -j MASQUERADE
-A POSTROUTING -d 100.64.0.9/32 -o tailscale0 -p tcp -m tcp --dport 22 -j MASQUERADE
-A POSTROUTING -s 100.64.0.0/10 -o ens3 -j MASQUERADE
COMMIT
*filter
-A FORWARD -d 100.64.0.5/32 -o tailscale0 -p tcp -m tcp --dport 25565 -j ACCEPT
-A FORWARD -d 100.64.0.5/32 -o tailscale0 -p udp -m udp --dport 25565 -j ACCEPT
-A FORWARD -d 100.64.0.5/32 -o tailscale0 -p tcp -m tcp --dport 25565 -m comment --comment "keep me" -j ACCEPT
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
COMMIT
`

func TestParseExistingRulesAdoptsRulesWithoutInterface(t *testing.T) {
	got := ParseExistingRules(friendRuleset, "ens3")
	byPort := make(map[string]ExistingRule)
	for _, existing := range got {
		byPort[fmt.Sprintf("%d/%s", existing.Rule.PublicPort, existing.Rule.Protocol)] = existing
	}
	tcp, udp := byPort["25565/tcp"], byPort["25565/udp"]
	if !tcp.Legacy || tcp.AnyCount != 1 || tcp.Count != 0 || tcp.Rule.DestIP != "100.64.0.5" {
		t.Fatalf("interface-less TCP forward not adopted: %+v", tcp)
	}
	if len(tcp.Helpers) != 2 || len(udp.Helpers) != 2 {
		t.Fatalf("each forward should own its MASQUERADE and FORWARD helpers: tcp=%v udp=%v", tcp.Helpers, udp.Helpers)
	}
	for _, helper := range append(tcp.Helpers, udp.Helpers...) {
		if strings.Contains(strings.Join(helper, " "), "comment") {
			t.Fatalf("a helper with extra matches must be left alone: %v", helper)
		}
	}
	if ssh, ok := byPort["2222/tcp"]; !ok || len(ssh.Helpers) != 0 {
		t.Fatalf("port 2222 shares 100.64.0.9:22 with an ens4 rule that stays, so its helpers must stay: %+v", ssh)
	}
	if _, ok := byPort["2223/tcp"]; ok {
		t.Fatal("a rule bound to a different interface must not be adopted")
	}
	if _, ok := byPort["8080/tcp"]; ok {
		t.Fatal("a local redirect to loopback must not be adopted")
	}
}

func TestRemoveLegacyDeletesInterfaceLessRuleAndHelpers(t *testing.T) {
	runner := &matchingRunner{}
	manager := Manager{Runner: runner, PublicIF: "ens3"}
	if err := manager.RemoveLegacy(context.Background(), ParseExistingRules(friendRuleset, "ens3")); err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(runner.commands, "\n")
	for _, expected := range []string{
		"iptables -t nat -D PREROUTING -p tcp --dport 25565 -j DNAT --to-destination 100.64.0.5:25565",
		"iptables -t nat -D PREROUTING -p udp --dport 25565 -j DNAT --to-destination 100.64.0.5:25565",
		"iptables -t nat -D POSTROUTING -d 100.64.0.5/32 -o tailscale0 -p tcp -m tcp --dport 25565 -j MASQUERADE",
		"iptables -t filter -D FORWARD -d 100.64.0.5/32 -o tailscale0 -p udp -m udp --dport 25565 -j ACCEPT",
		"iptables -t nat -D PREROUTING -p tcp --dport 2222 -j DNAT --to-destination 100.64.0.9:22",
	} {
		if !strings.Contains(commands, expected) {
			t.Errorf("missing cleanup command %q in:\n%s", expected, commands)
		}
	}
	for _, unexpected := range []string{"-i ens3", "dport 22 -j MASQUERADE", "keep me", "RELATED,ESTABLISHED", "-s 100.64.0.0/10"} {
		if strings.Contains(commands, unexpected) {
			t.Errorf("cleanup touched %q:\n%s", unexpected, commands)
		}
	}
}

type matchingRunner struct {
	commands []string
}

func (r *matchingRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.commands = append(r.commands, strings.Join(args, " "))
	return nil, nil
}

func testRule(publicPort uint16, destIP string, destPort uint16, protocol string) store.Rule {
	return store.Rule{PublicPort: publicPort, DestIP: destIP, DestPort: destPort, Protocol: protocol, Enabled: true}
}
