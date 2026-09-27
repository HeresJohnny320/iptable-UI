package firewall

import (
	"context"
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
