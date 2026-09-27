package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/store"
)

type fakeRunner struct {
	commands []string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	f.commands = append(f.commands, strings.Join(args, " "))
	if len(args) > 1 && args[0] == "iptables" {
		for _, argument := range args[1:] {
			if argument == "-S" || argument == "-C" {
				return nil, errors.New("chain or hook does not exist yet")
			}
		}
	}
	return nil, nil
}

func TestReconcileBuildsOnlyEnabledRules(t *testing.T) {
	runner := &fakeRunner{}
	manager := Manager{Runner: runner, PublicIF: "eth0", WGInterface: "wg0", BackupDir: t.TempDir()}
	err := manager.Reconcile(context.Background(), []store.Rule{
		{ID: 1, PublicPort: 51820, DestIP: "10.0.0.4", DestPort: 51820, Protocol: "both", Enabled: true},
		{ID: 2, PublicPort: 9000, DestIP: "10.0.0.5", DestPort: 9000, Protocol: "tcp", Enabled: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	commands := strings.Join(runner.commands, "\n")
	if !strings.Contains(commands, "--dport 51820") || strings.Contains(commands, "--dport 9000") {
		t.Fatalf("unexpected managed rule commands:\n%s", commands)
	}
	if !strings.Contains(commands, "IPTUI_DNAT") || !strings.Contains(commands, "IPTUI_FWD") || !strings.Contains(commands, "IPTUI_SNAT") {
		t.Fatalf("managed chains were not initialized:\n%s", commands)
	}
	if strings.Contains(commands, "iptables -t -t") || !strings.Contains(commands, "iptables -t nat -N IPTUI_DNAT") {
		t.Fatalf("invalid NAT command generated:\n%s", commands)
	}
	if !strings.Contains(commands, "iptables -t nat -I PREROUTING 1 -j IPTUI_DNAT") || !strings.Contains(commands, "iptables -I FORWARD 1 -j IPTUI_FWD") {
		t.Fatalf("first-run hooks were not installed:\n%s", commands)
	}
	if !strings.Contains(commands, "--ctorigdstport 51820") || !strings.Contains(commands, "-o wg0 -d 10.0.0.4") {
		t.Fatalf("return path is not restricted to the managed forward:\n%s", commands)
	}
}
