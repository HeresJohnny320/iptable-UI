package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/store"
)

type fakeRunner struct {
	commands []string
	// save is what iptables-save prints; payload is the last restore input.
	save    string
	payload string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	f.commands = append(f.commands, strings.Join(args, " "))
	return []byte(f.save), nil
}

func (f *fakeRunner) RunInput(_ context.Context, input string, args ...string) ([]byte, error) {
	f.commands = append(f.commands, strings.Join(args, " "))
	f.payload = input
	return nil, nil
}

func TestReconcileAppliesEverythingInOneRestore(t *testing.T) {
	runner := &fakeRunner{}
	manager := Manager{Runner: runner, PublicIF: "eth0", WGInterface: "wg0", BackupDir: t.TempDir()}
	err := manager.Reconcile(context.Background(), []store.Rule{
		{ID: 1, PublicPort: 51820, DestIP: "10.0.0.4", DestPort: 51820, Protocol: "both", Enabled: true},
		{ID: 2, PublicPort: 9000, DestIP: "10.0.0.5", DestPort: 9000, Protocol: "tcp", Enabled: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(runner.commands, "\n"); got != "iptables-save\niptables-restore --noflush" {
		t.Fatalf("expected one save and one restore, got:\n%s", got)
	}
	for _, expected := range []string{
		"*nat\n:IPTUI_DNAT - [0:0]\n:IPTUI_SNAT - [0:0]\n-I PREROUTING 1 -j IPTUI_DNAT\n-I POSTROUTING 1 -j IPTUI_SNAT\n",
		"-A IPTUI_DNAT -i eth0 -p udp --dport 51820 -j DNAT --to-destination 10.0.0.4:51820\n",
		"*filter\n:IPTUI_FWD - [0:0]\n-I FORWARD 1 -j IPTUI_FWD\n",
		"-A IPTUI_FWD -i eth0 -o wg0 -d 10.0.0.4 -p tcp --dport 51820 -m conntrack --ctstate NEW,ESTABLISHED,RELATED --ctorigdstport 51820 -j ACCEPT\n",
		"-A IPTUI_FWD -i wg0 -o eth0 -s 10.0.0.4 -p tcp -m conntrack --ctstate ESTABLISHED,RELATED --ctorigdstport 51820 -j ACCEPT\n",
		"-A IPTUI_SNAT -o wg0 -d 10.0.0.4 -p udp --dport 51820 -m conntrack --ctorigdstport 51820 -j MASQUERADE\n",
		"*mangle\n:IPTUI_MSS - [0:0]\n-I FORWARD 1 -j IPTUI_MSS\n-A IPTUI_MSS -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\nCOMMIT\n",
		// A disabled rule cuts connections that were already open.
		"-A IPTUI_FWD -p tcp -m conntrack --ctstate DNAT --ctorigdstport 9000 --ctreplsrc 10.0.0.5 -j DROP\n",
	} {
		if !strings.Contains(runner.payload, expected) {
			t.Errorf("payload missing %q:\n%s", expected, runner.payload)
		}
	}
	if strings.Contains(runner.payload, "--dport 9000 -j DNAT") {
		t.Fatalf("a disabled rule must not be forwarded:\n%s", runner.payload)
	}
	if strings.Count(runner.payload, "COMMIT") != 3 {
		t.Fatalf("each table must be committed once:\n%s", runner.payload)
	}
}

func TestReconcileDoesNotDuplicateExistingHooks(t *testing.T) {
	runner := &fakeRunner{save: "*nat\n-A PREROUTING -j IPTUI_DNAT\n-A POSTROUTING -j IPTUI_SNAT\nCOMMIT\n*filter\n-A FORWARD -j IPTUI_FWD\nCOMMIT\n*mangle\n-A FORWARD -j IPTUI_MSS\nCOMMIT\n"}
	manager := Manager{Runner: runner, PublicIF: "eth0", WGInterface: "wg0", BackupDir: t.TempDir()}
	if err := manager.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(runner.payload, "-I ") {
		t.Fatalf("hooks already exist and must not be inserted again:\n%s", runner.payload)
	}
}

func TestBackupsArePruned(t *testing.T) {
	directory := t.TempDir()
	for index := 0; index < maxBackups+5; index++ {
		name := filepath.Join(directory, fmt.Sprintf("iptables-20260101T0000%02d.000000000Z.v4", index))
		if err := os.WriteFile(name, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	manager := Manager{Runner: &fakeRunner{}, PublicIF: "eth0", WGInterface: "wg0", BackupDir: directory}
	if err := manager.Reconcile(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	backups, _ := filepath.Glob(filepath.Join(directory, "iptables-*.v4"))
	if len(backups) != maxBackups {
		t.Fatalf("kept %d backups, want %d", len(backups), maxBackups)
	}
	if _, err := os.Stat(filepath.Join(directory, "iptables-20260101T000000.000000000Z.v4")); !os.IsNotExist(err) {
		t.Fatal("the oldest backup should be removed first")
	}
}

func TestKeepClientIPSkipsMasquerade(t *testing.T) {
	runner := &fakeRunner{}
	manager := Manager{Runner: runner, PublicIF: "eth0", WGInterface: "wg0", BackupDir: t.TempDir()}
	err := manager.Reconcile(context.Background(), []store.Rule{
		{ID: 1, PublicPort: 25565, DestIP: "10.0.0.4", DestPort: 25565, Protocol: "tcp", Enabled: true, KeepClientIP: true},
		{ID: 2, PublicPort: 8080, DestIP: "10.0.0.4", DestPort: 80, Protocol: "tcp", Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(runner.payload, "--ctorigdstport 25565 -j MASQUERADE") || !strings.Contains(runner.payload, "--ctorigdstport 8080 -j MASQUERADE") {
		t.Fatalf("only the masked rule should be masqueraded:\n%s", runner.payload)
	}
	if !strings.Contains(runner.payload, "--dport 25565 -j DNAT --to-destination 10.0.0.4:25565") {
		t.Fatalf("a real-client-IP rule still needs its DNAT:\n%s", runner.payload)
	}
}

type scriptedRunner struct {
	output string
	err    error
	calls  []string
}

func (r *scriptedRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	return []byte(r.output), r.err
}

func TestDisconnectCountsClosedConnections(t *testing.T) {
	runner := &scriptedRunner{output: "conntrack v1.4.7 (conntrack-tools): 3 flow entries have been deleted.\n"}
	closed, err := Manager{Runner: runner}.Disconnect(context.Background(), store.Rule{PublicPort: 25565, DestIP: "10.0.0.4", Protocol: "both"})
	if err != nil || closed != 6 {
		t.Fatalf("closed %d, err %v; want 3 per protocol", closed, err)
	}
	if runner.calls[0] != "conntrack -D -p tcp --orig-port-dst 25565 --reply-src 10.0.0.4" {
		t.Fatalf("unexpected command %q", runner.calls[0])
	}
	none := &scriptedRunner{output: "conntrack v1.4.7 (conntrack-tools): 0 flow entries have been deleted.\n", err: errors.New("exit status 1")}
	if closed, err := (Manager{Runner: none}).Disconnect(context.Background(), store.Rule{PublicPort: 80, DestIP: "10.0.0.4", Protocol: "tcp"}); err != nil || closed != 0 {
		t.Fatalf("no matches is not an error: closed=%d err=%v", closed, err)
	}
	missing := &scriptedRunner{err: fmt.Errorf("conntrack: %w", exec.ErrNotFound)}
	if _, err := (Manager{Runner: missing}).Disconnect(context.Background(), store.Rule{PublicPort: 80, DestIP: "10.0.0.4", Protocol: "tcp"}); !errors.Is(err, ErrNoConntrack) {
		t.Fatalf("missing tool should report ErrNoConntrack, got %v", err)
	}
}

func TestOtherForwardsFindsRulesOutsideManagedChain(t *testing.T) {
	runner := &scriptedRunner{output: "*nat\n-A PREROUTING -j IPTUI_DNAT\n-A IPTUI_DNAT -i eth0 -p tcp -m tcp --dport 8080 -j DNAT --to-destination 10.0.0.4:80\n-A PREROUTING -p udp -m udp --dport 25565 -j DNAT --to-destination 10.0.0.9:25565\nCOMMIT\n"}
	manager := Manager{Runner: runner}
	for _, test := range []struct {
		port     uint16
		protocol string
		want     bool
	}{{8080, "tcp", false}, {25565, "udp", true}, {25565, "tcp", false}, {25565, "both", true}} {
		if got, err := manager.OtherForwards(context.Background(), test.port, test.protocol); err != nil || got != test.want {
			t.Errorf("port %d/%s: got %v (%v), want %v", test.port, test.protocol, got, err, test.want)
		}
	}
}
