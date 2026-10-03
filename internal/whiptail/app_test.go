package whiptail

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
)

// step is one scripted answer; the title/text it saw is recorded for checks.
type step struct {
	answer string
	ok     bool
}

type scriptedDialog struct {
	t        *testing.T
	steps    []step
	seen     []string
	messages []string
}

func (d *scriptedDialog) next(kind, title, text string) step {
	d.t.Helper()
	d.seen = append(d.seen, kind+": "+title+": "+text)
	if len(d.steps) == 0 {
		d.t.Fatalf("unexpected %s dialog %q: %s", kind, title, text)
	}
	current := d.steps[0]
	d.steps = d.steps[1:]
	return current
}

func (d *scriptedDialog) Menu(title, text string, items []Item, _ string) (string, bool, error) {
	labels := make([]string, len(items))
	for index, item := range items {
		labels[index] = item.Tag + "=" + item.Label
	}
	answer := d.next("menu", title, text+" ["+strings.Join(labels, "; ")+"]")
	return answer.answer, answer.ok, nil
}

// Input returns the pre-filled value for an empty scripted answer, like
// pressing Enter in a real input box.
func (d *scriptedDialog) Input(title, text, initial string) (string, bool, error) {
	answer := d.next("input", title, text)
	if answer.ok && answer.answer == "" {
		return initial, true, nil
	}
	return answer.answer, answer.ok, nil
}

func (d *scriptedDialog) YesNo(title, text string) (bool, error) {
	return d.next("yesno", title, text).ok, nil
}

func (d *scriptedDialog) Message(title, text string) error {
	d.messages = append(d.messages, title+": "+text)
	return nil
}

type noopFirewall struct{}

func (noopFirewall) Reconcile(context.Context, []store.Rule) error { return nil }

type fakeHost struct{ status system.Status }

func (h *fakeHost) Status(context.Context) system.Status { return h.status }
func (h *fakeHost) SetForwarding(_ context.Context, on bool) error {
	h.status.Forwarding = on
	return nil
}
func (h *fakeHost) SetBootRestore(_ context.Context, on bool) error {
	h.status.BootRestore = on
	return nil
}

func newService(t *testing.T) (app.Service, *store.Store) {
	t.Helper()
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return app.Service{Store: database, Firewall: noopFirewall{}}, database
}

func ok(answer string) step { return step{answer: answer, ok: true} }

var cancel = step{}

func TestAddToggleAndRemoveRule(t *testing.T) {
	service, database := newService(t)
	host := &fakeHost{status: system.Status{Forwarding: true, PublicInterface: "ens3", VPNInterface: "wg0", VPNUp: true}}
	dialog := &scriptedDialog{t: t, steps: []step{
		ok("add"), ok("Minecraft"), ok("70000"), ok("25565"), ok("10.66.0.2"), ok(""), ok("both"), ok("real"),
		ok("rules"), ok("1"), ok("toggle"), cancel,
		ok("rules"), ok("1"), ok("remove"), ok(""), // last rule gone: back to the main menu
		ok("quit"),
	}}
	switchToTUI, err := Run(dialog, service, nil, host)
	if err != nil || switchToTUI {
		t.Fatalf("Run returned %v, %v", switchToTUI, err)
	}
	if len(dialog.messages) != 2 || !strings.Contains(dialog.messages[0], "between 1 and 65535") || !strings.Contains(dialog.messages[1], "No saved forwarding rules") {
		t.Fatalf("expected the invalid-port and no-rules messages, got %v", dialog.messages)
	}
	transcript := strings.Join(dialog.seen, "\n")
	for _, expected := range []string{
		"Rule #1 added: ON  :25565 -> 10.66.0.2:25565  BOTH  real IP  Minecraft",
		"Rule #1 disabled",
		"Rule #1 removed",
		"Forwarding ON | Route ens3 -> wg0 (VPN) UP | Apply on boot OFF",
	} {
		if !strings.Contains(transcript, expected) {
			t.Errorf("transcript missing %q:\n%s", expected, transcript)
		}
	}
	if rules, _ := database.List(context.Background()); len(rules) != 0 {
		t.Fatalf("rule should be removed, got %+v", rules)
	}
}

func TestClientIPToggleAsksBeforeTurningOn(t *testing.T) {
	service, database := newService(t)
	if _, err := service.Add(context.Background(), store.Rule{PublicPort: 25565, DestIP: "10.0.0.2", DestPort: 25565, Protocol: "udp"}); err != nil {
		t.Fatal(err)
	}
	dialog := &scriptedDialog{t: t, steps: []step{
		ok("rules"), ok("1"), ok("clientip"), cancel, // declined
		ok("1"), ok("clientip"), ok(""), // confirmed
		cancel, ok("quit"),
	}}
	if _, err := Run(dialog, service, nil, nil); err != nil {
		t.Fatal(err)
	}
	rules, _ := database.List(context.Background())
	if len(rules) != 1 || !rules[0].KeepClientIP {
		t.Fatalf("real client IP should be on after confirming: %+v", rules)
	}
	if !strings.Contains(strings.Join(dialog.seen, "\n"), "Rule #1: real client IP ON") {
		t.Fatalf("result not reported:\n%s", strings.Join(dialog.seen, "\n"))
	}
}

func TestHelpExplainsReapplyAndApplyOnBoot(t *testing.T) {
	service, _ := newService(t)
	dialog := &scriptedDialog{t: t, steps: []step{ok("help"), ok("quit")}}
	if _, err := Run(dialog, service, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(dialog.messages) != 1 || !strings.Contains(dialog.messages[0], "Re-apply rules: rebuilds the firewall") || !strings.Contains(dialog.messages[0], "Apply rules on boot") {
		t.Fatalf("help should explain both options, got %v", dialog.messages)
	}
}

func TestDestinationPortDefaultsToPublicPort(t *testing.T) {
	service, database := newService(t)
	dialog := &scriptedDialog{t: t, steps: []step{ok("add"), ok(""), ok("8080"), ok("10.0.0.2"), ok(""), ok("tcp"), ok("masked"), ok("quit")}}
	if _, err := Run(dialog, service, nil, nil); err != nil {
		t.Fatal(err)
	}
	rules, _ := database.List(context.Background())
	if len(rules) != 1 || rules[0].DestPort != 8080 || rules[0].KeepClientIP || rules[0].Protocol != "tcp" {
		t.Fatalf("unexpected rule %+v", rules)
	}
}

func TestDisablingForwardingAsksFirst(t *testing.T) {
	service, _ := newService(t)
	host := &fakeHost{status: system.Status{Forwarding: true}}
	dialog := &scriptedDialog{t: t, steps: []step{ok("forwarding"), cancel, ok("forwarding"), ok(""), ok("quit")}}
	if _, err := Run(dialog, service, nil, host); err != nil {
		t.Fatal(err)
	}
	if host.status.Forwarding {
		t.Fatal("forwarding should be off after confirming")
	}
	if !strings.Contains(strings.Join(dialog.seen, "\n"), "IPv4 forwarding turned OFF") {
		t.Fatalf("result not reported:\n%s", strings.Join(dialog.seen, "\n"))
	}
}

func TestSwitchToTUIAndCancelQuits(t *testing.T) {
	service, _ := newService(t)
	if switchToTUI, err := Run(&scriptedDialog{t: t, steps: []step{ok("tui")}}, service, nil, nil); err != nil || !switchToTUI {
		t.Fatalf("tui item should switch modes: %v, %v", switchToTUI, err)
	}
	if switchToTUI, err := Run(&scriptedDialog{t: t, steps: []step{cancel}}, service, nil, nil); err != nil || switchToTUI {
		t.Fatalf("Back on the main menu should quit: %v, %v", switchToTUI, err)
	}
}

func TestTextLinesWrapsLongLines(t *testing.T) {
	if got := textLines(strings.Repeat("x", 100)+"\nshort", 54); got != 3 {
		t.Fatalf("got %d lines, want 3 (100 chars at 50 per line, plus one)", got)
	}
}

type fakeWeb struct{}

func (fakeWeb) Toggle() (bool, error) { return true, nil }
func (fakeWeb) Enabled() bool         { return true }
func (fakeWeb) StatusText() string    { return "ON at http://203.0.113.5:8787 (plain HTTP)" }
func (fakeWeb) MaskedStatusText() string {
	return "ON at http://203.•••.•••.•••:8787 (plain HTTP)"
}
func (fakeWeb) Token() string     { return "3f9a00112233" }
func (fakeWeb) SignInURL() string { return "http://203.0.113.5:8787/#token=3f9a00112233" }

func TestWebAddressIsMaskedButCanBeShown(t *testing.T) {
	service, _ := newService(t)
	dialog := &scriptedDialog{t: t, steps: []step{ok("link"), ok("quit")}}
	if _, err := Run(dialog, service, fakeWeb{}, nil); err != nil {
		t.Fatal(err)
	}
	status := dialog.seen[0]
	if strings.Contains(status, "203.0.113.5") || strings.Contains(status, "3f9a00112233") || !strings.Contains(status, "203.•••.•••.•••") || !strings.Contains(status, "3f9a••••••••") {
		t.Fatalf("the main menu should mask the IP and token: %s", status)
	}
	if len(dialog.messages) != 1 || !strings.Contains(dialog.messages[0], "http://203.0.113.5:8787/#token=3f9a00112233") {
		t.Fatalf("the sign-in link item should show the full link: %v", dialog.messages)
	}
}
