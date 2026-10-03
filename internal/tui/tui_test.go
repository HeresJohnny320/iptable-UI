package tui

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/backup"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
	"github.com/HeresJohnny320/iptable-ui/internal/traffic"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

type testWebControl struct {
	enabled bool
	port    int
}

func (w *testWebControl) Toggle() (bool, error) {
	w.enabled = !w.enabled
	return w.enabled, nil
}

func (w *testWebControl) Enabled() bool { return w.enabled }
func (w *testWebControl) Port() int {
	if w.port == 0 {
		return 8787
	}
	return w.port
}
func (w *testWebControl) SetPort(port int) (string, error) {
	w.port = port
	return fmt.Sprintf("http://203.0.113.5:%d", port), nil
}
func (w *testWebControl) URL() string       { return "http://127.0.0.1:8787/" }
func (w *testWebControl) SignInURL() string { return w.URL() + "#token=" + w.Token() }
func (w *testWebControl) DownloadLink(name string) (string, error) {
	return "http://203.0.113.5:8787/download/secret-" + name, nil
}
func (w *testWebControl) Address() string { return "127.0.0.1:8787" }
func (w *testWebControl) Token() string   { return "temporary-token" }
func (w *testWebControl) StatusText() string {
	if w.enabled {
		return "ON at http://" + w.Address()
	}
	return "OFF; press W to start"
}

func TestWebToggleKeyAndTokenDisplay(t *testing.T) {
	webControl := &testWebControl{}
	current := model{webControl: webControl}
	updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'w'}})
	if !webControl.Enabled() {
		t.Fatal("w key did not enable the web UI")
	}
	view := updated.(model).View()
	if !contains(view, "temp••••••••") || contains(view, "temporary-token") || !contains(view, "ON at http://127.0.0.1:8787") {
		t.Fatalf("TUI should show the web state with the token masked: %s", view)
	}
	revealed, _ := updated.(model).updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	if view := revealed.(model).View(); !contains(view, "temporary-token") || !contains(view, "V hide") {
		t.Fatalf("V should reveal the token: %s", view)
	}
	hidden, _ := revealed.(model).updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	if contains(hidden.(model).View(), "temporary-token") {
		t.Fatal("V again should hide the token")
	}
}

// publicWebControl serves the web UI on a public IP, which must be masked.
type publicWebControl struct{ testWebControl }

func (w *publicWebControl) URL() string { return "http://203.0.113.5:8787/" }
func (w *publicWebControl) StatusText() string {
	return "ON at http://203.0.113.5:8787 (plain HTTP)"
}
func (w *publicWebControl) SignInURL() string { return w.URL() + "#token=" + w.Token() }

func TestPublicAddressIsMaskedUntilRevealed(t *testing.T) {
	current := model{width: 100, webControl: &publicWebControl{testWebControl{enabled: true}}}
	if view := current.View(); !contains(view, "ON at http://203.•••.•••.•••:8787 (plain HTTP)") || contains(view, "203.0.113.5") {
		t.Fatalf("the public IP should be masked:\n%s", view)
	}
	current.reveal = true
	if view := current.View(); !contains(view, "ON at http://203.0.113.5:8787") {
		t.Fatalf("V should show the real IP:\n%s", view)
	}
}

func TestCopySignInLink(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = write
	t.Setenv("TMUX", "")
	current, _ := press(t, model{webControl: &testWebControl{enabled: true}}, "c")
	os.Stderr = stderr
	write.Close()
	sequence, _ := io.ReadAll(read)
	encoded := base64.StdEncoding.EncodeToString([]byte("http://127.0.0.1:8787/#token=temporary-token"))
	if !strings.Contains(string(sequence), "\x1b]52;c;"+encoded) || !strings.Contains(current.message, "copied to your clipboard") {
		t.Fatalf("C should send the sign-in link over OSC 52: %q, %q", sequence, current.message)
	}
}

func TestParseWireGuardSetup(t *testing.T) {
	request, err := parseSetup([]string{"wg0", "10.66.0.1/24", "10.66.0.2", "192.168.1.0/24", "peer-public-key", "vpn.example.net:51820", "51820"})
	if err != nil {
		t.Fatal(err)
	}
	if request.InterfaceName != "wg0" || request.ListenPort != 51820 || request.PeerPublicKey != "peer-public-key" {
		t.Fatalf("unexpected setup request: %+v", request)
	}
}

func TestEditKeyPrefillsSelectedRule(t *testing.T) {
	current := model{rules: []store.Rule{{ID: 12, Name: "old label", PublicPort: 25565, DestIP: "10.0.0.8", DestPort: 25565, Protocol: "tcp"}}}
	updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	model := updated.(model)
	if model.activeScreen != addScreen || model.editingID != 12 || model.fields[0] != "old label" || model.fields[2] != "10.0.0.8" {
		t.Fatalf("edit screen did not load selected rule: %+v", model)
	}
	if !strings.Contains(model.View(), "EDIT PORT FORWARD #12") {
		t.Fatalf("edit view title missing: %s", model.View())
	}
}

func TestRuleMenuHighlightsForwardDetails(t *testing.T) {
	current := model{width: 80, rules: []store.Rule{{ID: 5, Name: "Game server", PublicPort: 25565, DestIP: "192.168.1.20", DestPort: 25566, Protocol: "both", Enabled: true}}}
	view := current.View()
	for _, expected := range []string{"PORT FORWARD MANAGER", "RULES MENU", "ENABLED", "Game server", "PUBLIC", ":25565", "192.168.1.20", "25566", "PROTOCOL BOTH", "UP/DOWN", "actions", "more"} {
		if !strings.Contains(view, expected) {
			t.Errorf("TUI view missing %q:\n%s", expected, view)
		}
	}
}

func TestRuleMenuFitsTypicalTerminalWidths(t *testing.T) {
	for _, width := range []int{48, 80, 120} {
		views := []model{
			{width: width, webControl: &testWebControl{enabled: true}, system: &testSystem{}, systemStatus: &system.Status{VPNInterface: "tailscale0"}, rules: []store.Rule{{ID: 5, Name: "Game server", PublicPort: 25565, DestIP: "192.168.1.20", DestPort: 25566, Protocol: "both", Enabled: true}}},
			{width: width, activeScreen: addScreen, fields: []string{"Game server", "25565", "192.168.1.20", "25566", "both", "masked"}, focus: 2},
			{width: width, activeScreen: wireGuardScreen, fields: []string{"wg0", "10.66.0.1/24", "10.66.0.2", "192.168.1.0/24", "peer-public-key-placeholder", "vpn.example.net:51820", "51820"}, focus: 1},
		}
		for viewIndex, current := range views {
			for lineNumber, line := range strings.Split(current.View(), "\n") {
				if actual := lipgloss.Width(line); actual > width {
					t.Errorf("terminal width %d, view %d: line %d is %d columns wide:\n%s", width, viewIndex, lineNumber+1, actual, line)
				}
			}
		}
	}
}

func TestProtocolPickerCyclesWithArrowKeys(t *testing.T) {
	current := model{activeScreen: addScreen, fields: []string{"label", "25565", "192.168.1.20", "25565", "both", "masked"}, focus: 4}
	updated, _ := current.updateAdd(tea.KeyMsg{Type: tea.KeyRight})
	if got := updated.(model).fields[4]; got != "tcp" {
		t.Fatalf("right arrow selected %q, want tcp", got)
	}
	updated, _ = updated.(model).updateAdd(tea.KeyMsg{Type: tea.KeyLeft})
	if got := updated.(model).fields[4]; got != "both" {
		t.Fatalf("left arrow selected %q, want both", got)
	}
}

func TestArrowNavigationMovesOneRuleAndClampsAtEnds(t *testing.T) {
	current := model{rules: make([]store.Rule, 3)}
	updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyDown})
	if got := updated.(model).cursor; got != 1 {
		t.Fatalf("down arrow moved cursor to %d, want 1", got)
	}
	updated, _ = updated.(model).updateList(tea.KeyMsg{Type: tea.KeyDown})
	updated, _ = updated.(model).updateList(tea.KeyMsg{Type: tea.KeyDown})
	if got := updated.(model).cursor; got != 2 {
		t.Fatalf("cursor should stop at last row, got %d", got)
	}
	updated, _ = updated.(model).updateList(tea.KeyMsg{Type: tea.KeyUp})
	if got := updated.(model).cursor; got != 1 {
		t.Fatalf("up arrow moved cursor to %d, want 1", got)
	}
}

func TestSelectedRuleStaysInVisibleWindow(t *testing.T) {
	rules := make([]store.Rule, 30)
	for index := range rules {
		rules[index] = store.Rule{ID: int64(index + 1), Name: "rule", PublicPort: uint16(2000 + index), DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp", Enabled: true}
	}
	current := model{rules: rules, width: 80, height: 30}
	for range 10 {
		updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyDown})
		current = updated.(model)
	}
	if current.cursor != 10 {
		t.Fatalf("cursor ended at %d, want 10", current.cursor)
	}
	start, end := current.visibleRuleRange()
	if current.cursor != end-1 || start == 0 {
		t.Fatalf("scrolling down should keep the selection on the last visible row: cursor=%d range=[%d,%d)", current.cursor, start, end)
	}
	view := current.View()
	if !strings.Contains(view, fmt.Sprintf("Showing %d-%d of 30 rules", start+1, end)) || !strings.Contains(view, "#11") {
		t.Fatalf("viewport does not follow selected rule: %s", view)
	}
	for range 10 {
		updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyUp})
		current = updated.(model)
	}
	if start, _ := current.visibleRuleRange(); start != 0 || !strings.Contains(current.View(), "#1 ") {
		t.Fatalf("scrolling back up should return to the top, range starts at %d", start)
	}
}

func TestResizeKeepsSelectedRuleVisible(t *testing.T) {
	rules := make([]store.Rule, 20)
	current := model{rules: rules, cursor: 12, width: 80, height: 24, listOffset: 10}
	updated, _ := current.Update(tea.WindowSizeMsg{Width: 80, Height: 50})
	current = updated.(model)
	start, end := current.visibleRuleRange()
	if current.cursor < start || current.cursor >= end {
		t.Fatalf("resize hid selected row %d in range [%d,%d)", current.cursor, start, end)
	}
}

func TestExternalRuleUpdatesAppearWithoutChangingSelectedRule(t *testing.T) {
	current := model{
		width:      90,
		rules:      []store.Rule{{ID: 1, Name: "first", PublicPort: 1001}, {ID: 2, Name: "selected", PublicPort: 1002}},
		cursor:     1,
		selectedID: 2,
	}
	updated, _ := current.Update(rulesLoaded{rules: []store.Rule{
		{ID: 2, Name: "changed in web", PublicPort: 2002, DestIP: "10.0.0.22", DestPort: 22, Protocol: "tcp", Enabled: true},
		{ID: 1, Name: "first", PublicPort: 1001},
	}})
	model := updated.(model)
	if model.cursor != 0 || model.selectedID != 2 {
		t.Fatalf("selection moved to a different rule after refresh: cursor=%d selectedID=%d", model.cursor, model.selectedID)
	}
	view := model.View()
	if !strings.Contains(view, "changed in web") || !strings.Contains(view, "10.0.0.22") || !strings.Contains(view, ":2002") {
		t.Fatalf("updated rule fields did not appear in the TUI:\n%s", view)
	}
}

func TestRefreshKeepsSelectionInViewAfterSelectedRuleIsDeleted(t *testing.T) {
	current := model{rules: []store.Rule{{ID: 1}, {ID: 2}, {ID: 3}}, cursor: 1, selectedID: 2, width: 80, height: 24}
	updated, _ := current.Update(rulesLoaded{rules: []store.Rule{{ID: 1}, {ID: 3}}})
	model := updated.(model)
	if model.cursor != 1 || model.selectedID != 3 {
		t.Fatalf("deleted selection did not clamp to the nearest remaining rule: cursor=%d selectedID=%d", model.cursor, model.selectedID)
	}
	start, end := model.visibleRuleRange()
	if model.cursor < start || model.cursor >= end {
		t.Fatalf("fallback selection is not visible: cursor=%d range=[%d,%d)", model.cursor, start, end)
	}
}

type testSystem struct {
	status system.Status
}

func (s *testSystem) Status(context.Context) system.Status { return s.status }

func (s *testSystem) SetForwarding(_ context.Context, enabled bool) error {
	s.status.Forwarding = enabled
	return nil
}

func (s *testSystem) SetBootRestore(_ context.Context, enabled bool) error {
	s.status.BootRestore = enabled
	return nil
}

type testRuleStore struct {
	rules   []store.Rule
	deleted []int64
}

func (s *testRuleStore) List(context.Context) ([]store.Rule, error) { return s.rules, nil }
func (s *testRuleStore) Add(_ context.Context, rule store.Rule) (store.Rule, error) {
	return rule, nil
}
func (s *testRuleStore) Update(_ context.Context, rule store.Rule) (store.Rule, error) {
	return rule, nil
}
func (s *testRuleStore) SetEnabled(context.Context, int64, bool) error { return nil }
func (s *testRuleStore) DeleteAll(context.Context) ([]store.Rule, error) {
	removed := s.rules
	s.rules = nil
	return removed, nil
}
func (s *testRuleStore) Delete(_ context.Context, id int64) error {
	s.deleted = append(s.deleted, id)
	return nil
}

type testRuleFirewall struct{}

func (testRuleFirewall) Reconcile(context.Context, []store.Rule) error { return nil }

func press(t *testing.T, current model, key string) (model, tea.Cmd) {
	t.Helper()
	updated, command := current.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
	return updated.(model), command
}

// run executes a command, feeds its message back into the model, then applies
// the host status refresh that the TUI schedules after every action.
func run(t *testing.T, current model, command tea.Cmd) model {
	t.Helper()
	if command == nil {
		t.Fatal("expected a command")
	}
	updated, _ := current.Update(command())
	current = updated.(model)
	if current.system != nil {
		updated, _ = current.Update(current.loadSystem())
		current = updated.(model)
	}
	return current
}

func TestHostStatusShownInHeader(t *testing.T) {
	current := model{width: 90, system: &testSystem{status: system.Status{PublicInterface: "ens3", VPNInterface: "wg0"}}}
	current = run(t, current, current.loadSystem)
	view := current.View()
	for _, expected := range []string{"FORWARDING", "OFF (forwards blocked)", "ROUTE", "ens3 -> wg0 DOWN", "APPLY ON BOOT", "OFF (rules lost on reboot)", "more", "help"} {
		if !strings.Contains(view, expected) {
			t.Errorf("view missing %q:\n%s", expected, view)
		}
	}
	if strings.Contains((model{width: 90}).View(), "APPLY ON BOOT") {
		t.Fatal("host rows should be hidden when no system control is configured")
	}
}

func TestForwardingToggleConfirmsBeforeDisabling(t *testing.T) {
	host := &testSystem{}
	current := model{system: host, systemStatus: &system.Status{}}

	current, command := press(t, current, "f")
	current = run(t, current, command)
	if !host.status.Forwarding || !current.systemStatus.Forwarding {
		t.Fatalf("f should enable forwarding without a prompt: host=%v model=%v", host.status.Forwarding, current.systemStatus.Forwarding)
	}

	current, command = press(t, current, "f")
	if command != nil || current.confirm == nil || !strings.Contains(current.message, "Disable IPv4 forwarding?") {
		t.Fatalf("disabling forwarding should ask first: %q", current.message)
	}
	current, command = press(t, current, "n")
	if command != nil || current.confirm != nil || !host.status.Forwarding {
		t.Fatal("any key other than y should cancel the prompt")
	}

	current, _ = press(t, current, "f")
	current, command = press(t, current, "y")
	current = run(t, current, command)
	if host.status.Forwarding || current.systemStatus.Forwarding {
		t.Fatal("y should disable forwarding")
	}
}

func TestBootRestoreToggle(t *testing.T) {
	host := &testSystem{}
	current := model{system: host, systemStatus: &system.Status{}}
	current, command := press(t, current, "b")
	current = run(t, current, command)
	if !host.status.BootRestore || !strings.Contains(current.message, "Apply on boot is ON") {
		t.Fatalf("b should enable boot restore: %q", current.message)
	}
	current, command = press(t, current, "b")
	current = run(t, current, command)
	if host.status.BootRestore {
		t.Fatal("b should disable boot restore again")
	}
}

func TestSavingRuleWarnsWhenForwardingIsOff(t *testing.T) {
	current := model{system: &testSystem{}, systemStatus: &system.Status{}}
	updated, _ := current.Update(actionFinished{message: "Rule saved and applied", warnForwarding: true})
	if message := updated.(model).message; !strings.Contains(message, "IPv4 forwarding is OFF") {
		t.Fatalf("expected forwarding warning, got %q", message)
	}
	current.systemStatus.Forwarding = true
	updated, _ = current.Update(actionFinished{message: "Rule saved and applied", warnForwarding: true})
	if message := updated.(model).message; message != "Rule saved and applied" {
		t.Fatalf("unexpected warning with forwarding on: %q", message)
	}
}

func TestDeleteRemovesRuleChosenWhenPromptOpened(t *testing.T) {
	rules := &testRuleStore{rules: []store.Rule{{ID: 4}, {ID: 9}}}
	current := model{service: app.Service{Store: rules, Firewall: testRuleFirewall{}}, rules: rules.rules}
	current, _ = press(t, current, "d")
	current.cursor = 1 // a refresh or stray navigation must not change the target
	_, command := press(t, current, "y")
	command()
	if len(rules.deleted) != 1 || rules.deleted[0] != 4 {
		t.Fatalf("deleted %v, want [4]", rules.deleted)
	}
}

func TestColorProfileUpgradesPlainXterm(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}
	tests := []struct {
		name     string
		detected termenv.Profile
		env      map[string]string
		tty      bool
		want     termenv.Profile
	}{
		{"PuTTY default xterm", termenv.Ascii, map[string]string{"TERM": "xterm"}, true, termenv.ANSI256},
		{"vt220 over SSH", termenv.Ascii, map[string]string{"TERM": "vt220"}, true, termenv.ANSI256},
		{"truecolor terminal kept", termenv.TrueColor, map[string]string{"TERM": "xterm-256color"}, true, termenv.TrueColor},
		{"linux console kept at 16 colors", termenv.ANSI, map[string]string{"TERM": "linux"}, true, termenv.ANSI},
		{"dumb terminal", termenv.Ascii, map[string]string{"TERM": "dumb"}, true, termenv.Ascii},
		{"no TERM", termenv.Ascii, map[string]string{}, true, termenv.Ascii},
		{"not a terminal", termenv.Ascii, map[string]string{"TERM": "xterm"}, false, termenv.Ascii},
		{"NO_COLOR wins", termenv.TrueColor, map[string]string{"TERM": "xterm-256color", "NO_COLOR": "1"}, true, termenv.Ascii},
	}
	for _, test := range tests {
		if got := colorProfile(test.detected, env(test.env), test.tty); got != test.want {
			t.Errorf("%s: got profile %v, want %v", test.name, got, test.want)
		}
	}
}

func TestShortcutsIgnoreCapsLock(t *testing.T) {
	current := model{rules: []store.Rule{{ID: 3, Name: "web", PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"}}}
	added, _ := press(t, current, "A")
	if added.activeScreen != addScreen {
		t.Fatal("A should open the add screen like a")
	}
	removing, _ := press(t, current, "D")
	if removing.confirm == nil {
		t.Fatal("D should ask to remove the rule like d")
	}
	if _, command := press(t, current, "Q"); command == nil {
		t.Fatal("Q should quit like q")
	}
}

func TestCtrlHDeletesInForms(t *testing.T) {
	current := model{activeScreen: addScreen, fields: []string{"abc", "", "", "", "both", "masked"}}
	updated, _ := current.updateAdd(tea.KeyMsg{Type: tea.KeyCtrlH})
	if got := updated.(model).fields[0]; got != "ab" {
		t.Fatalf("Ctrl+H (PuTTY backspace option) left %q, want ab", got)
	}
}

// TestEveryScreenFitsAnyTerminalSize checks the raw layouts, before the
// final trim, so a help bar can never be silently cut off.
func TestEveryScreenFitsAnyTerminalSize(t *testing.T) {
	rules := make([]store.Rule, 12)
	for index := range rules {
		rules[index] = store.Rule{ID: int64(index + 1), Name: "Minecraft server number one", PublicPort: 25565, DestIP: "192.168.100.200", DestPort: 25565, Protocol: "both", Enabled: true}
	}
	message := "Rule saved and applied. IPv4 forwarding is OFF, so traffic will not pass; press F to enable it."
	status := &system.Status{PublicInterface: "ens3", VPNInterface: "tailscale0"}
	result := wgsetup.SetupResult{ConfigPath: "/etc/wireguard/wg0.conf", ServerPublicKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG=", PeerConfig: "[Interface]\nAddress = 10.66.0.2/24\nPrivateKey = <HOME_PRIVATE_KEY>\n\n[Peer]\nPublicKey = x\nEndpoint = vpn.example.net:51820\nAllowedIPs = 10.66.0.0/24\nPersistentKeepalive = 25"}
	for _, width := range []int{20, 30, 40, 49, 50, 60, 80, 100, 120, 200} {
		for _, height := range []int{8, 12, 15, 20, 24, 30, 40, 60} {
			screens := map[string]func(model) string{
				"rules":            model.listView,
				"add":              model.addView,
				"WireGuard form":   model.wireGuardView,
				"WireGuard result": model.wireGuardResultView,
			}
			for name, render := range screens {
				for _, withRules := range []bool{true, false} {
					current := model{width: width, height: height, webControl: &testWebControl{enabled: true}, system: &testSystem{}, systemStatus: status, message: message, cursor: 7,
						fields: []string{"Game server", "25565", "192.168.1.20", "25566", "both", "vpn.example.net:51820", "51820"}, focus: 4, wgResult: result, wgInterface: "wg0"}
					if withRules {
						current.rules = rules
					}
					lines := strings.Split(render(current), "\n")
					if len(lines) > height {
						t.Errorf("%dx%d %s (rules=%v): %d lines tall", width, height, name, withRules, len(lines))
					}
					for number, text := range lines {
						if lipgloss.Width(text) > width {
							t.Errorf("%dx%d %s: line %d is %d columns wide", width, height, name, number+1, lipgloss.Width(text))
						}
					}
				}
			}
		}
	}
}

func TestStandardTerminalShowsRulesUnderFullHeader(t *testing.T) {
	rules := make([]store.Rule, 12)
	for index := range rules {
		rules[index] = store.Rule{ID: int64(index + 1), Name: "web", PublicPort: 8080, DestIP: "192.168.100.200", DestPort: 80, Protocol: "tcp", Enabled: true}
	}
	current := model{width: 80, height: 24, rules: rules, webControl: &testWebControl{enabled: true}, system: &testSystem{}, systemStatus: &system.Status{PublicInterface: "ens3", VPNInterface: "wg0"}}
	view := current.View()
	for _, expected := range []string{"temp••••••••", "FORWARDING", "ROUTE", ":8080 -> 192.168.100.200:80", "Q   quit"} {
		if !strings.Contains(view, expected) {
			t.Errorf("80x24 view missing %q:\n%s", expected, view)
		}
	}
	if start, end := current.visibleRuleRange(); end-start < 5 {
		t.Fatalf("80x24 should fit at least 5 rules, got %d", end-start)
	}
}

func TestNarrowFormKeepsEndOfTypedValueVisible(t *testing.T) {
	key := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG="
	current := model{width: 30, height: 30, activeScreen: wireGuardScreen, fields: []string{"wg0", "10.66.0.1/24", "10.66.0.2", "192.168.1.0/24", key, "vpn.example.net:51820", "51820"}, focus: 4}
	if view := current.View(); !strings.Contains(view, "ABCDEFG=_") {
		t.Fatalf("the cursor end of a long value should stay visible:\n%s", view)
	}
}

func TestShortFormFollowsFocusedField(t *testing.T) {
	current := model{width: 60, height: 8, activeScreen: wireGuardScreen, fields: []string{"wg0", "10.66.0.1/24", "10.66.0.2", "192.168.1.0/24", "peer", "vpn.example.net:51820", "51820"}, focus: 6}
	view := current.View()
	if !strings.Contains(view, "Listen port") || strings.Contains(view, "Interface name") {
		t.Fatalf("a short screen should scroll the form to the focused field:\n%s", view)
	}
}

func TestWireGuardResultScrolls(t *testing.T) {
	result := wgsetup.SetupResult{ConfigPath: "/etc/wireguard/wg0.conf", ServerPublicKey: "key=", PeerConfig: strings.Repeat("line\n", 20) + "LAST CONFIG LINE"}
	current := model{width: 60, height: 10, activeScreen: wireGuardResultScreen, wgResult: result, wgInterface: "wg0"}
	if strings.Contains(current.View(), "sudo wg-quick up wg0") {
		t.Fatal("the end of a long result should start off screen")
	}
	for range 40 {
		updated, _ := current.Update(tea.KeyMsg{Type: tea.KeyDown})
		current = updated.(model)
	}
	if current.scroll != current.maxResultScroll() || !strings.Contains(current.View(), "sudo wg-quick up wg0") {
		t.Fatalf("scrolling down should stop at the end and show it (scroll=%d max=%d):\n%s", current.scroll, current.maxResultScroll(), current.View())
	}
	updated, _ := current.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if updated.(model).activeScreen != listScreen {
		t.Fatal("enter should return to the rule list")
	}
}

func TestClientIPPickerAndTypingIgnoredOnPickers(t *testing.T) {
	current := model{activeScreen: addScreen, fields: []string{"web", "8080", "10.0.0.2", "80", "tcp", "masked"}, focus: 5}
	updated, _ := current.updateAdd(tea.KeyMsg{Type: tea.KeyRight})
	current = updated.(model)
	if current.fields[5] != "real" || !strings.Contains(current.View(), "REAL CLIENT IP") || !strings.Contains(current.View(), "route back through the tunnel") {
		t.Fatalf("right arrow should pick the real client IP and explain it: %q\n%s", current.fields[5], current.View())
	}
	for _, focus := range []int{4, 5} {
		current.focus = focus
		before := current.fields[focus]
		updated, _ = current.updateAdd(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
		updated, _ = updated.(model).updateAdd(tea.KeyMsg{Type: tea.KeyBackspace})
		if got := updated.(model).fields[focus]; got != before {
			t.Fatalf("typing changed picker %d from %q to %q", focus, before, got)
		}
	}
	rule, err := parseRule(current.fields)
	if err != nil || !rule.KeepClientIP || rule.Protocol != "tcp" {
		t.Fatalf("parsed %+v, %v", rule, err)
	}
}

func TestEditLoadsClientIPMode(t *testing.T) {
	current := model{rules: []store.Rule{{ID: 4, PublicPort: 25565, DestIP: "10.0.0.8", DestPort: 25565, Protocol: "udp", KeepClientIP: true}}}
	updated, _ := press(t, current, "e")
	if updated.fields[5] != "real" {
		t.Fatalf("edit should load the client IP mode, got %q", updated.fields[5])
	}
}

func TestToggleShowsWhichRuleChanged(t *testing.T) {
	rules := &testRuleStore{rules: []store.Rule{{ID: 7, PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp", Enabled: true}}}
	current := model{service: app.Service{Store: rules, Firewall: testRuleFirewall{}}, rules: rules.rules}
	_, command := press(t, current, "t")
	if finished := command().(actionFinished); finished.err != nil || finished.message != "Rule #7 disabled" {
		t.Fatalf("unexpected toggle result: %+v", finished)
	}
}

func TestWhiptailKey(t *testing.T) {
	current, command := press(t, model{}, "u")
	if command != nil || current.switchToWhiptail || !strings.Contains(current.message, "whiptail is not installed") {
		t.Fatalf("without whiptail, U should explain how to install it: %q", current.message)
	}
	current, command = press(t, model{allowWhiptail: true}, "u")
	if command == nil || !current.switchToWhiptail {
		t.Fatal("with whiptail installed, U should leave the TUI to switch modes")
	}
	for _, installed := range []bool{true, false} {
		opened, _ := press(t, model{allowWhiptail: installed, width: 120, height: 40}, "m")
		if !strings.Contains(opened.View(), "Whiptail look") {
			t.Fatalf("the More menu should always offer the whiptail look (installed: %v):\n%s", installed, opened.View())
		}
	}
}

func TestRowsLineUpAsColumns(t *testing.T) {
	current := model{width: 100, height: 12, rules: []store.Rule{
		{ID: 1, Name: "a", PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp", Enabled: true},
		{ID: 2, Name: "b", PublicPort: 25565, DestIP: "192.168.100.200", DestPort: 25565, Protocol: "both", Enabled: true, KeepClientIP: true},
	}}
	if current.layout().cards {
		t.Fatal("a 12-line terminal should use one-line rows")
	}
	view := current.View()
	first, second := strings.Index(lineContaining(view, "#1 a"), "#1"), strings.Index(lineContaining(view, "#2 b"), "#2")
	if first < 0 || first != second {
		t.Fatalf("rule IDs should start in the same column (%d vs %d):\n%s", first, second, view)
	}
	if !strings.Contains(lineContaining(view, "#2 b"), "real") || !strings.Contains(lineContaining(view, "#1 a"), "masked") {
		t.Fatalf("rows should show the client IP mode:\n%s", view)
	}
}

func TestToggleShowsImmediatelyAndIgnoresStaleRefresh(t *testing.T) {
	rules := &testRuleStore{rules: []store.Rule{{ID: 3, PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp", Enabled: true}}}
	current := model{service: app.Service{Store: rules, Firewall: testRuleFirewall{}}, rules: rules.rules}
	current, command := press(t, current, "t")
	if current.rules[0].Enabled || current.applying != 1 || !strings.Contains(current.message, "Applying rule #3") {
		t.Fatalf("the toggle should show at once: %+v %q", current.rules[0], current.message)
	}
	if rules.rules[0].Enabled != true {
		t.Fatal("the on-screen change must not modify the caller's slice")
	}
	// A refresh that raced the change must not flash the old state back.
	updated, _ := current.Update(rulesLoaded{rules: []store.Rule{{ID: 3, Enabled: true}}})
	if updated.(model).rules[0].Enabled {
		t.Fatal("a refresh during the change should be ignored")
	}
	updated, _ = updated.(model).Update(command())
	if updated.(model).applying != 0 || updated.(model).message != "Rule #3 disabled" {
		t.Fatalf("finished change: applying=%d message=%q", updated.(model).applying, updated.(model).message)
	}
}

func TestClientIPKeyConfirmsBeforeTurningOn(t *testing.T) {
	rules := &testRuleStore{rules: []store.Rule{{ID: 5, PublicPort: 25565, DestIP: "10.0.0.2", DestPort: 25565, Protocol: "udp", Enabled: true}}}
	current := model{service: app.Service{Store: rules, Firewall: testRuleFirewall{}}, rules: rules.rules}
	current, command := press(t, current, "i")
	if command != nil || current.confirm == nil || !strings.Contains(current.message, "return route") {
		t.Fatalf("turning the real client IP on should ask first: %q", current.message)
	}
	current, command = press(t, current, "y")
	finished := command().(actionFinished)
	if finished.err != nil || !strings.Contains(finished.message, "now passes the real client IP") {
		t.Fatalf("unexpected result %+v", finished)
	}
	// Turning it back off is safe, so it applies at once without a prompt.
	current.rules = []store.Rule{{ID: 5, PublicPort: 25565, DestIP: "10.0.0.2", DestPort: 25565, Protocol: "udp", Enabled: true, KeepClientIP: true}}
	current, command = press(t, current, "i")
	if command == nil || current.confirm != nil || current.rules[0].KeepClientIP {
		t.Fatal("turning the real client IP off should apply at once")
	}
}

func TestHelpScreenExplainsReapplyAndApplyOnBoot(t *testing.T) {
	current, _ := press(t, model{width: 80, height: 24}, "?")
	if current.activeScreen != helpScreen {
		t.Fatal("? should open the help screen")
	}
	full := strings.Join(current.resultLines(innerWidth(current.contentWidth())), "\n")
	for _, expected := range []string{"Re-apply rules", "Rebuilds the firewall from your saved rules", "Apply on boot", "vanish when the server restarts", "Real client IP"} {
		if !strings.Contains(full, expected) {
			t.Errorf("help is missing %q:\n%s", expected, full)
		}
	}
	if current.maxResultScroll() == 0 {
		t.Fatal("help is longer than 24 lines and should scroll")
	}
	for range 100 {
		updated, _ := current.Update(tea.KeyMsg{Type: tea.KeyDown})
		current = updated.(model)
	}
	if !strings.Contains(current.View(), "keep working after you quit") {
		t.Fatalf("scrolling should reach the end of the help:\n%s", current.View())
	}
	closed, _ := current.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	if closed.(model).activeScreen != listScreen {
		t.Fatal("? again should close the help")
	}
}

func typeKeys(t *testing.T, current model, text string) model {
	t.Helper()
	for _, character := range text {
		key := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{character}}
		if character == ' ' {
			key = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
		}
		updated, _ := current.updateList(key)
		current = updated.(model)
	}
	return current
}

func searchRules() []store.Rule {
	return []store.Rule{
		{ID: 1, Name: "Minecraft", PublicPort: 25565, DestIP: "10.66.0.2", DestPort: 25565, Protocol: "both", Enabled: true},
		{ID: 2, Name: "Website", PublicPort: 8080, DestIP: "10.66.0.3", DestPort: 80, Protocol: "tcp", Enabled: true},
		{ID: 3, Name: "Quake", PublicPort: 27960, DestIP: "10.66.0.4", DestPort: 27960, Protocol: "udp", Enabled: false},
	}
}

func TestSearchFiltersAsYouType(t *testing.T) {
	rules := &testRuleStore{rules: searchRules()}
	current := model{width: 100, height: 30, service: app.Service{Store: rules, Firewall: testRuleFirewall{}}}
	current.updateRules(rules.rules)
	current, _ = press(t, current, "/")
	if !current.searching || !strings.Contains(current.View(), "Search: _") {
		t.Fatalf("/ should open the search line:\n%s", current.View())
	}
	// "q" is a letter here, not quit.
	current = typeKeys(t, current, "udp q")
	if len(current.rules) != 1 || current.rules[0].ID != 3 {
		t.Fatalf("\"udp q\" should match only Quake, got %+v", current.rules)
	}
	if view := current.View(); !strings.Contains(view, `matching "udp q"`) || strings.Contains(view, "Website") {
		t.Fatalf("view should show only the match:\n%s", view)
	}
	for range 2 {
		updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyBackspace})
		current = updated.(model)
	}
	if len(current.rules) != 2 {
		t.Fatalf("\"udp\" should match Minecraft (both) and Quake, got %d", len(current.rules))
	}
	updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyDown})
	current = updated.(model)
	if current.rules[current.cursor].ID != 3 || !current.searching {
		t.Fatal("DOWN should browse the matches while still typing")
	}
	updated, _ = current.updateList(tea.KeyMsg{Type: tea.KeyEnter})
	current = updated.(model)
	if current.searching || current.query != "udp" || !strings.Contains(current.View(), "Filtered by udp") {
		t.Fatalf("ENTER should keep the filter and leave the search line:\n%s", current.View())
	}
	_, command := press(t, current, "t")
	if finished := command().(actionFinished); finished.message != "Rule #3 enabled" {
		t.Fatalf("T should act on the selected match, got %q", finished.message)
	}
	// The once-a-second refresh keeps the filter.
	updated, _ = current.Update(rulesLoaded{rules: searchRules()})
	if current = updated.(model); len(current.rules) != 2 || len(current.allRules) != 3 {
		t.Fatalf("refresh should keep the filter: %d shown of %d", len(current.rules), len(current.allRules))
	}
	updated, _ = current.updateList(tea.KeyMsg{Type: tea.KeyEsc})
	if current = updated.(model); current.query != "" || len(current.rules) != 3 {
		t.Fatal("ESC on the list should clear the filter")
	}
}

func TestSearchWithNoMatches(t *testing.T) {
	current := model{width: 80, height: 24}
	current.updateRules(searchRules())
	current, _ = press(t, current, "/")
	current = typeKeys(t, current, "zzz")
	if view := current.View(); !strings.Contains(view, `No rules match "zzz"`) {
		t.Fatalf("expected a no-match message:\n%s", view)
	}
	updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyEnter})
	current = updated.(model)
	if current, command := press(t, current, "d"); command != nil || current.confirm != nil {
		t.Fatal("no rule is shown, so D must not offer to remove anything")
	}
}

func TestSearchLineFitsSmallTerminals(t *testing.T) {
	for _, size := range [][2]int{{20, 8}, {40, 12}, {80, 24}} {
		current := model{width: size[0], height: size[1], searching: true, query: "a very long search query"}
		current.updateRules(searchRules())
		lines := strings.Split(current.listView(), "\n")
		if len(lines) > size[1] {
			t.Errorf("%dx%d: %d lines", size[0], size[1], len(lines))
		}
		for _, text := range lines {
			if lipgloss.Width(text) > size[0] {
				t.Errorf("%dx%d: line %d wide", size[0], size[1], lipgloss.Width(text))
			}
		}
	}
}

func TestBackupScreenBacksUpAndRestores(t *testing.T) {
	directory := t.TempDir()
	database, err := store.Open(filepath.Join(directory, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	service := app.Service{Store: database, Firewall: testRuleFirewall{}}
	manager := &backup.Manager{Store: database, Dir: filepath.Join(directory, "backups"),
		Apply: func(ctx context.Context, rules []store.Rule, settings map[string]string) error {
			if err := database.ReplaceAll(ctx, rules, settings); err != nil {
				return err
			}
			return service.Reconcile(ctx)
		}}
	ctx := context.Background()
	if _, err := service.Add(ctx, store.Rule{Name: "keep", PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	current := model{width: 90, height: 30, service: service, backups: manager}
	current, command := press(t, current, "s")
	current = run(t, current, command)
	if current.activeScreen != backupScreen || !strings.Contains(current.View(), "No backups yet") {
		t.Fatalf("S should open the backups screen:\n%s", current.View())
	}
	updated, command := current.updateBackups(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	current = updated.(model)
	updated, _ = current.Update(command())
	updated, _ = updated.(model).Update(updated.(model).loadBackups()) // the reload it schedules
	current = updated.(model)
	if len(current.backupList) != 1 || !strings.Contains(current.message, "Backup saved (1 rules)") || !strings.Contains(current.View(), "manual") {
		t.Fatalf("N should make a manual backup: %q\n%s", current.message, current.View())
	}
	if _, err := service.Add(ctx, store.Rule{Name: "extra", PublicPort: 443, DestIP: "10.0.0.3", DestPort: 443, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	updated, _ = current.updateBackups(tea.KeyMsg{Type: tea.KeyEnter})
	current = updated.(model)
	if current.confirm == nil || !strings.Contains(current.message, "Restore the backup from") {
		t.Fatalf("ENTER should ask before restoring: %q", current.message)
	}
	updated, _ = current.updateBackups(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	if current = updated.(model); current.message != "Cancelled." {
		t.Fatal("any key but y should cancel the restore")
	}
	updated, _ = current.updateBackups(tea.KeyMsg{Type: tea.KeyEnter})
	updated, command = updated.(model).updateBackups(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	updated, _ = updated.(model).Update(command())
	if current = updated.(model); !strings.Contains(current.message, "Restored the backup from") {
		t.Fatalf("restore result: %q", current.message)
	}
	if rules, _ := database.List(ctx); len(rules) != 1 || rules[0].Name != "keep" {
		t.Fatalf("restore should bring back the single saved rule, got %+v", rules)
	}
	updated, _ = current.updateBackups(tea.KeyMsg{Type: tea.KeyEsc})
	if updated.(model).activeScreen != listScreen {
		t.Fatal("ESC should return to the rules")
	}
}

func TestBackupScreenFitsSmallTerminals(t *testing.T) {
	backups := make([]backup.Info, 40)
	for index := range backups {
		backups[index] = backup.Info{Name: fmt.Sprint(index), Kind: backup.Auto, Rules: index}
	}
	for _, size := range [][2]int{{20, 8}, {40, 12}, {80, 24}, {120, 40}} {
		current := model{width: size[0], height: size[1], activeScreen: backupScreen, backupList: backups, backupCursor: 35, message: "Backup saved (3 rules)."}
		lines := strings.Split(current.backupView(), "\n")
		if len(lines) > size[1] {
			t.Errorf("%dx%d: %d lines", size[0], size[1], len(lines))
		}
		for _, text := range lines {
			if lipgloss.Width(text) > size[0] {
				t.Errorf("%dx%d: line %d wide", size[0], size[1], lipgloss.Width(text))
			}
		}
		if size[1] >= 12 && !strings.Contains(current.backupView(), "35 rules") {
			t.Errorf("%dx%d: the selected backup should stay in view", size[0], size[1])
		}
	}
}

func submitPrompt(t *testing.T, current model, text string) (model, tea.Cmd) {
	t.Helper()
	current = typeKeys(t, current, text)
	updated, command := current.updateList(tea.KeyMsg{Type: tea.KeyEnter})
	return updated.(model), command
}

func TestPortPrompt(t *testing.T) {
	web := &testWebControl{enabled: true}
	current, _ := press(t, model{webControl: web}, "p")
	if current.prompt == nil || current.prompt.value != "8787" {
		t.Fatal("P should open the port prompt with the current port")
	}
	for range 4 {
		updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyBackspace})
		current = updated.(model)
	}
	current, command := submitPrompt(t, current, "99999")
	if command != nil || !strings.Contains(current.message, "1 to 65535") {
		t.Fatalf("an invalid port must be refused: %q", current.message)
	}
	current, _ = press(t, current, "p")
	updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyEsc})
	if current = updated.(model); current.prompt != nil || current.message != "Cancelled." {
		t.Fatal("ESC should cancel the prompt")
	}
	current, _ = press(t, current, "p")
	for range 4 {
		updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyBackspace})
		current = updated.(model)
	}
	current, command = submitPrompt(t, current, "9443")
	finished := command().(actionFinished)
	if web.port != 9443 || !strings.Contains(finished.message, "Web UI moved to http://203.0.113.5:9443") {
		t.Fatalf("port change: %d %q", web.port, finished.message)
	}
}

func TestRemoveAllNeedsTypedConfirmation(t *testing.T) {
	rules := &testRuleStore{rules: searchRules()}
	current := model{service: app.Service{Store: rules, Firewall: testRuleFirewall{}}}
	current.updateRules(rules.rules)
	current, _ = press(t, current, "x")
	if current.prompt == nil || !strings.Contains(current.prompt.label, "Remove all 3 rules") {
		t.Fatal("X should ask for typed confirmation")
	}
	// "q" and "y" are letters here, not quit or yes.
	current, command := submitPrompt(t, current, "yq")
	if command != nil || len(rules.rules) != 3 || !strings.Contains(current.message, "Nothing was removed") {
		t.Fatalf("wrong confirmation text must remove nothing: %q", current.message)
	}
	current, _ = press(t, current, "x")
	current, command = submitPrompt(t, current, "REMOVE ALL")
	finished := command().(actionFinished)
	if finished.err != nil || len(rules.rules) != 0 || !strings.Contains(finished.message, "Removed 3 rule(s)") {
		t.Fatalf("remove all: %+v, %d left", finished, len(rules.rules))
	}
	if current, _ := press(t, model{}, "x"); current.prompt != nil {
		t.Fatal("with no rules there is nothing to remove")
	}
}

type pathBackups struct{ BackupControl }

func (pathBackups) Path(name string) (string, error) {
	return "/var/lib/iptable-ui/db-backups/" + name, nil
}

func TestBackupDownloadKey(t *testing.T) {
	web := &testWebControl{}
	current := model{activeScreen: backupScreen, webControl: web, backups: pathBackups{}, backupList: []backup.Info{{Name: "rules-x.db", Rules: 2}}}
	updated, _ := current.updateBackups(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if message := updated.(model).message; !strings.Contains(message, "Turn on the web UI (W)") || !strings.Contains(message, "scp root@<this-server>:/var/lib/iptable-ui/db-backups/rules-x.db") {
		t.Fatalf("with the web UI off, D should explain and offer scp: %q", message)
	}
	web.enabled = true
	updated, _ = current.updateBackups(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if message := updated.(model).message; !strings.Contains(message, "http://203.0.113.5:8787/download/secret-rules-x.db") || !strings.Contains(message, "10 minutes") {
		t.Fatalf("D should show the download link: %q", message)
	}
}

func TestPromptFitsSmallTerminals(t *testing.T) {
	for _, size := range [][2]int{{20, 8}, {40, 12}, {80, 24}} {
		current := model{width: size[0], height: size[1], prompt: &textPrompt{label: "Remove all 120 rules? A backup is taken first. Type REMOVE ALL", value: "REMOVE"}}
		current.updateRules(searchRules())
		lines := strings.Split(current.listView(), "\n")
		if len(lines) > size[1] {
			t.Errorf("%dx%d: %d lines", size[0], size[1], len(lines))
		}
		for _, text := range lines {
			if lipgloss.Width(text) > size[0] {
				t.Errorf("%dx%d: line %d wide", size[0], size[1], lipgloss.Width(text))
			}
		}
	}
}

func TestEnterOpensRuleActions(t *testing.T) {
	rules := &testRuleStore{rules: searchRules()}
	current := model{width: 100, height: 30, service: app.Service{Store: rules, Firewall: testRuleFirewall{}}}
	current.updateRules(rules.rules)
	updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyEnter})
	current = updated.(model)
	view := current.View()
	if current.menu == nil || !strings.Contains(view, "Rule #1  Minecraft") || !strings.Contains(view, "Turn off") || !strings.Contains(view, "ESC") {
		t.Fatalf("ENTER should open the selected rule's actions:\n%s", view)
	}
	// DOWN then ENTER picks "Turn off", the same as pressing T.
	updated, _ = current.updateList(tea.KeyMsg{Type: tea.KeyDown})
	updated, command := updated.(model).updateList(tea.KeyMsg{Type: tea.KeyEnter})
	if current = updated.(model); current.menu != nil || command == nil || command().(actionFinished).message != "Rule #1 disabled" {
		t.Fatal("choosing Turn off should close the menu and disable the rule")
	}
	// A letter runs its item directly: D asks to remove.
	updated, _ = current.updateList(tea.KeyMsg{Type: tea.KeyEnter})
	updated, _ = updated.(model).updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	if current = updated.(model); current.confirm == nil || !strings.Contains(current.message, "Remove rule #1") {
		t.Fatalf("D in the menu should ask to remove the rule: %q", current.message)
	}
	updated, _ = current.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	updated, _ = updated.(model).updateList(tea.KeyMsg{Type: tea.KeyEnter})
	updated, _ = updated.(model).updateList(tea.KeyMsg{Type: tea.KeyEsc})
	if updated.(model).menu != nil {
		t.Fatal("ESC should close the menu")
	}
	if empty, _ := (model{}).updateList(tea.KeyMsg{Type: tea.KeyEnter}); empty.(model).menu != nil {
		t.Fatal("with no rules, ENTER has nothing to act on")
	}
}

func TestMoreMenuHoldsTheOtherActions(t *testing.T) {
	current := model{width: 100, height: 40, system: &testSystem{}, systemStatus: &system.Status{}, webControl: &testWebControl{}, backups: pathBackups{}}
	current.updateRules(searchRules())
	current, _ = press(t, current, "m")
	view := current.View()
	for _, expected := range []string{"More actions", "Re-apply rules", "IPv4 forwarding: turn on", "Apply on boot: turn on", "Backups", "Web UI port", "Remove all rules", "WireGuard setup", "Whiptail look"} {
		if !strings.Contains(view, expected) {
			t.Errorf("More menu missing %q:\n%s", expected, view)
		}
	}
	// Choosing Backups opens the backups screen.
	updated, _ := current.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	if updated.(model).activeScreen != backupScreen || updated.(model).menu != nil {
		t.Fatal("S in the More menu should open backups")
	}
	// M again closes it.
	current, _ = press(t, current, "m")
	if current.menu != nil {
		t.Fatal("M should close the More menu")
	}
}

func TestMenusFitSmallTerminals(t *testing.T) {
	for _, size := range [][2]int{{20, 8}, {40, 12}, {80, 24}} {
		current := model{width: size[0], height: size[1], system: &testSystem{}, systemStatus: &system.Status{}, webControl: &testWebControl{}}
		current.updateRules(searchRules())
		current.menu = current.moreMenu()
		current.menu.cursor = len(current.menu.items) - 1
		view := current.listView()
		lines := strings.Split(view, "\n")
		if len(lines) > size[1] {
			t.Errorf("%dx%d: %d lines", size[0], size[1], len(lines))
		}
		for _, text := range lines {
			if lipgloss.Width(text) > size[0] {
				t.Errorf("%dx%d: line %d wide", size[0], size[1], lipgloss.Width(text))
			}
		}
		if size[1] >= 12 && !strings.Contains(view, "Whiptail") {
			t.Errorf("%dx%d: the selected item should stay in view:\n%s", size[0], size[1], view)
		}
	}
}

type liveRuleFirewall struct{ testRuleFirewall }

func (liveRuleFirewall) LiveRules(context.Context) (string, error) {
	return "Chain IPTUI_DNAT (1 references)\n num   pkts bytes target  prot opt in   out  source     destination\n 1       42  2520 DNAT    6    --  ens3 *    0.0.0.0/0  0.0.0.0/0  tcp dpt:25565 to:10.66.0.2:25565\n", nil
}

func TestLiveRulesScreen(t *testing.T) {
	current := model{width: 90, height: 24, service: app.Service{Store: &testRuleStore{}, Firewall: liveRuleFirewall{}}}
	current, command := press(t, current, "l")
	updated, _ := current.Update(command())
	current = updated.(model)
	view := current.View()
	for _, expected := range []string{"LIVE FIREWALL RULES", "sudo iptables -t nat -L IPTUI_DNAT -n -v --line-numbers", "IPTUI_DNAT  1 rules, 1 with traffic", ":25565 -> 10.66.0.2:25565", "tcp", "PACKETS", "2.5 KB", "R   refresh", "T   raw output"} {
		if !strings.Contains(view, expected) {
			t.Errorf("live screen missing %q:\n%s", expected, view)
		}
	}
	raw, _ := current.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("t")})
	if view := raw.(model).View(); !strings.Contains(view, "Chain IPTUI_DNAT (1 references)") || !strings.Contains(view, "to:10.66.0.2:25565") || !strings.Contains(view, "T   table") {
		t.Fatalf("T should show the raw iptables output:\n%s", view)
	}
	if _, refresh := current.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")}); refresh == nil {
		t.Fatal("R should refresh the live rules")
	}
	updated, _ = current.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if updated.(model).activeScreen != listScreen {
		t.Fatal("ESC should return to the rules")
	}
	menu, _ := press(t, model{width: 100, height: 40}, "m")
	if !strings.Contains(menu.View(), "Live firewall rules") {
		t.Fatal("the More menu should offer the live rules")
	}
}

func TestBackupImportAndFolderFromTUI(t *testing.T) {
	directory := t.TempDir()
	database, err := store.Open(filepath.Join(directory, "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	if _, err := database.Add(ctx, store.Rule{PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	exported := filepath.Join(directory, "from-my-pc.db")
	if err := database.Backup(ctx, exported); err != nil {
		t.Fatal(err)
	}
	manager := &backup.Manager{Store: database, Dir: filepath.Join(directory, "backups")}
	current := model{width: 100, height: 30, activeScreen: backupScreen, backups: manager}
	if !strings.Contains(current.View(), "Saved in "+manager.Folder()) {
		t.Fatalf("the backups screen should show the folder:\n%s", current.View())
	}
	updated, _ := current.updateBackups(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("i")})
	current = updated.(model)
	for _, character := range exported {
		updated, _ = current.updateBackups(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{character}})
		current = updated.(model)
	}
	if !strings.Contains(current.View(), "Import a backup file") {
		t.Fatalf("the import prompt should be visible:\n%s", current.View())
	}
	updated, command := current.updateBackups(tea.KeyMsg{Type: tea.KeyEnter})
	updated, _ = updated.(model).Update(command())
	if current = updated.(model); !strings.Contains(current.message, "Imported from-my-pc.db (1 rules)") {
		t.Fatalf("import result: %q", current.message)
	}
	if backups, _ := manager.List(); len(backups) != 1 || backups[0].Kind != backup.Uploaded {
		t.Fatalf("the imported file should be listed: %+v", backups)
	}

	updated, _ = current.updateBackups(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("i")})
	current = typeIntoPrompt(t, updated.(model), "/no/such/file.db")
	updated, command = current.updateBackups(tea.KeyMsg{Type: tea.KeyEnter})
	if updated, _ = updated.(model).Update(command()); !strings.Contains(updated.(model).message, "no such file") {
		t.Fatalf("a missing file should be reported: %q", updated.(model).message)
	}
	current = updated.(model)

	target := filepath.Join(directory, "home", "iptable-ui-backups")
	updated, _ = current.updateBackups(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("o")})
	current = updated.(model)
	current.prompt.value = ""
	current = typeIntoPrompt(t, current, target)
	updated, command = current.updateBackups(tea.KeyMsg{Type: tea.KeyEnter})
	updated, _ = updated.(model).Update(command())
	if manager.Folder() != target || !strings.Contains(updated.(model).message, "Backups are now saved in "+target) {
		t.Fatalf("folder change: %q, message %q", manager.Folder(), updated.(model).message)
	}
}

func typeIntoPrompt(t *testing.T, current model, text string) model {
	t.Helper()
	for _, character := range text {
		updated, _ := current.updateBackups(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{character}})
		current = updated.(model)
	}
	return current
}

type memorySettings map[string]string

func (s memorySettings) Setting(_ context.Context, key string) (string, error) { return s[key], nil }
func (s memorySettings) SetSetting(_ context.Context, key, value string) error {
	s[key] = value
	return nil
}

func TestLookToggleCyclesAndSaves(t *testing.T) {
	defer applyTheme(tuiThemes[0])
	settings := memorySettings{}
	current := model{width: 100, height: 40, settings: settings, themeName: "classic"}
	seen := []string{}
	for range len(tuiThemes) {
		updated, command := current.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("o")})
		current = updated.(model)
		if command != nil {
			command()
		}
		seen = append(seen, settings[themeSetting])
	}
	if strings.Join(seen, ",") != "readable,light,ocean,plain,classic" {
		t.Fatalf("O should step through every look and save each: %v", seen)
	}
	menu, _ := press(t, current, "m")
	if !strings.Contains(menu.View(), "TUI look: Classic (next: Readable)") {
		t.Fatalf("the More menu should offer the next look:\n%s", menu.View())
	}
}

func TestPlainLookHasNoColors(t *testing.T) {
	defer applyTheme(tuiThemes[0])
	defer lipgloss.SetColorProfile(termenv.Ascii)
	lipgloss.SetColorProfile(termenv.ANSI256)
	applyTheme(findTheme("plain"))
	view := (model{width: 80, height: 24, rules: searchRules()}).View()
	if strings.Contains(view, "\x1b[38;") || strings.Contains(view, "\x1b[48;") {
		t.Fatal("the plain look must not use any colors")
	}
	applyTheme(findTheme("readable"))
	if colored := (model{width: 80, height: 24, rules: searchRules()}).View(); !strings.Contains(colored, "\x1b[") {
		t.Fatal("other looks use colors")
	}
}

type fakeTraffic struct{ snapshot traffic.Snapshot }

func (f fakeTraffic) Snapshot() traffic.Snapshot { return f.snapshot }

func TestTrafficShowsInHeaderAndRuleMenu(t *testing.T) {
	snapshot := traffic.Snapshot{
		Adapters: []traffic.Adapter{{Name: "ens3", Rate: traffic.Rate{InPerSecond: 1_200_000, OutPerSecond: 340_000}}},
		Forwards: map[traffic.Forward]traffic.Rate{{PublicPort: 25565, Protocol: "tcp", DestIP: "10.66.0.2"}: {InPerSecond: 1500, OutPerSecond: 300_000}},
	}
	current := model{width: 100, height: 30, traffic: fakeTraffic{snapshot}}
	current.updateRules(searchRules())
	updated, _ := current.Update(current.loadTraffic())
	current = updated.(model)
	if view := current.View(); !strings.Contains(view, "ENS3 RX 1.2 MB/s TX 340 KB/s") {
		t.Fatalf("the header should show adapter speeds:\n%s", view)
	}
	updated, _ = current.updateList(tea.KeyMsg{Type: tea.KeyEnter})
	if view := updated.(model).View(); !strings.Contains(view, "▼ 1.5 KB/s ▲ 300 KB/s") {
		t.Fatalf("the rule menu should show the rule's speed:\n%s", view)
	}
}

func TestReadableCounter(t *testing.T) {
	for value, want := range map[string]string{"0": "0 B", "2520": "2.5 KB", "73K": "73 KB", "1.2M": "1.2 MB", "odd": "odd"} {
		if got := readableCounter(value); got != want {
			t.Errorf("readableCounter(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestSimpleViewToggleSavesAndReadsPlainly(t *testing.T) {
	settings := memorySettings{}
	current := model{width: 80, height: 24, settings: settings, webControl: &testWebControl{enabled: true},
		systemStatus: &system.Status{Forwarding: false, PublicInterface: "ens3", VPNInterface: "tailscale0", VPNUp: true, VPNKind: "Tailscale", VPNAddress: "100.64.0.1", BootRestore: true}, system: &testSystem{}}
	current.updateRules(searchRules())
	updated, command := current.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	current = updated.(model)
	command()
	if !current.simple || settings[viewSetting] != "simple" {
		t.Fatalf("N should switch to the simple view and save it: %v %v", current.simple, settings)
	}
	view := current.View()
	for _, expected := range []string{"Forwarding is off, so forwards do not work", "Connected through Tailscale (this server is 100.64.0.1 on it).", "After a reboot: your rules come back automatically.", "On   Minecraft", "port 25565 → 10.66.0.2:25565", "port 8080 → 10.66.0.3:80", "TCP+UDP", "Web UI is on"} {
		if !strings.Contains(view, expected) {
			t.Errorf("simple view missing %q:\n%s", expected, view)
		}
	}
	if strings.Contains(view, "ROUTE") || strings.Contains(view, "masked") || strings.Contains(view, "temp••••") {
		t.Fatalf("the simple view should hide codes and the token:\n%s", view)
	}
	updated, command = current.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	command()
	if updated.(model).simple || settings[viewSetting] != "detailed" || !strings.Contains(updated.(model).View(), "ROUTE") {
		t.Fatal("N again should return to the detailed view and save it")
	}
}

func TestSimpleViewFitsAnyTerminalSize(t *testing.T) {
	for _, width := range []int{20, 30, 40, 59, 60, 80, 120} {
		for _, height := range []int{8, 12, 24, 40} {
			current := model{width: width, height: height, simple: true, webControl: &testWebControl{enabled: true}, message: "Rule saved and applied.",
				systemStatus: &system.Status{PublicInterface: "ens3", VPNInterface: "wg0", VPNKind: "WireGuard"}, system: &testSystem{}}
			current.updateRules(searchRules())
			lines := strings.Split(current.listView(), "\n")
			if len(lines) > height {
				t.Errorf("%dx%d: %d lines", width, height, len(lines))
			}
			for _, text := range lines {
				if lipgloss.Width(text) > width {
					t.Errorf("%dx%d: line %d wide", width, height, lipgloss.Width(text))
				}
			}
		}
	}
}

func lineContaining(view, part string) string {
	for _, text := range strings.Split(view, "\n") {
		if strings.Contains(text, part) {
			return text
		}
	}
	return ""
}

func contains(value, part string) bool {
	return strings.Contains(value, part)
}
