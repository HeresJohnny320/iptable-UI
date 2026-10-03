package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

type testWebControl struct {
	enabled bool
}

func (w *testWebControl) Toggle() (bool, error) {
	w.enabled = !w.enabled
	return w.enabled, nil
}

func (w *testWebControl) Enabled() bool   { return w.enabled }
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
	if view := updated.(model).View(); !contains(view, "temporary-token") || !contains(view, "ON at http://127.0.0.1:8787") {
		t.Fatalf("TUI does not show web state and token: %s", view)
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
	for _, expected := range []string{"PORT FORWARD MANAGER", "RULES MENU", "ENABLED", "Game server", "PUBLIC", ":25565", "192.168.1.20", "25566", "PROTOCOL BOTH", "UP/DOWN", "WireGuard"} {
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
	for _, expected := range []string{"FORWARDING", "OFF (forwards blocked)", "ROUTE", "ens3 -> wg0 DOWN", "APPLY ON BOOT", "OFF (rules lost on reboot)", "forwarding", "apply on boot", "re-apply rules", "help"} {
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
	for _, expected := range []string{"temporary-token", "FORWARDING", "ROUTE", ":8080 -> 192.168.100.200:80", "Q   quit"} {
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
		if !strings.Contains((model{allowWhiptail: installed, width: 120}).View(), "whiptail look") {
			t.Fatalf("the U key should always be listed (whiptail installed: %v)", installed)
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
