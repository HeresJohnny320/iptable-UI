package tui

import (
	"strings"
	"testing"

	"github.com/HeresJohnny320/iptable-ui/internal/store"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
			{width: width, webControl: &testWebControl{enabled: true}, rules: []store.Rule{{ID: 5, Name: "Game server", PublicPort: 25565, DestIP: "192.168.1.20", DestPort: 25566, Protocol: "both", Enabled: true}}},
			{width: width, activeScreen: addScreen, fields: []string{"Game server", "25565", "192.168.1.20", "25566", "both"}, focus: 2},
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
	current := model{activeScreen: addScreen, fields: []string{"label", "25565", "192.168.1.20", "25565", "both"}, focus: 4}
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
	if current.cursor < start || current.cursor >= end || start != 9 {
		t.Fatalf("selected rule is not tracked in view: cursor=%d range=[%d,%d)", current.cursor, start, end)
	}
	view := current.View()
	if !strings.Contains(view, "Showing 10-11 of 30 rules") || !strings.Contains(view, "#11") {
		t.Fatalf("viewport does not follow selected rule: %s", view)
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

func contains(value, part string) bool {
	return strings.Contains(value, part)
}
