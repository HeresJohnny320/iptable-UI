package tui

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/muesli/termenv"
)

var (
	brandStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F2F7F3")).Background(lipgloss.Color("#176B4B")).Padding(0, 1)
	sectionStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#75D6A3"))
	mutedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#8B9A91"))
	labelStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#96A79C"))
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F5F8F5"))
	publicStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#E5B85C"))
	addressStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#61C7D4"))
	portStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#81D69F"))
	protocolStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#C5A7EF"))
	enabledStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#66D494"))
	disabledStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#D9A36A"))
	keyStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#12241A")).Background(lipgloss.Color("#80D6A5")).Padding(0, 1)
	messageStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#F0D28A")).BorderLeft(true).BorderForeground(lipgloss.Color("#D9A64F")).PaddingLeft(1)
	panelBorder   = lipgloss.RoundedBorder()
)

type screen int

const (
	listScreen screen = iota
	addScreen
	wireGuardScreen
	wireGuardResultScreen
	helpScreen
)

type WebControl interface {
	Toggle() (bool, error)
	Enabled() bool
	Address() string
	Token() string
	StatusText() string
}

type WireGuardSetup interface {
	Configure(context.Context, wgsetup.SetupRequest) (wgsetup.SetupResult, error)
}

type SystemControl interface {
	Status(context.Context) system.Status
	SetForwarding(context.Context, bool) error
	SetBootRestore(context.Context, bool) error
}

type model struct {
	service      app.Service
	webControl   WebControl
	wgSetup      WireGuardSetup
	system       SystemControl
	systemStatus *system.Status
	// rules is what the list shows: allRules filtered by query.
	rules    []store.Rule
	allRules []store.Rule
	query    string
	// searching is true while the search line has keyboard focus.
	searching    bool
	cursor       int
	selectedID   int64
	listOffset   int
	activeScreen screen
	fields       []string
	focus        int
	message      string
	confirm      *pendingAction
	wgResult     wgsetup.SetupResult
	wgInterface  string
	editingID    int64
	scroll       int
	// allowWhiptail shows the U key; switchToWhiptail is set when it is pressed.
	allowWhiptail    bool
	switchToWhiptail bool
	// applying counts changes shown on screen before the firewall finished
	// applying them; refreshes wait so they do not flash the old state.
	applying int
	width    int
	height   int
}

// pendingAction is a change that waits for the user to press y. Its action
// may return a notice to show after the success message.
type pendingAction struct {
	success string
	action  func(context.Context) (string, error)
}

const (
	clientIPMasked = "masked"
	clientIPReal   = "real"
)

// addPickers are the add-form fields chosen with LEFT/RIGHT instead of typed.
var addPickers = map[int][]string{
	4: {"both", "tcp", "udp"},
	5: {clientIPMasked, clientIPReal},
}

type rulesLoaded struct {
	rules []store.Rule
	err   error
}

type actionFinished struct {
	message string
	err     error
	// warnForwarding appends a hint when IPv4 forwarding is off, because the
	// rule cannot pass traffic until it is enabled.
	warnForwarding bool
	// optimistic marks a change that was already drawn on screen.
	optimistic bool
}

type systemLoaded system.Status

type wireGuardSetupFinished struct {
	result wgsetup.SetupResult
	err    error
}

type rulesRefreshTick time.Time

// Run shows the TUI until the user quits. It reports whether the user asked
// to switch to whiptail mode instead.
func Run(service app.Service, webControl WebControl, setup WireGuardSetup, host SystemControl, allowWhiptail bool) (bool, error) {
	lipgloss.SetColorProfile(colorProfile(lipgloss.ColorProfile(), os.Getenv, term.IsTerminal(os.Stdout.Fd())))
	program := tea.NewProgram(model{service: service, webControl: webControl, wgSetup: setup, system: host, allowWhiptail: allowWhiptail}, tea.WithAltScreen())
	final, err := program.Run()
	if err != nil {
		return false, err
	}
	finished, _ := final.(model)
	return finished.switchToWhiptail, nil
}

// colorProfile upgrades terminals that do not advertise color support. PuTTY,
// plain xterm and many SSH clients set TERM=xterm, which termenv treats as
// monochrome even though they all render 256 colors. NO_COLOR and TERM=dumb
// still turn colors off.
func colorProfile(detected termenv.Profile, getenv func(string) string, tty bool) termenv.Profile {
	if getenv("NO_COLOR") != "" {
		return termenv.Ascii
	}
	if detected != termenv.Ascii || !tty {
		return detected
	}
	switch strings.ToLower(getenv("TERM")) {
	case "", "dumb":
		return termenv.Ascii
	}
	return termenv.ANSI256
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.loadRules, m.loadSystem, scheduleRulesRefresh())
}

func (m model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.height = message.Height
		m.keepCursorVisible()
		return m, nil
	case rulesRefreshTick:
		if m.activeScreen == listScreen {
			return m, tea.Batch(m.loadRules, m.loadSystem, scheduleRulesRefresh())
		}
		return m, scheduleRulesRefresh()
	case rulesLoaded:
		if m.applying > 0 {
			return m, nil
		}
		if message.err != nil {
			m.message = "Rule list refresh failed: " + message.err.Error()
			return m, nil
		}
		m.updateRules(message.rules)
		if strings.HasPrefix(m.message, "Rule list refresh failed:") {
			m.message = ""
		}
		m.keepCursorVisible()
		return m, nil
	case systemLoaded:
		status := system.Status(message)
		m.systemStatus = &status
		return m, nil
	case actionFinished:
		if message.optimistic && m.applying > 0 {
			m.applying--
		}
		if message.err != nil {
			m.message = message.err.Error()
			return m, tea.Batch(m.loadRules, m.loadSystem)
		}
		m.message = message.message
		if message.warnForwarding && m.systemStatus != nil && !m.systemStatus.Forwarding {
			m.message += ". IPv4 forwarding is OFF, so traffic will not pass; press F to enable it."
		}
		if message.message == "Rule updated and applied" {
			m.activeScreen = listScreen
			m.editingID = 0
		}
		return m, tea.Batch(m.loadRules, m.loadSystem)
	case wireGuardSetupFinished:
		if message.err != nil {
			m.message = message.err.Error()
			return m, nil
		}
		m.wgResult = message.result
		m.wgInterface = m.fields[0]
		m.activeScreen = wireGuardResultScreen
		m.scroll = 0
		return m, nil
	case tea.KeyMsg:
		if m.activeScreen == addScreen {
			return m.updateAdd(message)
		}
		if m.activeScreen == wireGuardScreen {
			return m.updateWireGuard(message)
		}
		if m.activeScreen == wireGuardResultScreen || m.activeScreen == helpScreen {
			return m.updateResult(message)
		}
		return m.updateList(message)
	}
	return m, nil
}

func (m model) updateList(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.confirm != nil {
		pending := m.confirm
		m.confirm = nil
		if key.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if keyName(key) == "y" {
			return m, func() tea.Msg {
				notice, err := pending.action(context.Background())
				return actionFinished{message: withNotice(pending.success, notice), err: err}
			}
		}
		m.message = "Cancelled."
		return m, nil
	}
	if m.searching {
		if handled, quit := m.updateSearch(key); quit {
			return m, tea.Quit
		} else if handled {
			return m, nil
		}
	}
	if key.Type == tea.KeyUp {
		if m.cursor > 0 {
			m.selectRule(m.cursor - 1)
		}
		m.keepCursorVisible()
		return m, nil
	}
	if key.Type == tea.KeyDown {
		if m.cursor < len(m.rules)-1 {
			m.selectRule(m.cursor + 1)
		}
		m.keepCursorVisible()
		return m, nil
	}
	switch keyName(key) {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "k":
		if m.cursor > 0 {
			m.selectRule(m.cursor - 1)
		}
		m.keepCursorVisible()
	case "j":
		if m.cursor < len(m.rules)-1 {
			m.selectRule(m.cursor + 1)
		}
		m.keepCursorVisible()
	case "r":
		return m, m.perform("Saved rules re-applied to the firewall", m.service.Reconcile)
	case "w":
		if m.webControl == nil {
			m.message = "Web UI control is unavailable."
			break
		}
		enabled, err := m.webControl.Toggle()
		if err != nil {
			m.message = err.Error()
		} else if enabled {
			m.message = "Web UI is ON at http://" + m.webControl.Address()
		} else {
			m.message = "Web UI is OFF. The session token remains valid only for this process."
		}
	case "/":
		m.searching = true
		m.message = ""
	case "esc":
		if m.query != "" {
			m.query = ""
			m.filterRules()
			m.message = "Search cleared."
		}
	case "?", "h":
		m.activeScreen = helpScreen
		m.scroll = 0
	case "u":
		if !m.allowWhiptail {
			m.message = "whiptail is not installed (Debian/Ubuntu: apt install whiptail; Fedora: dnf install newt)."
			break
		}
		m.switchToWhiptail = true
		return m, tea.Quit
	case "g":
		m.activeScreen = wireGuardScreen
		m.fields = []string{"wg0", "10.66.0.1/24", "10.66.0.2", "192.168.0.0/24", "", "vpn.example.net:51820", "51820"}
		m.focus = 0
		m.message = "Home peer public key is required. Install wireguard-tools first if wg is unavailable."
	case "a":
		m.activeScreen = addScreen
		m.editingID = 0
		m.fields = []string{"", "", "", "", "both", clientIPMasked}
		m.focus = 0
		m.message = "Tab moves between fields. Enter saves on the final field."
	case "e":
		if len(m.rules) > 0 {
			rule := m.rules[m.cursor]
			m.activeScreen = addScreen
			m.editingID = rule.ID
			clientIP := clientIPMasked
			if rule.KeepClientIP {
				clientIP = clientIPReal
			}
			m.fields = []string{rule.Name, fmt.Sprint(rule.PublicPort), rule.DestIP, fmt.Sprint(rule.DestPort), rule.Protocol, clientIP}
			m.focus = 0
			m.message = "Editing selected rule. Enter saves the change."
		}
	case "t":
		if len(m.rules) > 0 {
			rule := m.rules[m.cursor]
			changed := rule
			changed.Enabled = !rule.Enabled
			m.showApplying(changed)
			return m, func() tea.Msg {
				notice, err := m.service.SetEnabled(context.Background(), rule.ID, changed.Enabled)
				message := fmt.Sprintf("Rule #%d disabled", rule.ID)
				if changed.Enabled {
					message = fmt.Sprintf("Rule #%d enabled", rule.ID)
				}
				return actionFinished{message: withNotice(message, notice), err: err, warnForwarding: changed.Enabled, optimistic: true}
			}
		}
	case "i":
		if len(m.rules) > 0 {
			rule := m.rules[m.cursor]
			changed := rule
			changed.KeepClientIP = !rule.KeepClientIP
			if changed.KeepClientIP {
				m.confirm = &pendingAction{success: fmt.Sprintf("Rule #%d now passes the real client IP", rule.ID), action: func(ctx context.Context) (string, error) {
					_, err := m.service.Update(ctx, changed)
					return "Replies must route back through the tunnel; see README: Keep the Real Client IP", err
				}}
				m.message = fmt.Sprintf("Pass the real client IP for rule #%d? The home side needs a return route through the tunnel or the forward stops working. Press y to confirm, any other key to cancel.", rule.ID)
				break
			}
			m.showApplying(changed)
			return m, func() tea.Msg {
				_, err := m.service.Update(context.Background(), changed)
				return actionFinished{message: fmt.Sprintf("Rule #%d masks the client IP again", rule.ID), err: err, optimistic: true}
			}
		}
	case "d":
		if len(m.rules) > 0 {
			rule := m.rules[m.cursor]
			m.confirm = &pendingAction{success: fmt.Sprintf("Rule #%d removed", rule.ID), action: func(ctx context.Context) (string, error) { return m.service.Delete(ctx, rule.ID) }}
			m.message = fmt.Sprintf("Remove rule #%d? Press y to confirm, any other key to cancel.", rule.ID)
		}
	case "f":
		if m.system == nil || m.systemStatus == nil {
			m.message = "Host settings are unavailable."
			break
		}
		if m.systemStatus.Forwarding {
			m.confirm = &pendingAction{success: "IPv4 forwarding disabled", action: func(ctx context.Context) (string, error) { return "", m.system.SetForwarding(ctx, false) }}
			m.message = "Disable IPv4 forwarding? Every forward stops passing traffic. Press y to confirm, any other key to cancel."
			break
		}
		return m, m.perform("IPv4 forwarding enabled and saved for reboots", func(ctx context.Context) error { return m.system.SetForwarding(ctx, true) })
	case "b":
		if m.system == nil || m.systemStatus == nil {
			m.message = "Host settings are unavailable."
			break
		}
		if m.systemStatus.BootRestore {
			return m, m.perform("Apply on boot is OFF: after a reboot, forwards stay down until you open iptable-ui", func(ctx context.Context) error { return m.system.SetBootRestore(ctx, false) })
		}
		return m, m.perform("Apply on boot is ON: your saved rules come back automatically after a reboot", func(ctx context.Context) error { return m.system.SetBootRestore(ctx, true) })
	}
	return m, nil
}

func (m model) updateResult(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch keyName(key) {
	case "esc", "enter", "q", "?", "h":
		m.activeScreen = listScreen
	case "up", "k":
		m.scroll = max(0, m.scroll-1)
	case "down", "j":
		m.scroll = min(m.maxResultScroll(), m.scroll+1)
	case "pgup":
		m.scroll = max(0, m.scroll-max(1, m.heightLimit()/2))
	case "pgdown", " ":
		m.scroll = min(m.maxResultScroll(), m.scroll+max(1, m.heightLimit()/2))
	}
	return m, nil
}

func (m model) updateWireGuard(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.Type {
	case tea.KeyEsc:
		m.activeScreen = listScreen
		m.message = "WireGuard setup cancelled."
		return m, nil
	case tea.KeyTab, tea.KeyDown:
		m.focus = (m.focus + 1) % len(m.fields)
	case tea.KeyShiftTab, tea.KeyUp:
		m.focus = (m.focus - 1 + len(m.fields)) % len(m.fields)
	case tea.KeyEnter:
		if m.focus < len(m.fields)-1 {
			m.focus++
			return m, nil
		}
		request, err := parseSetup(m.fields)
		if err != nil {
			m.message = err.Error()
			return m, nil
		}
		return m, func() tea.Msg {
			result, err := m.wgSetup.Configure(context.Background(), request)
			return wireGuardSetupFinished{result: result, err: err}
		}
	case tea.KeyBackspace, tea.KeyCtrlH, tea.KeyDelete:
		if len(m.fields[m.focus]) > 0 {
			m.fields[m.focus] = m.fields[m.focus][:len(m.fields[m.focus])-1]
		}
	case tea.KeyRunes:
		m.fields[m.focus] += string(key.Runes)
	}
	return m, nil
}

func (m model) updateAdd(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.Type {
	case tea.KeyEsc:
		m.activeScreen = listScreen
		m.editingID = 0
		m.message = "Add cancelled."
		return m, nil
	case tea.KeyTab, tea.KeyDown:
		m.focus = (m.focus + 1) % len(m.fields)
	case tea.KeyShiftTab, tea.KeyUp:
		m.focus = (m.focus - 1 + len(m.fields)) % len(m.fields)
	case tea.KeyLeft, tea.KeyRight, tea.KeySpace:
		if choices, ok := addPickers[m.focus]; ok {
			current := 0
			for index, choice := range choices {
				if m.fields[m.focus] == choice {
					current = index
					break
				}
			}
			if key.Type == tea.KeyLeft {
				current = (current - 1 + len(choices)) % len(choices)
			} else {
				current = (current + 1) % len(choices)
			}
			m.fields[m.focus] = choices[current]
		}
	case tea.KeyEnter:
		if m.focus < len(m.fields)-1 {
			m.focus++
			return m, nil
		}
		rule, err := parseRule(m.fields)
		if err != nil {
			m.message = err.Error()
			return m, nil
		}
		return m, func() tea.Msg {
			if m.editingID != 0 {
				rule.ID = m.editingID
				_, err := m.service.Update(context.Background(), rule)
				return actionFinished{message: "Rule updated and applied", err: err, warnForwarding: true}
			}
			_, err := m.service.Add(context.Background(), rule)
			return actionFinished{message: "Rule saved and applied", err: err, warnForwarding: true}
		}
	case tea.KeyBackspace, tea.KeyCtrlH, tea.KeyDelete:
		if _, picker := addPickers[m.focus]; !picker && len(m.fields[m.focus]) > 0 {
			m.fields[m.focus] = m.fields[m.focus][:len(m.fields[m.focus])-1]
		}
	case tea.KeyRunes:
		if _, picker := addPickers[m.focus]; !picker {
			m.fields[m.focus] += string(key.Runes)
		}
	}
	return m, nil
}

func (m model) loadRules() tea.Msg {
	rules, err := m.service.List(context.Background())
	return rulesLoaded{rules: rules, err: err}
}

func (m model) loadSystem() tea.Msg {
	if m.system == nil {
		return nil
	}
	return systemLoaded(m.system.Status(context.Background()))
}

func scheduleRulesRefresh() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return rulesRefreshTick(t) })
}

func (m *model) updateRules(rules []store.Rule) {
	m.allRules = rules
	m.filterRules()
}

// filterRules shows the rules matching the search, keeping the selected rule
// selected while it still matches.
func (m *model) filterRules() {
	if m.allRules == nil {
		m.allRules = m.rules
	}
	selectedID := m.selectedID
	if selectedID == 0 && m.cursor >= 0 && m.cursor < len(m.rules) {
		selectedID = m.rules[m.cursor].ID
	}
	m.rules = make([]store.Rule, 0, len(m.allRules))
	for _, rule := range m.allRules {
		if rule.Matches(m.query) {
			m.rules = append(m.rules, rule)
		}
	}
	if len(m.rules) == 0 {
		m.cursor = 0
		m.selectedID = 0
		m.listOffset = 0
		return
	}
	if selectedID != 0 {
		for index, rule := range m.rules {
			if rule.ID == selectedID {
				m.cursor = index
				break
			}
		}
	}
	m.cursor = min(max(0, m.cursor), len(m.rules)-1)
	m.selectedID = m.rules[m.cursor].ID
	m.keepCursorVisible()
}

func (m *model) selectRule(index int) {
	if len(m.rules) == 0 {
		m.cursor = 0
		m.selectedID = 0
		return
	}
	m.cursor = min(max(0, index), len(m.rules)-1)
	m.selectedID = m.rules[m.cursor].ID
}

// updateSearch edits the search line. Up and Down are not handled, so the
// matches can be browsed while typing.
func (m *model) updateSearch(key tea.KeyMsg) (handled, quit bool) {
	switch key.Type {
	case tea.KeyCtrlC:
		return true, true
	case tea.KeyUp, tea.KeyDown:
		return false, false
	case tea.KeyEnter:
		m.searching = false
	case tea.KeyEsc:
		m.searching = false
		m.query = ""
		m.filterRules()
	case tea.KeyBackspace, tea.KeyCtrlH, tea.KeyDelete:
		if runes := []rune(m.query); len(runes) > 0 {
			m.query = string(runes[:len(runes)-1])
			m.filterRules()
		}
	case tea.KeySpace:
		m.query += " "
		m.filterRules()
	case tea.KeyRunes:
		m.query += string(key.Runes)
		m.filterRules()
	}
	return true, false
}

// showApplying draws a rule change right away, before the firewall has
// finished applying it.
func (m *model) showApplying(changed store.Rule) {
	if m.allRules == nil {
		m.allRules = m.rules
	}
	rules := append([]store.Rule(nil), m.allRules...)
	for index := range rules {
		if rules[index].ID == changed.ID {
			rules[index] = changed
		}
	}
	m.allRules = rules
	m.filterRules()
	m.applying++
	m.message = fmt.Sprintf("Applying rule #%d...", changed.ID)
}

func withNotice(message, notice string) string {
	if notice == "" {
		return message
	}
	return message + ". " + notice
}

func (m model) perform(success string, action func(context.Context) error) tea.Cmd {
	return func() tea.Msg {
		err := action(context.Background())
		return actionFinished{message: success, err: err}
	}
}

// keyName lowercases single-letter keys so shortcuts work with Caps Lock or
// Shift held, as the help bar shows them in capitals.
func keyName(key tea.KeyMsg) string {
	if key.Type == tea.KeyRunes && len(key.Runes) == 1 && !key.Alt {
		return strings.ToLower(string(key.Runes))
	}
	return key.String()
}

func onOff(on bool, onText, offText string) string {
	if on {
		return enabledStyle.Render(onText)
	}
	return disabledStyle.Render(offText)
}

func helpKey(key, description string) string {
	return lipgloss.JoinHorizontal(lipgloss.Center, keyStyle.Render(" "+key+" "), " ", mutedStyle.Render(description))
}

func parseRule(fields []string) (store.Rule, error) {
	publicPort, err := parsePort(fields[1])
	if err != nil {
		return store.Rule{}, fmt.Errorf("public port: %w", err)
	}
	destPort := publicPort
	if strings.TrimSpace(fields[3]) != "" {
		destPort, err = parsePort(fields[3])
		if err != nil {
			return store.Rule{}, fmt.Errorf("destination port: %w", err)
		}
	}
	address, err := netip.ParseAddr(strings.TrimSpace(fields[2]))
	if err != nil || !address.Is4() {
		return store.Rule{}, fmt.Errorf("destination must be a valid IPv4 address")
	}
	protocol := strings.ToLower(strings.TrimSpace(fields[4]))
	if protocol != "tcp" && protocol != "udp" && protocol != "both" {
		return store.Rule{}, fmt.Errorf("protocol must be tcp, udp, or both")
	}
	return store.Rule{Name: strings.TrimSpace(fields[0]), PublicPort: publicPort, DestIP: address.String(), DestPort: destPort, Protocol: protocol, KeepClientIP: len(fields) > 5 && fields[5] == clientIPReal}, nil
}

func parseSetup(fields []string) (wgsetup.SetupRequest, error) {
	listenPort, err := parsePort(fields[6])
	if err != nil {
		return wgsetup.SetupRequest{}, fmt.Errorf("listen port: %w", err)
	}
	return wgsetup.SetupRequest{
		InterfaceName: strings.TrimSpace(fields[0]), ServerAddress: strings.TrimSpace(fields[1]),
		PeerAddress: strings.TrimSpace(fields[2]), HomeLAN: strings.TrimSpace(fields[3]),
		PeerPublicKey: strings.TrimSpace(fields[4]), PublicEndpoint: strings.TrimSpace(fields[5]), ListenPort: listenPort,
	}, nil
}

func parsePort(value string) (uint16, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("must be between 1 and 65535")
	}
	return uint16(parsed), nil
}
