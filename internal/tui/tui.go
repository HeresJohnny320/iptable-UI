package tui

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

type model struct {
	service       app.Service
	webControl    WebControl
	wgSetup       WireGuardSetup
	rules         []store.Rule
	cursor        int
	selectedID    int64
	listOffset    int
	activeScreen  screen
	fields        []string
	focus         int
	message       string
	confirmDelete bool
	wgResult      wgsetup.SetupResult
	wgInterface   string
	editingID     int64
	width         int
	height        int
}

type rulesLoaded struct {
	rules []store.Rule
	err   error
}

type actionFinished struct {
	message string
	err     error
}

type wireGuardSetupFinished struct {
	result wgsetup.SetupResult
	err    error
}

type rulesRefreshTick time.Time

func Run(service app.Service, webControl WebControl, setup WireGuardSetup) error {
	program := tea.NewProgram(model{service: service, webControl: webControl, wgSetup: setup}, tea.WithAltScreen())
	_, err := program.Run()
	return err
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.loadRules, scheduleRulesRefresh())
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
			return m, tea.Batch(m.loadRules, scheduleRulesRefresh())
		}
		return m, scheduleRulesRefresh()
	case rulesLoaded:
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
	case actionFinished:
		if message.err != nil {
			m.message = message.err.Error()
			return m, nil
		}
		m.message = message.message
		if message.message == "Rule updated and applied" {
			m.activeScreen = listScreen
			m.editingID = 0
		}
		return m, m.loadRules
	case wireGuardSetupFinished:
		if message.err != nil {
			m.message = message.err.Error()
			return m, nil
		}
		m.wgResult = message.result
		m.wgInterface = m.fields[0]
		m.activeScreen = wireGuardResultScreen
		return m, nil
	case tea.KeyMsg:
		if m.activeScreen == addScreen {
			return m.updateAdd(message)
		}
		if m.activeScreen == wireGuardScreen {
			return m.updateWireGuard(message)
		}
		if m.activeScreen == wireGuardResultScreen {
			if message.Type == tea.KeyEsc || message.String() == "enter" || message.String() == "q" {
				m.activeScreen = listScreen
			}
			return m, nil
		}
		return m.updateList(message)
	}
	return m, nil
}

func (m model) updateList(key tea.KeyMsg) (tea.Model, tea.Cmd) {
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
	switch key.String() {
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
		return m, m.perform("Enabled rules restored", m.service.Reconcile)
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
	case "g":
		m.activeScreen = wireGuardScreen
		m.fields = []string{"wg0", "10.66.0.1/24", "10.66.0.2", "192.168.0.0/24", "", "vpn.example.net:51820", "51820"}
		m.focus = 0
		m.message = "Home peer public key is required. Install wireguard-tools first if wg is unavailable."
	case "a":
		m.activeScreen = addScreen
		m.editingID = 0
		m.fields = []string{"", "", "", "", "both"}
		m.focus = 0
		m.message = "Tab moves between fields. Enter saves on the final field."
	case "e":
		if len(m.rules) > 0 {
			rule := m.rules[m.cursor]
			m.activeScreen = addScreen
			m.editingID = rule.ID
			m.fields = []string{rule.Name, fmt.Sprint(rule.PublicPort), rule.DestIP, fmt.Sprint(rule.DestPort), rule.Protocol}
			m.focus = 0
			m.message = "Editing selected rule. Enter saves the change."
		}
	case "t":
		if len(m.rules) > 0 {
			rule := m.rules[m.cursor]
			return m, m.perform("Rule state changed", func(ctx context.Context) error {
				return m.service.SetEnabled(ctx, rule.ID, !rule.Enabled)
			})
		}
	case "d":
		if len(m.rules) > 0 {
			m.confirmDelete = true
			m.message = "Remove selected rule? Press y to confirm, n to cancel."
		}
	case "y":
		if m.confirmDelete && len(m.rules) > 0 {
			rule := m.rules[m.cursor]
			m.confirmDelete = false
			return m, m.perform("Rule removed", func(ctx context.Context) error { return m.service.Delete(ctx, rule.ID) })
		}
	case "n", "esc":
		if m.confirmDelete {
			m.confirmDelete = false
			m.message = "Removal cancelled."
		}
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
	case tea.KeyBackspace, tea.KeyDelete:
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
	case tea.KeyLeft, tea.KeyRight:
		if m.focus == 4 {
			protocols := []string{"both", "tcp", "udp"}
			current := 0
			for index, protocol := range protocols {
				if m.fields[4] == protocol {
					current = index
					break
				}
			}
			if key.Type == tea.KeyRight {
				current = (current + 1) % len(protocols)
			} else {
				current = (current - 1 + len(protocols)) % len(protocols)
			}
			m.fields[4] = protocols[current]
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
				return actionFinished{message: "Rule updated and applied", err: err}
			}
			_, err := m.service.Add(context.Background(), rule)
			return actionFinished{message: "Rule saved and applied", err: err}
		}
	case tea.KeyBackspace, tea.KeyDelete:
		if len(m.fields[m.focus]) > 0 {
			m.fields[m.focus] = m.fields[m.focus][:len(m.fields[m.focus])-1]
		}
	case tea.KeyRunes:
		m.fields[m.focus] += string(key.Runes)
	}
	return m, nil
}

func (m model) loadRules() tea.Msg {
	rules, err := m.service.List(context.Background())
	return rulesLoaded{rules: rules, err: err}
}

func scheduleRulesRefresh() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return rulesRefreshTick(t) })
}

func (m *model) updateRules(rules []store.Rule) {
	selectedID := m.selectedID
	if selectedID == 0 && m.cursor >= 0 && m.cursor < len(m.rules) {
		selectedID = m.rules[m.cursor].ID
	}
	m.rules = rules
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

func (m model) perform(success string, action func(context.Context) error) tea.Cmd {
	return func() tea.Msg {
		err := action(context.Background())
		return actionFinished{message: success, err: err}
	}
}

func (m model) View() string {
	if m.activeScreen == addScreen {
		return m.addView()
	}
	if m.activeScreen == wireGuardScreen {
		return m.wireGuardView()
	}
	if m.activeScreen == wireGuardResultScreen {
		return m.wireGuardResultView()
	}
	width := m.contentWidth()
	brand := lipgloss.JoinHorizontal(lipgloss.Center, brandStyle.Render(" IP TABLE UI "), "  ", sectionStyle.Render("PORT FORWARD MANAGER"))
	headerLines := []string{brand, mutedStyle.Render("Manage saved forwards and restore the live firewall from SQLite."), mutedStyle.Render("Rule list auto-syncs every second while this menu is open.")}
	if m.webControl != nil {
		status := m.webControl.StatusText()
		if m.webControl.Enabled() {
			status = enabledStyle.Render(status)
		} else {
			status = disabledStyle.Render(status)
		}
		headerLines = append(headerLines,
			lipgloss.JoinHorizontal(lipgloss.Left, labelStyle.Render("WEB  "), status),
			lipgloss.JoinHorizontal(lipgloss.Left, labelStyle.Render("TOKEN  "), publicStyle.Render(m.webControl.Token())),
		)
	}
	header := lipgloss.NewStyle().Border(panelBorder).BorderForeground(lipgloss.Color("#3B7557")).Padding(0, 1).Width(width - 8).MaxWidth(width - 4).Render(lipgloss.JoinVertical(lipgloss.Left, headerLines...))
	rows := make([]string, 0, len(m.rules)+1)
	if len(m.rules) == 0 {
		rows = append(rows, mutedStyle.Render("No saved forwarding rules yet. Choose Add rule to get started."))
	}
	start, end := m.visibleRuleRange()
	for index := start; index < end; index++ {
		rule := m.rules[index]
		marker := "  "
		if index == m.cursor {
			marker = selectedStyle.Render("> ")
		}
		state := disabledStyle.Render("DISABLED")
		if rule.Enabled {
			state = enabledStyle.Render("ENABLED")
		}
		label := rule.Name
		if label == "" {
			label = "Unnamed forward"
		}
		nameStyle := labelStyle
		if index == m.cursor {
			nameStyle = selectedStyle
		}
		topLine := lipgloss.JoinHorizontal(lipgloss.Left, marker, state, "  ", mutedStyle.Render(fmt.Sprintf("#%d", rule.ID)), "  ", nameStyle.Render(label))
		routeLine := lipgloss.JoinHorizontal(lipgloss.Left,
			labelStyle.Render("PUBLIC "), publicStyle.Render(fmt.Sprintf(":%d", rule.PublicPort)),
			mutedStyle.Render("   ->   TARGET "), addressStyle.Render(rule.DestIP), ":", portStyle.Render(fmt.Sprint(rule.DestPort)),
		)
		protocolLine := lipgloss.JoinHorizontal(lipgloss.Left, labelStyle.Render("PROTOCOL "), protocolStyle.Render(strings.ToUpper(rule.Protocol)))
		content := lipgloss.JoinVertical(lipgloss.Left, topLine, routeLine, protocolLine)
		borderColor := lipgloss.Color("#394940")
		if index == m.cursor {
			borderColor = lipgloss.Color("#58B981")
		}
		rows = append(rows, lipgloss.NewStyle().Border(panelBorder).BorderForeground(borderColor).Padding(0, 1).Width(width-16).MaxWidth(width-8).Render(content))
	}
	menuTitle := sectionStyle.Render("RULES MENU")
	menuLines := []string{menuTitle}
	if len(m.rules) > 0 {
		menuLines = append(menuLines, mutedStyle.Render(fmt.Sprintf("Showing %d-%d of %d rules", start+1, end, len(m.rules))))
		if start > 0 {
			menuLines = append(menuLines, mutedStyle.Render("... more above ..."))
		}
	}
	menu := lipgloss.NewStyle().Border(panelBorder).BorderForeground(lipgloss.Color("#394940")).Padding(0, 1).Width(width - 8).MaxWidth(width - 4).Render(lipgloss.JoinVertical(lipgloss.Left, append(menuLines, rows...)...))
	if end < len(m.rules) {
		menu += "\n" + mutedStyle.Render("... more below; use Up/Down to scroll ...")
	}
	help := lipgloss.JoinHorizontal(lipgloss.Left, helpKey("UP/DOWN", "select"), "  ", helpKey("A", "add"), "  ", helpKey("E", "edit"))
	moreHelp := lipgloss.JoinHorizontal(lipgloss.Left, helpKey("T", "toggle"), "  ", helpKey("D", "remove"), "  ", helpKey("R", "restore"))
	setupHelp := lipgloss.JoinHorizontal(lipgloss.Left, helpKey("G", "WireGuard"), "  ", helpKey("W", "web"), "  ", helpKey("Q", "quit"))
	sections := []string{header, "", menu, help, moreHelp, setupHelp}
	if m.message != "" {
		sections = append(sections, messageStyle.Width(width-8).MaxWidth(width-4).Render(m.message))
	}
	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m model) wireGuardView() string {
	labels := []string{"Interface name", "VPS tunnel address/CIDR", "Home peer tunnel address", "Home LAN CIDR", "Home peer public key", "VPS public endpoint", "Listen port"}
	fields := make([]string, 0, len(labels)*2)
	fields = append(fields, brandStyle.Render(" WIREGUARD SETUP "), mutedStyle.Render("Create a protected VPS config and peer template."))
	for index, label := range labels {
		marker := "  "
		valueStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#DDE7DF"))
		if index == m.focus {
			marker = selectedStyle.Render("> ")
			valueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F2C96D")).Bold(true)
		}
		fields = append(fields, marker+labelStyle.Render(label), valueStyle.Render("  "+displayField(m.fields[index], index == m.focus)))
	}
	fields = append(fields, mutedStyle.Render("On home peer: umask 077; wg genkey | tee privatekey | wg pubkey > publickey"))
	fields = append(fields, mutedStyle.Render("Paste its public key above. Existing config files are never overwritten."))
	fields = append(fields, mutedStyle.Render("Tunnel activation remains a separate manual step."))
	formHelp := lipgloss.JoinHorizontal(lipgloss.Left, helpKey("TAB", "move field"), "  ", helpKey("ENTER", "continue / create"))
	sections := []string{lipgloss.NewStyle().Border(panelBorder).BorderForeground(lipgloss.Color("#3B7557")).Padding(0, 1).Width(m.contentWidth() - 8).MaxWidth(m.contentWidth() - 4).Render(lipgloss.JoinVertical(lipgloss.Left, fields...)), formHelp, helpKey("ESC", "back")}
	if m.message != "" {
		sections = append(sections, messageStyle.Width(m.contentWidth()-8).MaxWidth(m.contentWidth()-4).Render(m.message))
	}
	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m model) wireGuardResultView() string {
	content := lipgloss.JoinVertical(lipgloss.Left,
		brandStyle.Render(" WIREGUARD CONFIG CREATED "),
		labelStyle.Render("VPS CONFIG"), addressStyle.Render(m.wgResult.ConfigPath),
		labelStyle.Render("VPS PUBLIC KEY"), publicStyle.Render(m.wgResult.ServerPublicKey),
		labelStyle.Render("HOME PEER TEMPLATE (set its private key)"), protocolStyle.Render(m.wgResult.PeerConfig),
		mutedStyle.Render("Review the config before activation."),
		selectedStyle.Render("sudo wg-quick up "+m.wgInterface),
		helpKey("ENTER", "return"),
	)
	return lipgloss.NewStyle().Border(panelBorder).BorderForeground(lipgloss.Color("#3B7557")).Padding(0, 1).Width(m.contentWidth() - 8).MaxWidth(m.contentWidth() - 4).Render(content)
}

func (m model) addView() string {
	labels := []string{"Label (optional)", "Public port", "Destination IPv4", "Destination port (blank = public)", "Protocol (tcp, udp, both)"}
	fields := make([]string, 0, len(labels)*2+2)
	if m.editingID != 0 {
		fields = append(fields, brandStyle.Render(fmt.Sprintf(" EDIT PORT FORWARD #%d ", m.editingID)))
	} else {
		fields = append(fields, brandStyle.Render(" ADD PORT FORWARD "))
	}
	for index, label := range labels {
		marker := "  "
		valueStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#DDE7DF"))
		if index == m.focus {
			marker = selectedStyle.Render("> ")
			valueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F2C96D")).Bold(true)
		}
		fields = append(fields, marker+labelStyle.Render(label+":"))
		if index == 4 {
			fields = append(fields, valueStyle.Render("  < "+strings.ToUpper(m.fields[index])+" >")+"  "+mutedStyle.Render("(LEFT/RIGHT to change)"))
		} else {
			fields = append(fields, valueStyle.Render("  "+displayField(m.fields[index], index == m.focus)))
		}
	}
	formHelp := lipgloss.JoinHorizontal(lipgloss.Left, helpKey("TAB", "move field"), "  ", helpKey("ENTER", "next / save"))
	sections := []string{lipgloss.NewStyle().Border(panelBorder).BorderForeground(lipgloss.Color("#3B7557")).Padding(0, 1).Width(m.contentWidth() - 8).MaxWidth(m.contentWidth() - 4).Render(lipgloss.JoinVertical(lipgloss.Left, fields...)), formHelp, helpKey("ESC", "cancel")}
	if m.message != "" {
		sections = append(sections, messageStyle.Width(m.contentWidth()-8).MaxWidth(m.contentWidth()-4).Render(m.message))
	}
	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m model) contentWidth() int {
	if m.width < 1 {
		return 80
	}
	return max(28, m.width)
}

func (m model) visibleRuleCount() int {
	if m.height < 1 {
		return max(1, len(m.rules))
	}
	rowHeight := 6
	if m.width > 0 && m.width < 56 {
		rowHeight = 8
	}
	return max(1, (m.height-15)/rowHeight)
}

func (m model) visibleRuleRange() (int, int) {
	count := min(len(m.rules), m.visibleRuleCount())
	start := min(max(0, m.listOffset), max(0, len(m.rules)-count))
	return start, start + count
}

func (m *model) keepCursorVisible() {
	if len(m.rules) == 0 {
		m.cursor = 0
		m.listOffset = 0
		return
	}
	m.cursor = min(max(0, m.cursor), len(m.rules)-1)
	count := min(len(m.rules), m.visibleRuleCount())
	if m.cursor < m.listOffset {
		m.listOffset = m.cursor
	}
	if m.cursor >= m.listOffset+count {
		m.listOffset = m.cursor - count + 1
	}
	m.listOffset = min(max(0, m.listOffset), max(0, len(m.rules)-count))
}

func displayField(value string, focused bool) string {
	if value == "" {
		value = "(empty)"
	}
	if focused {
		return value + "_"
	}
	return value
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
	return store.Rule{Name: strings.TrimSpace(fields[0]), PublicPort: publicPort, DestIP: address.String(), DestPort: destPort, Protocol: protocol}, nil
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
