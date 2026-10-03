package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/HeresJohnny320/iptable-ui/internal/backup"
	"github.com/HeresJohnny320/iptable-ui/internal/firewall"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
	"github.com/HeresJohnny320/iptable-ui/internal/traffic"
	"github.com/HeresJohnny320/iptable-ui/internal/web"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

// Layout sizes are measured from rendered text rather than hard-coded, so
// every screen adapts to the terminal: wide terminals get roomy cards, short
// ones get a condensed header and one-line rows, and nothing ever draws past
// the edges.
const (
	maxContentWidth = 120 // wider than this reads poorly, so content stops growing
	minBoxedWidth   = 50  // below this, rules drop their boxes and use tight one-line rows
	unknownHeight   = 1 << 20
	maxMessageLines = 3
)

type headerVariant int

const (
	fullHeader    headerVariant = iota // every detail, boxed
	compactHeader                      // one-line status summary, boxed
	bareHeader                         // summary without a box, for tiny terminals
	tinyHeader                         // name only
)

type helpVariant int

const (
	fullHelp    helpVariant = iota // styled key badges
	compactHelp                    // plain "A add" pairs
	minimalHelp                    // one line of key letters
)

type listLayout struct {
	header   string
	footer   string
	cards    bool
	capacity int
}

func (m model) View() string {
	var view string
	switch m.activeScreen {
	case addScreen:
		view = m.addView()
	case wireGuardScreen:
		view = m.wireGuardView()
	case wireGuardResultScreen, helpScreen, liveScreen:
		view = m.wireGuardResultView()
	case backupScreen:
		view = m.backupView()
	default:
		view = m.listView()
	}
	return fitScreen(view, m.width, m.height)
}

func (m model) contentWidth() int {
	if m.width < 1 {
		return 80
	}
	return min(m.width, maxContentWidth)
}

func (m model) heightLimit() int {
	if m.height < 1 {
		return unknownHeight
	}
	return m.height
}

// layout picks the richest list layout that still shows a useful number of
// rules: cards under the full header, then one-line rows, then a condensed
// header, then no header box at all.
func (m model) layout() listLayout {
	width := m.contentWidth()
	chrome := 1 // the unboxed title line
	if width >= minBoxedWidth {
		chrome = lipgloss.Height(panel(width, quietBorder, "RULES"))
	}
	cardHeight := lipgloss.Height(m.ruleCard(0, innerWidth(width)))
	total := len(m.rules)
	attempts := []struct {
		variant      headerVariant
		cards        bool
		help         helpVariant
		messageLines int
		need         int
	}{
		{fullHeader, true, fullHelp, maxMessageLines, min(total, 3)},
		{fullHeader, false, fullHelp, maxMessageLines, min(total, 5)},
		{compactHeader, false, fullHelp, maxMessageLines, min(total, 3)},
		{compactHeader, false, compactHelp, 2, min(total, 3)},
		{bareHeader, false, compactHelp, 1, min(total, 2)},
		{bareHeader, false, minimalHelp, 1, 1},
		{tinyHeader, false, minimalHelp, 1, 1},
	}
	var result listLayout
	for _, attempt := range attempts {
		if attempt.cards && (width < minBoxedWidth || total == 0 || m.simple) {
			continue
		}
		footer := m.listFooter(width, attempt.help, attempt.messageLines)
		header := m.header(attempt.variant, width)
		available := m.heightLimit() - lipgloss.Height(header) - lipgloss.Height(footer) - chrome
		unit := 1
		if attempt.cards {
			unit = cardHeight
		}
		result = listLayout{header: header, footer: footer, cards: attempt.cards, capacity: max(1, available/unit)}
		if available/unit >= max(1, attempt.need) {
			break
		}
	}
	return result
}

func (m model) listView() string {
	layout := m.layout()
	width := m.contentWidth()
	boxed := width >= minBoxedWidth
	inner := width
	if boxed {
		inner = innerWidth(width)
	}
	lines := make([]string, 0, layout.capacity+1)
	title := sectionStyle.Render("RULES MENU")
	filter := ""
	if m.query != "" {
		filter = fmt.Sprintf(" matching %q", m.query)
	}
	switch {
	case len(m.rules) == 0 && m.query != "":
		lines = append(lines, line(inner, title), line(inner, mutedStyle.Render(fmt.Sprintf("No rules match %q. Press Esc to clear the search.", m.query))))
	case len(m.rules) == 0:
		lines = append(lines, line(inner, title), line(inner, mutedStyle.Render("No saved forwarding rules yet. Press A to add one.")))
	default:
		start, end := m.visibleRange(layout.capacity)
		if boxed {
			title += mutedStyle.Render(fmt.Sprintf("  Showing %d-%d of %d rules%s", start+1, end, len(m.rules), filter))
			if start > 0 || end < len(m.rules) {
				title += mutedStyle.Render("  (UP/DOWN to scroll)")
			}
		} else {
			title = sectionStyle.Render("RULES") + mutedStyle.Render(fmt.Sprintf(" %d-%d of %d%s", start+1, end, len(m.rules), filter))
		}
		lines = append(lines, line(inner, title))
		columns := m.rowColumns(start, end)
		for index := start; index < end; index++ {
			if layout.cards {
				lines = append(lines, m.ruleCard(index, inner))
			} else {
				lines = append(lines, m.ruleRow(index, inner, boxed, columns))
			}
		}
	}
	rules := lipgloss.JoinVertical(lipgloss.Left, lines...)
	if boxed {
		rules = panel(width, quietBorder, lines...)
	}
	if m.menu != nil {
		// The menu may use all the room between header and footer.
		rules = m.menuView(width, m.heightLimit()-lipgloss.Height(layout.header)-lipgloss.Height(layout.footer))
	}
	return lipgloss.JoinVertical(lipgloss.Left, layout.header, rules, layout.footer)
}

// menuView draws an open menu at most height lines tall, scrolling to keep
// the selected item in view.
func (m model) menuView(width, height int) string {
	inner := innerWidth(width)
	lines := []string{line(inner, brandStyle.Render(" "+m.menu.title+" "))}
	items := make([]string, len(m.menu.items))
	for index, item := range m.menu.items {
		marker, style := "  ", valueStyle
		if index == m.menu.cursor {
			marker, style = selectedStyle.Render("> "), focusedStyle
		}
		items[index] = line(inner, marker+selectedStyle.Render(strings.ToUpper(item.key))+"  "+style.Render(item.label)+mutedStyle.Render("  "+item.hint))
	}
	chrome := lipgloss.Height(panel(width, accentBorder, "")) - 1
	size := max(1, height-1-chrome)
	start := min(max(0, m.menu.cursor-size/2), max(0, len(items)-size))
	lines = append(lines, items[start:min(len(items), start+size)]...)
	return panel(width, accentBorder, lines...)
}

func (m model) header(variant headerVariant, width int) string {
	brandWidth := innerWidth(width)
	if variant == bareHeader {
		brandWidth = width
	}
	brand := flow(brandWidth, brandStyle.Render(" IP TABLE UI "), sectionStyle.Render("PORT FORWARD MANAGER"))
	if variant == tinyHeader {
		return line(width, brandStyle.Render(" IP TABLE UI "))
	}
	if m.simple && variant != bareHeader {
		return m.simpleHeader(variant, width, brand)
	}
	if variant == fullHeader {
		items := make([]string, 0, 4)
		if status := m.systemStatus; status != nil {
			items = append(items,
				labelStyle.Render("FORWARDING ")+onOff(status.Forwarding, "ON", "OFF (forwards blocked)"),
				labelStyle.Render("ROUTE ")+addressStyle.Render(status.PublicInterface)+mutedStyle.Render(" -> ")+onOff(status.VPNUp, status.VPNInterface+" UP", status.VPNInterface+" DOWN")+vpnDetails(status),
				labelStyle.Render("APPLY ON BOOT ")+onOff(status.BootRestore, "ON (rules survive reboot)", "OFF (rules lost on reboot)"),
			)
		}
		if m.webControl != nil {
			items = append(items, labelStyle.Render("WEB ")+m.webStatus())
		}
		for _, adapter := range m.trafficNow.Adapters {
			items = append(items, labelStyle.Render(strings.ToUpper(adapter.Name)+" ")+
				mutedStyle.Render("RX ")+portStyle.Render(traffic.FormatRate(adapter.InPerSecond))+
				mutedStyle.Render(" TX ")+publicStyle.Render(traffic.FormatRate(adapter.OutPerSecond)))
		}
		lines := []string{brand}
		if len(items) > 0 {
			lines = append(lines, flow(innerWidth(width), items...))
		}
		if m.webControl != nil {
			lines = append(lines, m.tokenLine())
		}
		return panel(width, accentBorder, lines...)
	}
	summary := make([]string, 0, 4)
	if status := m.systemStatus; status != nil {
		summary = append(summary,
			labelStyle.Render("FWD ")+onOff(status.Forwarding, "ON", "OFF"),
			labelStyle.Render(strings.ToUpper(vpnName(status))+" ")+onOff(status.VPNUp, status.VPNInterface+" UP", status.VPNInterface+" DOWN"),
			labelStyle.Render("ON BOOT ")+onOff(status.BootRestore, "ON", "OFF"),
		)
	}
	lines := []string{brand}
	if m.webControl != nil {
		summary = append(summary, labelStyle.Render("WEB ")+onOff(m.webControl.Enabled(), "ON", "OFF"))
	}
	if len(summary) > 0 {
		lines = append(lines, flow(brandWidth, summary...))
	}
	if m.webControl != nil {
		// The token is needed to sign in to the web UI, so it is never hidden.
		lines = append(lines, m.tokenLine())
	}
	if variant == bareHeader {
		return wrap(width, lipgloss.JoinVertical(lipgloss.Left, lines...))
	}
	return panel(width, accentBorder, lines...)
}

func (m model) listFooter(width int, variant helpVariant, messageLines int) string {
	type binding struct{ key, description string }
	// Only the everyday keys are listed; M opens a menu with the rest
	// (whose letters still work as shortcuts).
	bindings := []binding{{"UP/DOWN", "select"}, {"ENTER", "actions"}, {"/", "search"}, {"A", "add"}, {"E", "edit"}, {"T", "on/off"}, {"D", "remove"}, {"W", "web"}, {"M", "more"}, {"?", "help"}, {"Q", "quit"}}
	if m.menu != nil {
		bindings = []binding{{"UP/DOWN", "select"}, {"ENTER", "choose"}, {"ESC", "close"}}
	}
	var help string
	switch variant {
	case fullHelp:
		keys := make([]string, len(bindings))
		for index, item := range bindings {
			keys[index] = helpKey(item.key, item.description)
		}
		help = flow(width, keys...)
	case compactHelp:
		keys := make([]string, len(bindings))
		for index, item := range bindings {
			keys[index] = selectedStyle.Render(item.key) + " " + mutedStyle.Render(item.description)
		}
		help = flow(width, keys...)
	default:
		letters := make([]string, 0, len(bindings))
		for _, item := range bindings[1:] {
			letters = append(letters, item.key)
		}
		help = line(width, mutedStyle.Render("Keys: ")+selectedStyle.Render(strings.Join(letters, " ")))
	}
	if m.prompt != nil {
		prompt := selectedStyle.Render(m.prompt.label+": ") + focusedStyle.Render(m.prompt.value+"_") + mutedStyle.Render("  ENTER confirm  ESC cancel")
		if variant == fullHelp {
			prompt = wrap(width, prompt)
		} else {
			prompt = line(width, prompt) // cramped screens: one line
		}
		help = lipgloss.JoinVertical(lipgloss.Left, prompt, help)
	} else if m.searching {
		search := selectedStyle.Render("Search: ") + focusedStyle.Render(m.query+"_") + mutedStyle.Render("  ENTER keep  ESC clear  UP/DOWN browse")
		help = lipgloss.JoinVertical(lipgloss.Left, line(width, search), help)
	} else if m.query != "" {
		help = lipgloss.JoinVertical(lipgloss.Left, line(width, mutedStyle.Render("Filtered by ")+focusedStyle.Render(m.query)+mutedStyle.Render("  / edit  ESC clear")), help)
	}
	return m.withMessage(width, help, messageLines)
}

func (m model) withMessage(width int, footer string, maxLines int) string {
	if m.message == "" {
		return footer
	}
	message := strings.Split(messageStyle.Width(max(1, width-1)).Render(m.message), "\n")
	if len(message) > maxLines {
		message = message[:maxLines]
		message[maxLines-1] = line(width, strings.TrimRight(message[maxLines-1], " ")+"…")
	}
	return lipgloss.JoinVertical(lipgloss.Left, footer, strings.Join(message, "\n"))
}

// ruleCard draws a rule as a bordered card exactly five lines tall.
func (m model) ruleCard(index, width int) string {
	if index >= len(m.rules) {
		return panel(width, quietBorder, "", "", "")
	}
	rule := m.rules[index]
	selected := index == m.cursor
	marker, nameStyle, border := "  ", labelStyle, lipgloss.TerminalColor(quietBorder)
	if selected {
		marker, nameStyle, border = selectedStyle.Render("> "), selectedStyle, selectedBorder
	}
	inner := innerWidth(width)
	return panel(width, border,
		line(inner, marker+onOff(rule.Enabled, "ENABLED", "DISABLED")+"  "+mutedStyle.Render(fmt.Sprintf("#%d", rule.ID))+"  "+nameStyle.Render(ruleLabel(rule.Name))),
		line(inner, labelStyle.Render("PUBLIC ")+publicStyle.Render(fmt.Sprintf(":%d", rule.PublicPort))+mutedStyle.Render("   ->   TARGET ")+addressStyle.Render(rule.DestIP)+":"+portStyle.Render(fmt.Sprint(rule.DestPort))),
		line(inner, labelStyle.Render("PROTOCOL ")+protocolStyle.Render(strings.ToUpper(rule.Protocol))+labelStyle.Render("   CLIENT IP ")+mutedStyle.Render(clientIPLabel(rule.KeepClientIP))+enabledStyle.Render(m.ruleSpeed(rule))),
	)
}

func clientIPLabel(keep bool) string {
	if keep {
		return "real"
	}
	return "masked"
}

// rowColumns holds column widths so one-line rows line up like a table.
type rowColumns struct{ public, target, protocol, name, route int }

func (m model) rowColumns(start, end int) rowColumns {
	var columns rowColumns
	for _, rule := range m.rules[start:end] {
		columns.name = min(24, max(columns.name, ansi.StringWidth(ruleLabel(rule.Name))))
		columns.route = max(columns.route, ansi.StringWidth(simpleRoute(rule)))
		columns.public = max(columns.public, len(fmt.Sprintf(":%d", rule.PublicPort)))
		columns.target = max(columns.target, len(fmt.Sprintf("%s:%d", rule.DestIP, rule.DestPort)))
		columns.protocol = max(columns.protocol, len(rule.Protocol))
	}
	return columns
}

func pad(text string, width int) string {
	return text + strings.Repeat(" ", max(0, width-ansi.StringWidth(text)))
}

// ruleRow draws a rule on one line, route first so a narrow terminal cuts
// the label rather than the address. Roomy rows add spacing; tight rows
// squeeze a whole route into about 40 columns.
func (m model) ruleRow(index, width int, roomy bool, columns rowColumns) string {
	if m.simple {
		return m.simpleRow(index, width, columns)
	}
	rule := m.rules[index]
	marker, nameStyle := "  ", labelStyle
	if index == m.cursor {
		marker, nameStyle = selectedStyle.Render("> "), selectedStyle
	}
	gap, arrow := " ", "->"
	if roomy {
		gap, arrow = "  ", " -> "
	}
	target := addressStyle.Render(rule.DestIP) + ":" + portStyle.Render(fmt.Sprint(rule.DestPort))
	text := marker + onOff(rule.Enabled, "ON ", "OFF") + gap[1:] + " " +
		pad(publicStyle.Render(fmt.Sprintf(":%d", rule.PublicPort)), columns.public) + mutedStyle.Render(arrow) +
		pad(target, columns.target) + gap +
		pad(protocolStyle.Render(strings.ToUpper(rule.Protocol)), columns.protocol) + gap
	if roomy {
		text += pad(mutedStyle.Render(clientIPLabel(rule.KeepClientIP)), len("masked")) + gap
	}
	text += mutedStyle.Render(fmt.Sprintf("#%d ", rule.ID)) + nameStyle.Render(ruleLabel(rule.Name))
	if speed := m.ruleSpeed(rule); speed != "" && roomy && width >= 100 {
		text = line(width-28, text)
		text += strings.Repeat(" ", max(0, width-28-ansi.StringWidth(text))) + enabledStyle.Render(speed)
	}
	return line(width, text)
}

func ruleLabel(name string) string {
	if name == "" {
		return "Unnamed forward"
	}
	return name
}

func (m model) visibleRuleCount() int {
	if m.height < 1 {
		return max(1, len(m.rules))
	}
	return m.layout().capacity
}

func (m model) visibleRuleRange() (int, int) {
	return m.visibleRange(m.visibleRuleCount())
}

// visibleRange returns the window of rules to draw. It always contains the
// cursor, even if the stored offset is stale because the layout changed.
func (m model) visibleRange(capacity int) (int, int) {
	count := min(len(m.rules), max(1, capacity))
	start := min(max(0, m.listOffset), max(0, len(m.rules)-count))
	if m.cursor < start {
		start = m.cursor
	}
	if m.cursor >= start+count {
		start = m.cursor - count + 1
	}
	start = max(0, start)
	return start, start + count
}

func (m *model) keepCursorVisible() {
	if len(m.rules) == 0 {
		m.cursor = 0
		m.listOffset = 0
		return
	}
	m.cursor = min(max(0, m.cursor), len(m.rules)-1)
	m.listOffset, _ = m.visibleRuleRange()
}

type formField struct {
	label string
	value string
	// fixed fields (like the protocol picker) are not free text.
	fixed bool
}

// formView lays out a form to fit the terminal: label above value when there
// is room, then without the notes, then label and value on one line, and on
// very short terminals a window that follows the focused field.
func (m model) formView(title string, fields []formField, notes []string, keys []formKey) string {
	width := m.contentWidth()
	inner := innerWidth(width)
	chrome := lipgloss.Height(panel(width, accentBorder, "")) - 1
	// Shrink the help and message until the title and a field fit.
	var footer string
	var available int
	for _, variant := range []helpVariant{fullHelp, compactHelp, minimalHelp} {
		messageLines := maxMessageLines
		if variant != fullHelp {
			messageLines = 1
		}
		footer = m.withMessage(width, formHelp(width, variant, keys), messageLines)
		available = max(1, m.heightLimit()-lipgloss.Height(footer)-chrome)
		if available >= 2 {
			break
		}
	}
	titleLine := line(inner, brandStyle.Render(title))

	stacked := make([]string, 0, len(fields)*2)
	inline := make([]string, 0, len(fields))
	for index, field := range fields {
		marker, style := "  ", valueStyle
		if index == m.focus {
			marker, style = selectedStyle.Render("> "), focusedStyle
		}
		stacked = append(stacked,
			line(inner, marker+labelStyle.Render(field.label+":")),
			"  "+style.Render(fieldText(field, index == m.focus, inner-2)),
		)
		prefix := marker + labelStyle.Render(field.label+": ")
		inline = append(inline, prefix+style.Render(fieldText(field, index == m.focus, max(4, inner-lipgloss.Width(prefix)))))
	}
	for i := range inline {
		inline[i] = line(inner, inline[i])
	}
	noteLines := make([]string, 0, len(notes))
	for _, note := range notes {
		noteLines = append(noteLines, strings.Split(wrap(inner, mutedStyle.Render(note)), "\n")...)
	}

	var body []string
	if available < 2 {
		return lipgloss.JoinVertical(lipgloss.Left, panel(width, accentBorder, inline[min(m.focus, len(inline)-1)]), footer)
	}
	switch {
	case 1+len(stacked)+len(noteLines) <= available:
		body = append(stacked, noteLines...)
	case 1+len(stacked) <= available:
		body = stacked
	default:
		start := min(max(0, m.focus-(available-1)/2), max(0, len(inline)-(available-1)))
		body = inline[start:min(len(inline), start+max(1, available-1))]
	}
	return lipgloss.JoinVertical(lipgloss.Left, panel(width, accentBorder, append([]string{titleLine}, body...)...), footer)
}

type formKey struct{ key, description string }

func formHelp(width int, variant helpVariant, keys []formKey) string {
	items := make([]string, len(keys))
	for index, item := range keys {
		switch variant {
		case fullHelp:
			items[index] = helpKey(item.key, item.description)
		case compactHelp:
			items[index] = selectedStyle.Render(item.key) + " " + mutedStyle.Render(item.description)
		default:
			items[index] = selectedStyle.Render(item.key)
		}
	}
	if variant == minimalHelp {
		return line(width, strings.Join(items, " "))
	}
	return flow(width, items...)
}

// fieldText shows a field value in width columns. While typing, the end of a
// long value stays visible so the cursor never scrolls out of view.
func fieldText(field formField, focused bool, width int) string {
	value := field.value
	if field.fixed {
		return line(width, value)
	}
	if value == "" {
		value = "(empty)"
	}
	if focused {
		value += "_"
		if ansi.StringWidth(value) > width && width > 1 {
			return "…" + ansi.TruncateLeft(value, ansi.StringWidth(value)-(width-1), "")
		}
	}
	return line(width, value)
}

func (m model) addView() string {
	title := " ADD PORT FORWARD "
	if m.editingID != 0 {
		title = fmt.Sprintf(" EDIT PORT FORWARD #%d ", m.editingID)
	}
	fields := []formField{
		{label: "Label (optional)", value: m.fields[0]},
		{label: "Public port", value: m.fields[1]},
		{label: "Destination IPv4", value: m.fields[2]},
		{label: "Destination port (blank = public)", value: m.fields[3]},
		{label: "Protocol", value: "< " + strings.ToUpper(m.fields[4]) + " >  " + mutedStyle.Render("(LEFT/RIGHT to change)"), fixed: true},
		{label: "Client IP the server sees", value: "< " + clientIPChoice(m.field(5)) + " >  " + mutedStyle.Render("(LEFT/RIGHT)"), fixed: true},
	}
	notes := []string{"VPS tunnel IP works everywhere; the server sees every visitor as the VPS."}
	if m.field(5) == clientIPReal {
		notes = []string{"Real client IP: the server sees each visitor's address, but its replies must route back through the tunnel. On a WireGuard home peer: set AllowedIPs = 0.0.0.0/0 with Table = off, then route replies from this server via the tunnel (see README: Keep the real client IP)."}
	}
	return m.formView(title, fields, notes, []formKey{{"TAB", "move field"}, {"ENTER", "next / save"}, {"ESC", "cancel"}})
}

// field returns a form value, or "" when the form has fewer fields.
func (m model) field(index int) string {
	if index < len(m.fields) {
		return m.fields[index]
	}
	return ""
}

func clientIPChoice(value string) string {
	if value == clientIPReal {
		return "REAL CLIENT IP"
	}
	return "VPS TUNNEL IP (masked)"
}

func (m model) wireGuardView() string {
	labels := []string{"Interface name", "VPS tunnel address/CIDR", "Home peer tunnel address", "Home LAN CIDR", "Home peer public key", "VPS public endpoint", "Listen port"}
	fields := make([]formField, len(labels))
	for index, label := range labels {
		fields[index] = formField{label: label, value: m.fields[index]}
	}
	notes := []string{
		"Creates a protected VPS config and peer template.",
		"On the home peer: umask 077; wg genkey | tee privatekey | wg pubkey > publickey",
		"Paste its public key above. Existing config files are never overwritten. Tunnel activation remains a separate manual step.",
	}
	return m.formView(" WIREGUARD SETUP ", fields, notes, []formKey{{"TAB", "move field"}, {"ENTER", "continue / create"}, {"ESC", "back"}})
}

// helpTopics explains every key in plain words.
var helpTopics = []struct{ section, key, title, text string }{
	{"RULES", "UP/DOWN", "Select a rule", ""},
	{"RULES", "ENTER", "Rule actions", "Opens a menu for the selected rule: edit, turn on or off, real client IP, remove."},
	{"RULES", "M", "More actions", "Opens a menu with everything else: re-apply rules, forwarding, apply on boot, backups, web port, remove all, WireGuard, whiptail look. Each item's letter also works straight from the rule list."},
	{"RULES", "/", "Search", "Filter the list by port, IP, name or #ID, or by keyword: on/up, off/down, tcp, udp, real, masked. Words combine, e.g. \"udp off\". ENTER keeps the filter, ESC clears it."},
	{"RULES", "A / E", "Add / edit a rule", "Forward a public port on this server to a port on a machine behind the VPN."},
	{"RULES", "T", "Turn a rule on or off", "Off stops the forward right away, including connections that are already open. The rule stays saved."},
	{"RULES", "I", "Real client IP", "Off (default): the server sees every visitor as this VPS. On: it sees each visitor's real address, but replies must route back through the tunnel (README: Keep the Real Client IP)."},
	{"RULES", "D", "Remove a rule", "Deletes it from the firewall and from the saved list."},
	{"FIREWALL", "", "Traffic", "The header shows each adapter's speed (RX received, TX sent). A rule's speed shows on wide screens and in its ENTER menu: ▼ flows to your server, ▲ back to visitors."},
	{"FIREWALL", "R", "Re-apply rules", "Rebuilds the firewall from your saved rules. Every change already applies automatically, so you only need this if something else (another script, ufw, Docker, iptables -F) wiped or changed the rules."},
	{"FIREWALL", "F", "IPv4 forwarding", "Lets this server pass traffic on to other machines. Must be ON for any forward to work. The setting survives reboots."},
	{"FIREWALL", "B", "Apply on boot", "Firewall rules live in memory and vanish when the server restarts. When ON, a startup service re-applies your saved rules automatically, so forwards come back after a reboot."},
	{"FIREWALL", "L", "Live firewall rules", "Shows the port forwards as the firewall has them right now, with packet and byte counters (sudo iptables -t nat -L IPTUI_DNAT -n -v --line-numbers). R refreshes."},
	{"RULES", "X", "Remove all rules", "Deletes every rule from the database and the firewall. You must type REMOVE ALL to confirm, and a backup is taken first so you can undo it from Backups (S)."},
	{"OTHER", "S", "Backups", "Your rules and settings are backed up at startup and every 5 minutes while something changed. Back up by hand (N), download one (D gives a link that works for 10 minutes while the web UI is on), or restore any backup (ENTER): it replaces every rule and applies it to the firewall at once. The current state is backed up first, so a restore can be undone."},
	{"OTHER", "P", "Web UI port", "Moves the web UI to another port right away and saves it, so it is used every time iptable-ui starts. Allow the new port in your firewall."},
	{"OTHER", "G", "WireGuard setup", "Creates a WireGuard tunnel config for this VPS and a template for the home side."},
	{"OTHER", "W", "Web UI", "Starts or stops the browser interface. Sign in with the TOKEN shown at the top."},
	{"OTHER", "N", "Simple or detailed view", "Simple shows plain sentences and fewer details; detailed shows interface names, codes and columns. Saved for next time."},
	{"OTHER", "O", "TUI look", "Switches between Classic, Readable (bright, high contrast), Light terminal (for white backgrounds), Ocean and Plain (no colors, for monochrome terminals and screen readers). Saved for next time."},
	{"OTHER", "U", "Whiptail look", "Switches to classic blue whiptail menus (like raspi-config). Needs the whiptail package: apt install whiptail (Fedora: dnf install newt). Choose \"Switch to the full TUI\" there to come back."},
	{"OTHER", "Q", "Quit", "Your rules keep working after you quit."},
}

func helpLines(width int) []string {
	lines := []string{brandStyle.Render(" HELP ")}
	section := ""
	for _, topic := range helpTopics {
		if topic.section != section {
			section = topic.section
			lines = append(lines, "", sectionStyle.Render(section))
		}
		lines = append(lines, line(width, selectedStyle.Render(pad(topic.key, 8))+labelStyle.Render(topic.title)))
		if topic.text != "" {
			for _, text := range strings.Split(wrap(max(1, width-8), mutedStyle.Render(topic.text)), "\n") {
				lines = append(lines, "        "+text)
			}
		}
	}
	return lines
}

// resultLines is the WireGuard result (or help) content wrapped to width,
// one entry per screen line, so it can scroll.
func (m model) resultLines(width int) []string {
	if m.activeScreen == helpScreen {
		return helpLines(width)
	}
	if m.activeScreen == liveScreen {
		return m.liveLines(width)
	}
	blocks := []string{
		brandStyle.Render(" WIREGUARD CONFIG CREATED "),
		labelStyle.Render("VPS CONFIG"), addressStyle.Render(m.wgResult.ConfigPath),
		labelStyle.Render("VPS PUBLIC KEY"), publicStyle.Render(m.wgResult.ServerPublicKey),
		labelStyle.Render("HOME PEER TEMPLATE (set its private key)"),
	}
	for _, configLine := range strings.Split(m.wgResult.PeerConfig, "\n") {
		blocks = append(blocks, protocolStyle.Render(configLine))
	}
	blocks = append(blocks, mutedStyle.Render("Review the config before activation."), selectedStyle.Render("sudo wg-quick up "+m.wgInterface))
	lines := make([]string, 0, len(blocks))
	for _, block := range blocks {
		lines = append(lines, strings.Split(wrap(width, block), "\n")...)
	}
	return lines
}

func (m model) resultWindow() (lines []string, start, size int, footer string) {
	width := m.contentWidth()
	lines = m.resultLines(innerWidth(width))
	chrome := lipgloss.Height(panel(width, accentBorder, "")) - 1
	keys := []string{helpKey("ENTER", "return")}
	if m.activeScreen == liveScreen {
		view := "raw output"
		if m.liveRaw {
			view = "table"
		}
		keys = append(keys, helpKey("R", "refresh"), helpKey("T", view))
	}
	footer = flow(width, keys...)
	size = max(1, m.heightLimit()-lipgloss.Height(footer)-chrome)
	if size < len(lines) {
		footer = flow(width, append([]string{helpKey("UP/DOWN", "scroll")}, keys...)...)
		size = max(1, m.heightLimit()-lipgloss.Height(footer)-chrome)
	}
	start = min(max(0, m.scroll), max(0, len(lines)-size))
	return lines, start, size, footer
}

func (m model) maxResultScroll() int {
	lines, _, size, _ := m.resultWindow()
	return max(0, len(lines)-size)
}

func (m model) wireGuardResultView() string {
	lines, start, size, footer := m.resultWindow()
	return lipgloss.JoinVertical(lipgloss.Left, panel(m.contentWidth(), accentBorder, lines[start:min(len(lines), start+size)]...), footer)
}

// panel draws a rounded box exactly width columns wide. Too narrow for a
// border, it falls back to plain wrapped text.
func panel(width int, color lipgloss.TerminalColor, lines ...string) string {
	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	if width < 8 {
		return wrap(width, content)
	}
	return lipgloss.NewStyle().Border(panelBorder).BorderForeground(color).Padding(0, 1).Width(width - 2).Render(wrap(innerWidth(width), content))
}

// innerWidth is the text width inside a panel of the given width.
func innerWidth(width int) int {
	if width < 8 {
		return max(1, width)
	}
	return width - 4
}

// line cuts styled text to a single line of at most width columns.
func line(width int, text string) string {
	return ansi.Truncate(strings.ReplaceAll(text, "\n", " "), max(0, width), "…")
}

// wrap breaks text at spaces to fit width, splitting words that are longer
// than a whole line (URLs, keys), and pads every line to width.
func wrap(width int, text string) string {
	width = max(1, width)
	lines := strings.Split(ansi.Wrap(text, width, ""), "\n")
	for index, text := range lines {
		lines[index] = line(width, strings.TrimRight(text, " "))
	}
	return lipgloss.NewStyle().Width(width).Render(strings.Join(lines, "\n"))
}

// flow lays items out left to right, starting a new line when the next one
// would not fit, like words in a paragraph.
func flow(width int, items ...string) string {
	lines := make([]string, 0, 2)
	current := ""
	for _, item := range items {
		item = line(width, item)
		switch {
		case current == "":
			current = item
		case lipgloss.Width(current)+2+lipgloss.Width(item) <= width:
			current += "  " + item
		default:
			lines = append(lines, current)
			current = item
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return strings.Join(lines, "\n")
}

// fitScreen is the last line of defense: no line wider than the terminal and
// no more lines than it has rows, keeping the top so the header stays put.
func fitScreen(view string, width, height int) string {
	lines := strings.Split(view, "\n")
	if height > 0 && len(lines) > height {
		lines = lines[:height]
	}
	if width > 0 {
		for index, text := range lines {
			if ansi.StringWidth(text) > width {
				lines[index] = ansi.Truncate(text, width, "")
			}
		}
	}
	return strings.Join(lines, "\n")
}

var backupKinds = map[string]string{
	backup.Startup:    "on startup",
	backup.Auto:       "automatic",
	backup.Manual:     "manual",
	backup.PreRestore: "before a restore",
	backup.PreClear:   "before removing all",
	backup.Uploaded:   "uploaded",
}

// backupView lists backups, keeping the selected one in view.
func (m model) backupView() string {
	width := m.contentWidth()
	inner := innerWidth(width)
	keys := []formKey{{"UP/DOWN", "select"}, {"N", "back up now"}, {"D", "download"}, {"ENTER", "restore"}, {"I", "import file"}, {"O", "folder"}, {"ESC", "back"}}
	chrome := lipgloss.Height(panel(width, accentBorder, "")) - 1
	// Shrink the help and message until at least one backup fits.
	var footer string
	var available int
	for _, variant := range []helpVariant{fullHelp, compactHelp, minimalHelp} {
		messageLines := maxMessageLines
		if variant != fullHelp {
			messageLines = 1
		}
		help := formHelp(width, variant, keys)
		if m.prompt != nil {
			prompt := selectedStyle.Render(m.prompt.label+": ") + focusedStyle.Render(m.prompt.value+"_") + mutedStyle.Render("  ENTER confirm  ESC cancel")
			if variant == fullHelp {
				prompt = wrap(width, prompt)
			} else {
				prompt = line(width, prompt)
			}
			help = lipgloss.JoinVertical(lipgloss.Left, prompt, help)
		}
		footer = m.withMessage(width, help, messageLines)
		available = m.heightLimit() - lipgloss.Height(footer) - chrome - 1 // title
		if available >= 3 {
			break
		}
	}
	folder := ""
	if m.backups != nil {
		folder = "Saved in " + m.backups.Folder() + ". "
	}
	intro := strings.Split(wrap(inner, mutedStyle.Render(folder+"Taken at startup and every 5 minutes while something changed. Restoring replaces every rule and applies it at once; the current state is backed up first.")), "\n")
	if available-len(intro) < 3 {
		intro = nil // too short: keep the list, drop the explanation
	}
	rows := make([]string, 0, len(m.backupList))
	for index, info := range m.backupList {
		marker, style := "  ", valueStyle
		if index == m.backupCursor {
			marker, style = selectedStyle.Render("> "), focusedStyle
		}
		rows = append(rows, line(inner, marker+style.Render(info.Time.Local().Format("2006-01-02 15:04"))+"  "+
			pad(labelStyle.Render(fmt.Sprintf("%d rules", info.Rules)), 9)+"  "+mutedStyle.Render(backupKinds[info.Kind])))
	}
	if len(rows) == 0 {
		rows = append(rows, mutedStyle.Render("No backups yet. Press N to make one."))
	}
	size := max(1, available-len(intro))
	start := min(max(0, m.backupCursor-size/2), max(0, len(rows)-size))
	lines := append([]string{line(inner, brandStyle.Render(" BACKUPS ")+mutedStyle.Render(fmt.Sprintf("  %d saved", len(m.backupList))))}, intro...)
	lines = append(lines, rows[start:min(len(rows), start+size)]...)
	return lipgloss.JoinVertical(lipgloss.Left, panel(width, accentBorder, lines...), footer)
}

// webStatus is the web UI status with its address masked unless revealed;
// the address is a link to the full sign-in URL, so it can still be opened.
func (m model) webStatus() string {
	status := m.webControl.StatusText()
	base := strings.TrimSuffix(m.webControl.URL(), "/")
	shown := base
	if !m.reveal {
		shown = strings.TrimSuffix(web.MaskURL(base+"/"), "/")
	}
	before, after, found := strings.Cut(status, base)
	if !found {
		return onOff(m.webControl.Enabled(), status, status)
	}
	address := shown
	if m.webControl.Enabled() {
		address = hyperlink(m.webControl.SignInURL(), shown)
	}
	return onOff(m.webControl.Enabled(), before, before) + address + onOff(m.webControl.Enabled(), after, after)
}

func (m model) tokenLine() string {
	token := web.MaskToken(m.webControl.Token())
	hint := "  C copy sign-in link  V show"
	if m.reveal {
		token = m.webControl.Token()
		hint = "  C copy sign-in link  V hide"
	}
	return labelStyle.Render("TOKEN ") + publicStyle.Render(token) + mutedStyle.Render(hint)
}

// hyperlink makes text a clickable link (OSC 8) in terminals that support
// it; others just show the text. Plain-text terminals get no escape codes.
func hyperlink(target, text string) string {
	if lipgloss.ColorProfile() == termenv.Ascii {
		return text
	}
	return "\x1b]8;;" + target + "\x1b\\" + text + "\x1b]8;;\x1b\\"
}

// liveLines shows the live firewall rules as a colored table, or as the raw
// iptables output when the user asks for it (or it cannot be parsed).
func (m model) liveLines(width int) []string {
	lines := []string{brandStyle.Render(" LIVE FIREWALL RULES "), mutedStyle.Render("sudo " + strings.Join(firewall.LiveRulesCommand, " ")), ""}
	table, parsed := firewall.ParseLiveRules(m.liveOutput)
	if m.liveRaw || !parsed {
		for _, text := range strings.Split(strings.TrimRight(m.liveOutput, "\n"), "\n") {
			lines = append(lines, strings.Split(wrap(width, text), "\n")...)
		}
		return lines
	}
	if len(table.Entries) == 0 {
		return append(lines, mutedStyle.Render("No forwards are active in the firewall. Enabled rules appear here once applied."))
	}
	active := 0
	for _, entry := range table.Entries {
		if entry.Active {
			active++
		}
	}
	lines = append(lines, sectionStyle.Render(table.Chain)+mutedStyle.Render(fmt.Sprintf("  %d rules, %d with traffic", len(table.Entries), active)))
	var columns struct{ public, target, in, packets, bytes int }
	for _, entry := range table.Entries {
		columns.public = max(columns.public, len(entry.PublicPort)+1)
		columns.target = max(columns.target, len(entry.ForwardTo))
		columns.in = max(columns.in, len(entry.In))
		columns.packets = max(columns.packets, len(entry.Packets), len("PACKETS"))
		columns.bytes = max(columns.bytes, len(readableCounter(entry.Bytes)), len("DATA"))
	}
	lines = append(lines, line(width, labelStyle.Render(pad("#", 4)+pad("PROTO", 6)+pad("FORWARD", columns.public+4+columns.target+2)+pad("IN", columns.in+2)+
		padLeft("PACKETS", columns.packets)+"  "+padLeft("DATA", columns.bytes))))
	for _, entry := range table.Entries {
		counters := padLeft(entry.Packets, columns.packets) + "  " + padLeft(readableCounter(entry.Bytes), columns.bytes)
		traffic := mutedStyle.Render(counters)
		if entry.Active {
			traffic = enabledStyle.Render(counters)
		}
		forward := pad(publicStyle.Render(":"+entry.PublicPort), columns.public) + mutedStyle.Render(" -> ") + pad(addressStyle.Render(entry.ForwardTo), columns.target)
		if entry.ForwardTo == "" {
			forward = pad(labelStyle.Render(entry.Target+" "+entry.Extra), columns.public+4+columns.target)
		}
		row := mutedStyle.Render(pad(strconv.Itoa(entry.Number), 4)) + pad(protocolStyle.Render(entry.Protocol), 6) + forward + "  " +
			pad(labelStyle.Render(entry.In), columns.in) + "  " + traffic
		if entry.Extra != "" && entry.ForwardTo != "" {
			row += mutedStyle.Render("  " + entry.Extra)
		}
		lines = append(lines, strings.Split(wrap(width, row), "\n")...)
	}
	return lines
}

// vpnName is the kind of VPN, or "VPN" when it is not known.
func vpnName(status *system.Status) string {
	if status.VPNKind == "" {
		return "VPN"
	}
	return status.VPNKind
}

// vpnDetails names the VPN and this server's address on it, for example
// " (Tailscale 100.64.0.1)".
func vpnDetails(status *system.Status) string {
	details := vpnName(status)
	if status.VPNAddress != "" {
		details += " " + status.VPNAddress
	}
	return mutedStyle.Render(" (" + details + ")")
}

func padLeft(text string, width int) string {
	return strings.Repeat(" ", max(0, width-ansi.StringWidth(text))) + text
}

// readableCounter turns iptables' byte counts ("2520", "73K", "1.2M") into
// units people read ("2.5 KB", "73 KB", "1.2 MB").
func readableCounter(value string) string {
	multiplier := 1.0
	switch {
	case strings.HasSuffix(value, "K"):
		multiplier = 1e3
	case strings.HasSuffix(value, "M"):
		multiplier = 1e6
	case strings.HasSuffix(value, "G"):
		multiplier = 1e9
	case strings.HasSuffix(value, "T"):
		multiplier = 1e12
	}
	number, err := strconv.ParseFloat(strings.TrimRight(value, "KMGT"), 64)
	if err != nil {
		return value
	}
	return traffic.FormatBytes(number * multiplier)
}

// simpleHeader states the gateway's condition in plain sentences.
func (m model) simpleHeader(variant headerVariant, width int, brand string) string {
	lines := []string{brand}
	if status := m.systemStatus; status != nil {
		vpn := vpnName(status)
		if variant == compactHeader {
			lines = append(lines, flow(innerWidth(width),
				onOff(status.Forwarding, "Forwarding on", "Forwarding OFF"),
				onOff(status.VPNUp, vpn+" connected", vpn+" down"),
				onOff(status.BootRestore, "Rules kept after reboot", "Rules lost after reboot")))
		} else {
			connected := "Connected through " + vpn
			if status.VPNAddress != "" {
				connected += " (this server is " + status.VPNAddress + " on it)"
			}
			lines = append(lines,
				onOff(status.Forwarding, "Forwarding is on.", "Forwarding is off, so forwards do not work (press F to turn it on)."),
				onOff(status.VPNUp, connected+".", vpn+" ("+status.VPNInterface+") is down, so forwards cannot reach home."),
				onOff(status.BootRestore, "After a reboot: your rules come back automatically.", "After a reboot: rules are lost until you open iptable-ui (press B to fix)."),
			)
		}
	}
	if m.webControl != nil {
		webLine := mutedStyle.Render("Web UI is off (press W to start it).")
		if m.webControl.Enabled() {
			webLine = enabledStyle.Render("Web UI is on") + mutedStyle.Render(" at ") + m.webAddressLink() + mutedStyle.Render(". C copies the sign-in link.")
		}
		lines = append(lines, webLine)
	}
	if variant == fullHeader && len(m.trafficNow.Adapters) > 0 {
		parts := make([]string, 0, len(m.trafficNow.Adapters))
		for _, adapter := range m.trafficNow.Adapters {
			name := "Internet"
			if m.systemStatus != nil && adapter.Name == m.systemStatus.VPNInterface {
				name = vpnName(m.systemStatus)
			}
			parts = append(parts, labelStyle.Render(name+" ")+portStyle.Render("↓ "+traffic.FormatRate(adapter.InPerSecond))+" "+publicStyle.Render("↑ "+traffic.FormatRate(adapter.OutPerSecond)))
		}
		lines = append(lines, flow(innerWidth(width), parts...))
	}
	if m.webControl != nil && m.reveal {
		lines = append(lines, m.tokenLine())
	}
	return panel(width, accentBorder, lines...)
}

// webAddressLink is the web UI address, masked unless revealed, linking to
// the full sign-in URL.
func (m model) webAddressLink() string {
	base := strings.TrimSuffix(m.webControl.URL(), "/")
	shown := base
	if !m.reveal {
		shown = strings.TrimSuffix(web.MaskURL(base+"/"), "/")
	}
	return hyperlink(m.webControl.SignInURL(), addressStyle.Render(shown))
}

// simpleRoute is "port 25565 → 10.66.0.2:25565": the port this server
// listens on, then the destination address and port.
func simpleRoute(rule store.Rule) string {
	return fmt.Sprintf("port %d → %s:%d", rule.PublicPort, rule.DestIP, rule.DestPort)
}

func protocolWords(protocol string) string {
	if protocol == "both" {
		return "TCP+UDP"
	}
	return strings.ToUpper(protocol)
}

// simpleRow is a rule in plain words: "On   Minecraft   port 25565 → 10.66.0.2:25565   TCP+UDP".
// Narrow screens put the route first, so a cut takes the name instead.
func (m model) simpleRow(index, width int, columns rowColumns) string {
	rule := m.rules[index]
	marker, nameStyle := "  ", valueStyle
	if index == m.cursor {
		marker, nameStyle = selectedStyle.Render("> "), selectedStyle
	}
	name := pad(nameStyle.Render(line(columns.name, ruleLabel(rule.Name))), columns.name)
	route := pad(addressStyle.Render(simpleRoute(rule)), columns.route)
	text := marker + onOff(rule.Enabled, "On ", "Off") + "  " + name + "  " + route + "  " + protocolStyle.Render(protocolWords(rule.Protocol))
	if width < 60 {
		text = marker + onOff(rule.Enabled, "On ", "Off") + " " + route + " " + protocolStyle.Render(protocolWords(rule.Protocol)) + " " + nameStyle.Render(ruleLabel(rule.Name))
	}
	if rule.KeepClientIP {
		text += mutedStyle.Render("  real IPs")
	}
	if speed := m.ruleSpeed(rule); speed != "" && width >= 100 {
		text = line(width-28, text)
		text += strings.Repeat(" ", max(0, width-28-ansi.StringWidth(text))) + enabledStyle.Render(speed)
	}
	return line(width, text)
}
