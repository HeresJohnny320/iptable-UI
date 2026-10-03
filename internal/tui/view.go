package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
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

var (
	accentBorder   = lipgloss.Color("#3B7557")
	quietBorder    = lipgloss.Color("#394940")
	selectedBorder = lipgloss.Color("#58B981")
	valueStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#DDE7DF"))
	focusedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#F2C96D")).Bold(true)
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
	case wireGuardResultScreen, helpScreen:
		view = m.wireGuardResultView()
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
		if attempt.cards && (width < minBoxedWidth || total == 0) {
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
	return lipgloss.JoinVertical(lipgloss.Left, layout.header, rules, layout.footer)
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
	if variant == fullHeader {
		items := make([]string, 0, 4)
		if status := m.systemStatus; status != nil {
			items = append(items,
				labelStyle.Render("FORWARDING ")+onOff(status.Forwarding, "ON", "OFF (forwards blocked)"),
				labelStyle.Render("ROUTE ")+addressStyle.Render(status.PublicInterface)+mutedStyle.Render(" -> ")+onOff(status.VPNUp, status.VPNInterface+" UP", status.VPNInterface+" DOWN"),
				labelStyle.Render("APPLY ON BOOT ")+onOff(status.BootRestore, "ON (rules survive reboot)", "OFF (rules lost on reboot)"),
			)
		}
		if m.webControl != nil {
			items = append(items, labelStyle.Render("WEB ")+onOff(m.webControl.Enabled(), m.webControl.StatusText(), m.webControl.StatusText()))
		}
		lines := []string{brand}
		if len(items) > 0 {
			lines = append(lines, flow(innerWidth(width), items...))
		}
		if m.webControl != nil {
			lines = append(lines, labelStyle.Render("TOKEN ")+publicStyle.Render(m.webControl.Token()))
		}
		return panel(width, accentBorder, lines...)
	}
	summary := make([]string, 0, 4)
	if status := m.systemStatus; status != nil {
		summary = append(summary,
			labelStyle.Render("FWD ")+onOff(status.Forwarding, "ON", "OFF"),
			labelStyle.Render("ROUTE ")+addressStyle.Render(status.PublicInterface)+mutedStyle.Render("->")+onOff(status.VPNUp, status.VPNInterface+" UP", status.VPNInterface+" DOWN"),
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
		lines = append(lines, labelStyle.Render("TOKEN ")+publicStyle.Render(m.webControl.Token()))
	}
	if variant == bareHeader {
		return wrap(width, lipgloss.JoinVertical(lipgloss.Left, lines...))
	}
	return panel(width, accentBorder, lines...)
}

func (m model) listFooter(width int, variant helpVariant, messageLines int) string {
	type binding struct{ key, description string }
	bindings := []binding{{"UP/DOWN", "select"}, {"/", "search"}, {"A", "add"}, {"E", "edit"}, {"T", "on/off"}, {"I", "real client IP"}, {"D", "remove"}, {"R", "re-apply rules"}}
	if m.system != nil {
		bindings = append(bindings, binding{"F", "forwarding"}, binding{"B", "apply on boot"})
	}
	// U is always listed so the whiptail look is discoverable; without
	// whiptail installed, pressing it explains how to install it.
	bindings = append(bindings, binding{"G", "WireGuard"}, binding{"W", "web"}, binding{"U", "whiptail look"}, binding{"?", "help"}, binding{"Q", "quit"})
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
	if m.searching {
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
	marker, nameStyle, border := "  ", labelStyle, quietBorder
	if selected {
		marker, nameStyle, border = selectedStyle.Render("> "), selectedStyle, selectedBorder
	}
	inner := innerWidth(width)
	return panel(width, border,
		line(inner, marker+onOff(rule.Enabled, "ENABLED", "DISABLED")+"  "+mutedStyle.Render(fmt.Sprintf("#%d", rule.ID))+"  "+nameStyle.Render(ruleLabel(rule.Name))),
		line(inner, labelStyle.Render("PUBLIC ")+publicStyle.Render(fmt.Sprintf(":%d", rule.PublicPort))+mutedStyle.Render("   ->   TARGET ")+addressStyle.Render(rule.DestIP)+":"+portStyle.Render(fmt.Sprint(rule.DestPort))),
		line(inner, labelStyle.Render("PROTOCOL ")+protocolStyle.Render(strings.ToUpper(rule.Protocol))+labelStyle.Render("   CLIENT IP ")+mutedStyle.Render(clientIPLabel(rule.KeepClientIP))),
	)
}

func clientIPLabel(keep bool) string {
	if keep {
		return "real"
	}
	return "masked"
}

// rowColumns holds column widths so one-line rows line up like a table.
type rowColumns struct{ public, target, protocol int }

func (m model) rowColumns(start, end int) rowColumns {
	var columns rowColumns
	for _, rule := range m.rules[start:end] {
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
	return line(width, text+mutedStyle.Render(fmt.Sprintf("#%d ", rule.ID))+nameStyle.Render(ruleLabel(rule.Name)))
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
	{"RULES", "/", "Search", "Filter the list by port, IP, name or #ID, or by keyword: on/up, off/down, tcp, udp, real, masked. Words combine, e.g. \"udp off\". ENTER keeps the filter, ESC clears it."},
	{"RULES", "A / E", "Add / edit a rule", "Forward a public port on this server to a port on a machine behind the VPN."},
	{"RULES", "T", "Turn a rule on or off", "Off stops the forward right away, including connections that are already open. The rule stays saved."},
	{"RULES", "I", "Real client IP", "Off (default): the server sees every visitor as this VPS. On: it sees each visitor's real address, but replies must route back through the tunnel (README: Keep the Real Client IP)."},
	{"RULES", "D", "Remove a rule", "Deletes it from the firewall and from the saved list."},
	{"FIREWALL", "R", "Re-apply rules", "Rebuilds the firewall from your saved rules. Every change already applies automatically, so you only need this if something else (another script, ufw, Docker, iptables -F) wiped or changed the rules."},
	{"FIREWALL", "F", "IPv4 forwarding", "Lets this server pass traffic on to other machines. Must be ON for any forward to work. The setting survives reboots."},
	{"FIREWALL", "B", "Apply on boot", "Firewall rules live in memory and vanish when the server restarts. When ON, a startup service re-applies your saved rules automatically, so forwards come back after a reboot."},
	{"OTHER", "G", "WireGuard setup", "Creates a WireGuard tunnel config for this VPS and a template for the home side."},
	{"OTHER", "W", "Web UI", "Starts or stops the browser interface. Sign in with the TOKEN shown at the top."},
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
	footer = flow(width, keys...)
	size = max(1, m.heightLimit()-lipgloss.Height(footer)-chrome)
	if size < len(lines) {
		footer = flow(width, helpKey("UP/DOWN", "scroll"), helpKey("ENTER", "return"))
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
func panel(width int, color lipgloss.Color, lines ...string) string {
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
