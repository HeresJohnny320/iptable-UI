package tui

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/backup"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
	"github.com/HeresJohnny320/iptable-ui/internal/traffic"
	"github.com/HeresJohnny320/iptable-ui/internal/web"
	wgsetup "github.com/HeresJohnny320/iptable-ui/internal/wireguard"
	"github.com/aymanbagabas/go-osc52/v2"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/muesli/termenv"
)

var panelBorder = lipgloss.RoundedBorder()

type screen int

const (
	listScreen screen = iota
	addScreen
	wireGuardScreen
	wireGuardResultScreen
	helpScreen
	backupScreen
	liveScreen
)

type trafficLoaded traffic.Snapshot

type liveLoaded struct {
	output string
	err    error
}

// BackupControl lists, creates and restores database backups.
type BackupControl interface {
	List() ([]backup.Info, error)
	Create(context.Context, string) (backup.Info, bool, error)
	Restore(context.Context, string) error
	Path(string) (string, error)
	Import(io.Reader) (backup.Info, error)
	MoveTo(string) error
	Folder() string
}

// menu is a short list of actions shown over the rule list: the actions for
// one rule (ENTER) or the less common actions (M).
type menu struct {
	title  string
	items  []menuItem
	cursor int
}

// menuItem runs the same action as pressing key on the rule list.
type menuItem struct {
	key, label, hint string
}

// textPrompt is a one-line question at the bottom of the rule list.
type textPrompt struct {
	label  string
	value  string
	submit func(m *model, value string) tea.Cmd
}

const removeAllConfirmation = "REMOVE ALL"

type backupsLoaded struct {
	backups []backup.Info
	err     error
}

type backupFinished struct {
	message string
	err     error
}

type WebControl interface {
	Toggle() (bool, error)
	Enabled() bool
	Address() string
	Token() string
	StatusText() string
	Port() int
	SetPort(int) (string, error)
	DownloadLink(name string) (string, error)
	URL() string
	SignInURL() string
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
	backups      BackupControl
	traffic      TrafficSource
	trafficNow   traffic.Snapshot
	settings     Settings
	themeName    string
	// simple shows plain sentences instead of the detailed codes and columns.
	simple       bool
	backupList   []backup.Info
	backupCursor int
	liveOutput   string
	// reveal shows the web UI address and token unmasked.
	reveal bool
	// liveRaw shows the live firewall rules as plain iptables output.
	liveRaw bool
	// rules is what the list shows: allRules filtered by query.
	rules    []store.Rule
	allRules []store.Rule
	query    string
	// searching is true while the search line has keyboard focus.
	searching    bool
	prompt       *textPrompt
	menu         *menu
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
// TrafficSource reports measured network speeds.
type TrafficSource interface {
	Snapshot() traffic.Snapshot
}

// Settings stores TUI preferences such as its look.
type Settings interface {
	Setting(context.Context, string) (string, error)
	SetSetting(context.Context, string, string) error
}

// Options are what the TUI manages. A nil field turns its feature off.
type Options struct {
	Service       app.Service
	Web           WebControl
	WireGuard     WireGuardSetup
	Host          SystemControl
	Backups       BackupControl
	Traffic       TrafficSource
	Settings      Settings
	AllowWhiptail bool
}

// themeSetting remembers the TUI look and viewSetting the detailed or
// simple view, in the database.
const (
	themeSetting = "tui.theme"
	viewSetting  = "tui.view"
)

func Run(options Options) (bool, error) {
	lipgloss.SetColorProfile(colorProfile(lipgloss.ColorProfile(), os.Getenv, term.IsTerminal(os.Stdout.Fd())))
	theme := tuiThemes[0]
	if options.Settings != nil {
		if saved, err := options.Settings.Setting(context.Background(), themeSetting); err == nil {
			theme = findTheme(saved)
		}
	}
	applyTheme(theme)
	simple := false
	if options.Settings != nil {
		if view, err := options.Settings.Setting(context.Background(), viewSetting); err == nil {
			simple = view == "simple"
		}
	}
	program := tea.NewProgram(model{service: options.Service, webControl: options.Web, wgSetup: options.WireGuard, system: options.Host, backups: options.Backups,
		traffic: options.Traffic, settings: options.Settings, themeName: theme.name, simple: simple, allowWhiptail: options.AllowWhiptail}, tea.WithAltScreen())
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
	return tea.Batch(m.loadRules, m.loadSystem, m.loadTraffic, scheduleRulesRefresh())
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
			return m, tea.Batch(m.loadRules, m.loadSystem, m.loadTraffic, scheduleRulesRefresh())
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
	case trafficLoaded:
		m.trafficNow = traffic.Snapshot(message)
		return m, nil
	case liveLoaded:
		if message.err != nil {
			m.message = message.err.Error()
			return m, nil
		}
		m.liveOutput = message.output
		if m.activeScreen != liveScreen {
			m.activeScreen = liveScreen
			m.scroll = 0
		}
		m.message = ""
		return m, nil
	case backupsLoaded:
		if message.err != nil {
			m.message = message.err.Error()
			return m, nil
		}
		m.backupList = message.backups
		m.backupCursor = min(m.backupCursor, max(0, len(m.backupList)-1))
		return m, nil
	case backupFinished:
		if message.err != nil {
			m.message = message.err.Error()
		} else {
			m.message = message.message
		}
		return m, tea.Batch(m.loadBackups, m.loadRules, m.loadSystem)
	case tea.KeyMsg:
		if m.activeScreen == backupScreen {
			return m.updateBackups(message)
		}
		if m.activeScreen == addScreen {
			return m.updateAdd(message)
		}
		if m.activeScreen == wireGuardScreen {
			return m.updateWireGuard(message)
		}
		if m.activeScreen == wireGuardResultScreen || m.activeScreen == helpScreen || m.activeScreen == liveScreen {
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
	if m.prompt != nil {
		return m.updatePrompt(key)
	}
	if m.menu != nil {
		return m.updateMenu(key)
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
			m.message = "Web UI is " + m.webControl.StatusText()
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
	case "p":
		if m.webControl == nil {
			m.message = "Web UI control is unavailable."
			break
		}
		m.prompt = &textPrompt{label: "Web UI port (saved for next time)", value: strconv.Itoa(m.webControl.Port()), submit: submitPort}
		m.message = ""
	case "x":
		total := len(m.allRulesOrShown())
		if total == 0 {
			m.message = "There are no rules to remove."
			break
		}
		m.prompt = &textPrompt{label: fmt.Sprintf("Remove all %d rules? A backup is taken first. Type %s", total, removeAllConfirmation), submit: submitRemoveAll}
		m.message = ""
	case "s":
		if m.backups == nil {
			m.message = "Backups are unavailable."
			break
		}
		m.activeScreen = backupScreen
		m.backupCursor = 0
		m.message = ""
		return m, m.loadBackups
	case "enter":
		if len(m.rules) > 0 {
			m.menu = m.ruleMenu(m.rules[m.cursor])
			m.message = ""
		}
	case "m":
		m.menu = m.moreMenu()
		m.message = ""
	case "l":
		m.message = "Reading the firewall..."
		return m, m.loadLive
	case "n":
		m.simple = !m.simple
		view, message := "detailed", "Detailed view: interface names, codes and columns. Press N for the simple view."
		if m.simple {
			view, message = "simple", "Simple view: plain words, fewer details. Press N for the detailed view."
		}
		m.message = message
		m.keepCursorVisible()
		if m.settings != nil {
			settings := m.settings
			return m, func() tea.Msg {
				if err := settings.SetSetting(context.Background(), viewSetting, view); err != nil {
					return actionFinished{err: fmt.Errorf("the view changed but could not be saved: %w", err)}
				}
				return nil
			}
		}
	case "o":
		theme := nextTheme(m.themeName)
		applyTheme(theme)
		m.themeName = theme.name
		m.message = fmt.Sprintf("TUI look: %s. Press O again for the next look.", theme.label)
		if m.settings != nil {
			settings := m.settings
			return m, func() tea.Msg {
				if err := settings.SetSetting(context.Background(), themeSetting, theme.name); err != nil {
					return actionFinished{err: fmt.Errorf("the look changed but could not be saved: %w", err)}
				}
				return nil
			}
		}
	case "v":
		if m.webControl == nil {
			break
		}
		m.reveal = !m.reveal
		m.message = "Web address and token are hidden again."
		if m.reveal {
			m.message = "Web address and token are shown. Press V to hide them again."
		}
	case "c":
		if m.webControl == nil {
			break
		}
		copyToClipboard(m.webControl.SignInURL())
		m.message = "Sign-in link copied to your clipboard (in terminals that support it, like Windows Terminal or iTerm2; in PuTTY press V to show it and select it)."
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

func (m model) loadBackups() tea.Msg {
	if m.backups == nil {
		return nil
	}
	backups, err := m.backups.List()
	return backupsLoaded{backups: backups, err: err}
}

func (m model) updateBackups(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.prompt != nil {
		return m.updatePrompt(key)
	}
	if m.confirm != nil {
		pending := m.confirm
		m.confirm = nil
		if keyName(key) != "y" {
			m.message = "Cancelled."
			return m, nil
		}
		return m, func() tea.Msg {
			notice, err := pending.action(context.Background())
			return backupFinished{message: withNotice(pending.success, notice), err: err}
		}
	}
	switch keyName(key) {
	case "ctrl+c":
		return m, tea.Quit
	case "esc", "q":
		m.activeScreen = listScreen
		m.message = ""
	case "up", "k":
		m.backupCursor = max(0, m.backupCursor-1)
	case "down", "j":
		m.backupCursor = min(max(0, len(m.backupList)-1), m.backupCursor+1)
	case "d":
		if len(m.backupList) == 0 {
			break
		}
		chosen := m.backupList[m.backupCursor]
		path, err := m.backups.Path(chosen.Name)
		if err != nil {
			m.message = err.Error()
			break
		}
		copyHint := fmt.Sprintf("Copy it with: scp root@<this-server>:%s .", path)
		if m.webControl == nil || !m.webControl.Enabled() {
			m.message = "Turn on the web UI (W) to get a download link. " + copyHint
			break
		}
		link, err := m.webControl.DownloadLink(chosen.Name)
		if err != nil {
			m.message = err.Error() + ". " + copyHint
			break
		}
		m.message = fmt.Sprintf("Download link (works for %d minutes, no sign-in needed): %s  %s", int(web.LinkLifetime.Minutes()), link, copyHint)
	case "i":
		m.prompt = &textPrompt{label: "Import a backup file on this server (full path)", submit: submitImport}
		m.message = ""
	case "o":
		m.prompt = &textPrompt{label: "Backup folder", value: m.backups.Folder(), submit: submitFolder}
		m.message = ""
	case "n":
		m.message = "Backing up..."
		return m, func() tea.Msg {
			info, _, err := m.backups.Create(context.Background(), backup.Manual)
			return backupFinished{message: fmt.Sprintf("Backup saved (%d rules).", info.Rules), err: err}
		}
	case "enter", "r":
		if len(m.backupList) == 0 {
			break
		}
		chosen := m.backupList[m.backupCursor]
		when := chosen.Time.Local().Format("2006-01-02 15:04:05")
		m.confirm = &pendingAction{
			success: fmt.Sprintf("Restored the backup from %s; the firewall now matches it", when),
			action: func(ctx context.Context) (string, error) {
				return "", m.backups.Restore(ctx, chosen.Name)
			},
		}
		m.message = fmt.Sprintf("Restore the backup from %s? All %d current rules are replaced by its %d and applied now (the current state is backed up first). Press y to confirm, any other key to cancel.", when, len(m.allRulesOrShown()), chosen.Rules)
	}
	return m, nil
}

// allRulesOrShown is every saved rule, even when a search filters the list.
func (m model) allRulesOrShown() []store.Rule {
	if m.allRules != nil {
		return m.allRules
	}
	return m.rules
}

func (m model) loadTraffic() tea.Msg {
	if m.traffic == nil {
		return nil
	}
	return trafficLoaded(m.traffic.Snapshot())
}

func (m model) loadLive() tea.Msg {
	output, err := m.service.LiveRules(context.Background())
	return liveLoaded{output: output, err: err}
}

func (m model) updateResult(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch keyName(key) {
	case "r":
		if m.activeScreen == liveScreen {
			return m, m.loadLive
		}
	case "t":
		if m.activeScreen == liveScreen {
			m.liveRaw = !m.liveRaw
			m.scroll = 0
		}
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

func (m model) ruleMenu(rule store.Rule) *menu {
	toggle, clientIP := "Turn off", "Pass the real client IP"
	if !rule.Enabled {
		toggle = "Turn on"
	}
	if rule.KeepClientIP {
		clientIP = "Mask the client IP again"
	}
	return &menu{
		title: fmt.Sprintf("Rule #%d  %s  :%d -> %s:%d %s%s", rule.ID, ruleLabel(rule.Name), rule.PublicPort, rule.DestIP, rule.DestPort, strings.ToUpper(rule.Protocol), m.ruleSpeed(rule)),
		items: []menuItem{
			{"e", "Edit", "change its ports, address or protocol"},
			{"t", toggle, "applies right away"},
			{"i", clientIP, "what the server sees as the visitor's address"},
			{"d", "Remove", "asks first"},
		},
	}
}

func (m model) moreMenu() *menu {
	items := make([]menuItem, 0, 9)
	if len(m.rules) > 0 {
		items = append(items, menuItem{"i", "Real client IP for the selected rule", "show visitors' real addresses to the server"})
	}
	items = append(items,
		menuItem{"r", "Re-apply rules", "rebuild the firewall if another tool wiped it"},
		menuItem{"l", "Live firewall rules", "what iptables is forwarding right now"})
	if m.system != nil && m.systemStatus != nil {
		items = append(items,
			menuItem{"f", "IPv4 forwarding: turn " + offOn(m.systemStatus.Forwarding), "must be on for forwards to work"},
			menuItem{"b", "Apply on boot: turn " + offOn(m.systemStatus.BootRestore), "bring rules back after a reboot"},
		)
	}
	if m.backups != nil {
		items = append(items, menuItem{"s", "Backups", "back up, download or restore"})
	}
	if m.webControl != nil {
		items = append(items,
			menuItem{"c", "Copy web sign-in link", "to your clipboard, signs you in when opened"},
			menuItem{"v", map[bool]string{true: "Hide", false: "Show"}[m.reveal] + " web address and token", "they are masked on screen by default"},
			menuItem{"p", "Web UI port", "move the web UI to another port"},
		)
	}
	items = append(items, menuItem{"x", "Remove all rules", "type REMOVE ALL to confirm; backed up first"})
	// WireGuard setup only matters when WireGuard is the VPN, or none is up.
	if m.systemStatus == nil || m.systemStatus.VPNKind == "WireGuard" || !m.systemStatus.VPNUp {
		items = append(items, menuItem{"g", "WireGuard setup", "create a tunnel config for this VPS"})
	}
	items = append(items,
		menuItem{"n", map[bool]string{true: "Detailed view", false: "Simple view"}[m.simple], map[bool]string{true: "show interface names, codes and columns", false: "plain words, fewer details"}[m.simple]},
		menuItem{"o", fmt.Sprintf("TUI look: %s (next: %s)", findTheme(m.themeName).label, nextTheme(m.themeName).label), "colors and contrast, saved for next time"},
		menuItem{"u", "Whiptail look", "classic blue menus"})
	return &menu{title: "More actions", items: items}
}

// copyToClipboard puts text on the user's local clipboard with the OSC 52
// terminal sequence, which also works over SSH. Inside tmux or screen the
// sequence is wrapped so it reaches the outer terminal.
func copyToClipboard(text string) {
	sequence := osc52.New(text)
	switch {
	case os.Getenv("TMUX") != "":
		sequence = sequence.Tmux()
	case strings.HasPrefix(os.Getenv("TERM"), "screen"):
		sequence = sequence.Screen()
	}
	_, _ = sequence.WriteTo(os.Stderr)
}

// ruleSpeed is " ▼ 1.2 KB/s ▲ 300 KB/s" for an enabled rule with measured
// traffic: ▼ flows to your server, ▲ back to visitors.
func (m model) ruleSpeed(rule store.Rule) string {
	if !rule.Enabled {
		return ""
	}
	rate, ok := m.trafficNow.ForwardRate(rule.PublicPort, rule.Protocol, rule.DestIP)
	if !ok {
		return ""
	}
	return fmt.Sprintf("  ▼ %s ▲ %s", traffic.FormatRate(rate.InPerSecond), traffic.FormatRate(rate.OutPerSecond))
}

// offOn names the state a toggle switches to.
func offOn(currentlyOn bool) string {
	if currentlyOn {
		return "off"
	}
	return "on"
}

// updateMenu moves through a menu; ENTER or an item's letter runs it, as if
// that letter were pressed on the rule list.
func (m model) updateMenu(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	current := *m.menu
	name := keyName(key)
	switch name {
	case "ctrl+c":
		return m, tea.Quit
	case "esc", "q", "m":
		m.menu = nil
		return m, nil
	case "up", "k":
		current.cursor = max(0, current.cursor-1)
		m.menu = &current
		return m, nil
	case "down", "j":
		current.cursor = min(len(current.items)-1, current.cursor+1)
		m.menu = &current
		return m, nil
	case "enter":
		name = current.items[current.cursor].key
	}
	for _, item := range current.items {
		if item.key == name {
			m.menu = nil
			return m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(item.key)})
		}
	}
	return m, nil
}

func (m model) updatePrompt(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc:
		m.prompt = nil
		m.message = "Cancelled."
	case tea.KeyEnter:
		prompt := *m.prompt
		m.prompt = nil
		return m, prompt.submit(&m, strings.TrimSpace(prompt.value))
	case tea.KeyBackspace, tea.KeyCtrlH, tea.KeyDelete:
		if runes := []rune(m.prompt.value); len(runes) > 0 {
			m.prompt = &textPrompt{label: m.prompt.label, value: string(runes[:len(runes)-1]), submit: m.prompt.submit}
		}
	case tea.KeySpace:
		m.prompt = &textPrompt{label: m.prompt.label, value: m.prompt.value + " ", submit: m.prompt.submit}
	case tea.KeyRunes:
		m.prompt = &textPrompt{label: m.prompt.label, value: m.prompt.value + string(key.Runes), submit: m.prompt.submit}
	}
	return m, nil
}

func submitPort(m *model, value string) tea.Cmd {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		m.message = "Port must be a number from 1 to 65535."
		return nil
	}
	if port == m.webControl.Port() {
		m.message = fmt.Sprintf("The web UI already uses port %d.", port)
		return nil
	}
	m.message = fmt.Sprintf("Moving the web UI to port %d...", port)
	web := m.webControl
	return func() tea.Msg {
		url, err := web.SetPort(port)
		if err != nil && url == "" {
			return actionFinished{err: err}
		}
		message := fmt.Sprintf("Web UI port is now %d (saved for next time)", port)
		if web.Enabled() {
			message = fmt.Sprintf("Web UI moved to %s (saved for next time)", url)
		}
		if err != nil {
			message += ". " + err.Error()
		}
		return actionFinished{message: message}
	}
}

func submitImport(m *model, value string) tea.Cmd {
	if value == "" {
		m.message = "No file given."
		return nil
	}
	backups := m.backups
	m.message = "Importing..."
	return func() tea.Msg {
		file, err := os.Open(value)
		if err != nil {
			return backupFinished{err: fmt.Errorf("open %s: %w", value, err)}
		}
		defer file.Close()
		info, err := backups.Import(file)
		return backupFinished{message: fmt.Sprintf("Imported %s (%d rules). It is at the top of the list; press ENTER on it to restore", filepath.Base(value), info.Rules), err: err}
	}
}

func submitFolder(m *model, value string) tea.Cmd {
	backups := m.backups
	m.message = "Moving backups..."
	return func() tea.Msg {
		if err := backups.MoveTo(value); err != nil {
			return backupFinished{err: err}
		}
		return backupFinished{message: "Backups are now saved in " + backups.Folder()}
	}
}

func submitRemoveAll(m *model, value string) tea.Cmd {
	if value != removeAllConfirmation {
		m.message = fmt.Sprintf("Nothing was removed: you must type %s exactly.", removeAllConfirmation)
		return nil
	}
	m.message = "Removing all rules..."
	service := m.service
	return func() tea.Msg {
		removed, notice, err := service.DeleteAll(context.Background())
		message := fmt.Sprintf("Removed %d rule(s). A backup was taken first: restore it with S to undo", removed)
		return actionFinished{message: withNotice(message, notice), err: err}
	}
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
