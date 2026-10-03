package whiptail

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/HeresJohnny320/iptable-ui/internal/app"
	"github.com/HeresJohnny320/iptable-ui/internal/store"
	"github.com/HeresJohnny320/iptable-ui/internal/system"
)

type WebControl interface {
	Toggle() (bool, error)
	Enabled() bool
	StatusText() string
	Token() string
}

type SystemControl interface {
	Status(context.Context) system.Status
	SetForwarding(context.Context, bool) error
	SetBootRestore(context.Context, bool) error
}

type menu struct {
	dialog  Dialog
	service app.Service
	web     WebControl
	host    SystemControl
	// last is the result of the previous action, shown on the main menu so
	// routine changes do not need an extra OK press.
	last string
}

const title = "iptable-ui"

const helpText = `Rules forward a public port on this server to a port on a machine behind the VPN. Every change applies to the firewall right away.

Turn a rule off: the forward stops at once, including open connections. The rule stays saved.

Real client IP: off (default), the server sees every visitor as this VPS. On, it sees each visitor's real address, but replies must route back through the tunnel (README: Keep the Real Client IP).

Re-apply rules: rebuilds the firewall from your saved rules. Only needed if something else (another script, ufw, Docker, iptables -F) wiped or changed them.

IPv4 forwarding: lets this server pass traffic on to other machines. Must be ON for any forward to work. Survives reboots.

Apply rules on boot: firewall rules live in memory and vanish when the server restarts. When ON, a startup service re-applies your saved rules automatically.`

// Run shows the whiptail menus until the user quits. It reports whether the
// user asked to switch to the full TUI instead.
func Run(dialog Dialog, service app.Service, web WebControl, host SystemControl) (bool, error) {
	m := &menu{dialog: dialog, service: service, web: web, host: host}
	choice := ""
	for {
		rules, err := service.List(context.Background())
		if err != nil {
			return false, err
		}
		items := []Item{{"rules", fmt.Sprintf("Rules (%d)", len(rules))}, {"add", "Add a rule"}}
		if host != nil {
			status := host.Status(context.Background())
			items = append(items,
				Item{"forwarding", "IPv4 forwarding: turn " + onOff(!status.Forwarding)},
				Item{"boot", "Apply rules on boot: turn " + onOff(!status.BootRestore)},
			)
		}
		if web != nil {
			items = append(items, Item{"web", map[bool]string{true: "Web UI: stop", false: "Web UI: start"}[web.Enabled()]})
		}
		items = append(items, Item{"restore", "Re-apply rules (rebuild the firewall from saved rules)"}, Item{"help", "Help: what do these options do?"}, Item{"tui", "Switch to the full TUI (WireGuard setup)"}, Item{"quit", "Quit"})

		tag, ok, err := dialog.Menu(title, m.statusText(rules), items, choice)
		if err != nil {
			return false, err
		}
		if !ok || tag == "quit" {
			return false, nil
		}
		choice = tag
		switch tag {
		case "rules":
			err = m.rules()
		case "add":
			err = m.edit(store.Rule{Protocol: "both"})
		case "forwarding":
			err = m.toggleForwarding()
		case "boot":
			status := host.Status(context.Background())
			result := "Apply on boot is ON: your saved rules come back automatically after a reboot"
			if status.BootRestore {
				result = "Apply on boot is OFF: after a reboot, forwards stay down until you open iptable-ui"
			}
			m.report(result, host.SetBootRestore(context.Background(), !status.BootRestore))
		case "web":
			enabled, toggleErr := web.Toggle()
			m.report("Web UI "+map[bool]string{true: "started: " + web.StatusText(), false: "stopped"}[enabled], toggleErr)
		case "restore":
			m.report("Saved rules re-applied to the firewall", service.Reconcile(context.Background()))
		case "help":
			err = dialog.Message("Help", helpText)
		case "tui":
			return true, nil
		}
		if err != nil {
			return false, err
		}
	}
}

func (m *menu) statusText(rules []store.Rule) string {
	enabled := 0
	for _, rule := range rules {
		if rule.Enabled {
			enabled++
		}
	}
	lines := make([]string, 0, 4)
	if m.host != nil {
		status := m.host.Status(context.Background())
		link := "DOWN"
		if status.VPNUp {
			link = "UP"
		}
		lines = append(lines, fmt.Sprintf("Forwarding %s | Route %s -> %s %s | Apply on boot %s", onOff(status.Forwarding), status.PublicInterface, status.VPNInterface, link, onOff(status.BootRestore)))
	}
	if m.web != nil {
		lines = append(lines, "Web UI "+m.web.StatusText(), "Token "+m.web.Token())
	}
	lines = append(lines, fmt.Sprintf("Rules: %d saved, %d enabled", len(rules), enabled))
	if m.last != "" {
		lines = append(lines, "", m.last)
	}
	return strings.Join(lines, "\n")
}

// report records an action's result: errors get a dialog, successes are
// shown on the main menu.
func (m *menu) report(success string, err error) {
	if err != nil {
		m.last = ""
		_ = m.dialog.Message("Error", err.Error())
		return
	}
	m.last = success
}

func (m *menu) rules() error {
	choice := ""
	for {
		rules, err := m.service.List(context.Background())
		if err != nil {
			return err
		}
		if len(rules) == 0 {
			return m.dialog.Message(title, "No saved forwarding rules yet. Choose \"Add a rule\" on the main menu.")
		}
		items := make([]Item, len(rules))
		for index, rule := range rules {
			items[index] = Item{strconv.FormatInt(rule.ID, 10), RuleLine(rule)}
		}
		tag, ok, err := m.dialog.Menu("Rules", "Choose a rule to toggle, edit or remove.", items, choice)
		if err != nil || !ok {
			return err
		}
		choice = tag
		id, _ := strconv.ParseInt(tag, 10, 64)
		for _, rule := range rules {
			if rule.ID == id {
				if err := m.ruleActions(rule); err != nil {
					return err
				}
			}
		}
	}
}

// RuleLine is a one-line summary of a rule for menus.
func RuleLine(rule store.Rule) string {
	state, client, name := "OFF", "masked", rule.Name
	if rule.Enabled {
		state = "ON "
	}
	if rule.KeepClientIP {
		client = "real IP"
	}
	if name == "" {
		name = "Unnamed forward"
	}
	return fmt.Sprintf("%s :%-5d -> %s:%d  %s  %s  %s", state, rule.PublicPort, rule.DestIP, rule.DestPort, strings.ToUpper(rule.Protocol), client, name)
}

func (m *menu) ruleActions(rule store.Rule) error {
	toggle := "Disable"
	if !rule.Enabled {
		toggle = "Enable"
	}
	clientIP := "Real client IP: turn ON"
	if rule.KeepClientIP {
		clientIP = "Real client IP: turn OFF (mask it again)"
	}
	tag, ok, err := m.dialog.Menu(fmt.Sprintf("Rule #%d", rule.ID), RuleLine(rule), []Item{{"toggle", toggle}, {"clientip", clientIP}, {"edit", "Edit"}, {"remove", "Remove"}, {"back", "Back"}}, "")
	if err != nil || !ok {
		return err
	}
	switch tag {
	case "toggle":
		notice, err := m.service.SetEnabled(context.Background(), rule.ID, !rule.Enabled)
		m.report(withNotice(fmt.Sprintf("Rule #%d %sd", rule.ID, strings.ToLower(toggle)), notice), err)
	case "clientip":
		changed := rule
		changed.KeepClientIP = !rule.KeepClientIP
		if changed.KeepClientIP {
			confirmed, err := m.dialog.YesNo("Real client IP", "Pass the real client IP to the server?\n\nThe home side needs a return route through the tunnel (see README: Keep the Real Client IP), or this forward stops working.")
			if err != nil || !confirmed {
				return err
			}
		}
		_, err := m.service.Update(context.Background(), changed)
		m.report(fmt.Sprintf("Rule #%d: real client IP %s", rule.ID, onOff(changed.KeepClientIP)), err)
	case "edit":
		return m.edit(rule)
	case "remove":
		confirmed, err := m.dialog.YesNo("Remove rule", fmt.Sprintf("Remove rule #%d?\n\n%s", rule.ID, RuleLine(rule)))
		if err != nil || !confirmed {
			return err
		}
		notice, err := m.service.Delete(context.Background(), rule.ID)
		m.report(withNotice(fmt.Sprintf("Rule #%d removed", rule.ID), notice), err)
	}
	return nil
}

// edit walks through each field, re-asking when a value is invalid. Cancel
// at any step abandons the change.
func (m *menu) edit(rule store.Rule) error {
	heading := "Add a rule"
	if rule.ID != 0 {
		heading = fmt.Sprintf("Edit rule #%d", rule.ID)
	}
	name, ok, err := m.dialog.Input(heading, "Label (optional):", rule.Name)
	if err != nil || !ok {
		return err
	}
	publicPort, ok, err := m.askPort(heading, "Public port on this VPS (1-65535):", rule.PublicPort)
	if err != nil || !ok {
		return err
	}
	destIP, ok, err := m.askIPv4(heading, rule.DestIP)
	if err != nil || !ok {
		return err
	}
	destPort := rule.DestPort
	if destPort == 0 {
		destPort = publicPort
	}
	destPort, ok, err = m.askPort(heading, "Port on the destination server:", destPort)
	if err != nil || !ok {
		return err
	}
	protocol, ok, err := m.dialog.Menu(heading, "Protocol:", []Item{{"both", "TCP and UDP"}, {"tcp", "TCP only"}, {"udp", "UDP only"}}, rule.Protocol)
	if err != nil || !ok {
		return err
	}
	current := "masked"
	if rule.KeepClientIP {
		current = "real"
	}
	client, ok, err := m.dialog.Menu(heading, "Which client IP should the destination server see?\n\nReal client IPs need replies to route back through the tunnel; see the README section \"Keep the real client IP\".",
		[]Item{{"masked", "VPS tunnel IP (works everywhere)"}, {"real", "Real client IP (needs a return route at home)"}}, current)
	if err != nil || !ok {
		return err
	}
	updated := store.Rule{ID: rule.ID, Name: strings.TrimSpace(name), PublicPort: publicPort, DestIP: destIP, DestPort: destPort, Protocol: protocol, KeepClientIP: client == "real"}
	if rule.ID == 0 {
		added, err := m.service.Add(context.Background(), updated)
		m.report(fmt.Sprintf("Rule #%d added: %s", added.ID, RuleLine(added)), err)
	} else {
		saved, err := m.service.Update(context.Background(), updated)
		m.report(fmt.Sprintf("Rule #%d updated: %s", saved.ID, RuleLine(saved)), err)
	}
	if m.host != nil && !m.host.Status(context.Background()).Forwarding && m.last != "" {
		m.last += "\nIPv4 forwarding is OFF, so traffic will not pass yet."
	}
	return nil
}

func (m *menu) askPort(heading, prompt string, initial uint16) (uint16, bool, error) {
	value := ""
	if initial != 0 {
		value = strconv.Itoa(int(initial))
	}
	for {
		answer, ok, err := m.dialog.Input(heading, prompt, value)
		if err != nil || !ok {
			return 0, ok, err
		}
		port, parseErr := strconv.ParseUint(strings.TrimSpace(answer), 10, 16)
		if parseErr == nil && port > 0 {
			return uint16(port), true, nil
		}
		if err := m.dialog.Message("Invalid port", "Ports must be a number between 1 and 65535."); err != nil {
			return 0, false, err
		}
		value = answer
	}
}

func (m *menu) askIPv4(heading, initial string) (string, bool, error) {
	value := initial
	for {
		answer, ok, err := m.dialog.Input(heading, "Destination server IPv4 (its address on the VPN):", value)
		if err != nil || !ok {
			return "", ok, err
		}
		address, parseErr := netip.ParseAddr(strings.TrimSpace(answer))
		if parseErr == nil && address.Is4() {
			return address.String(), true, nil
		}
		if err := m.dialog.Message("Invalid address", "Enter an IPv4 address such as 10.66.0.2."); err != nil {
			return "", false, err
		}
		value = answer
	}
}

func (m *menu) toggleForwarding() error {
	status := m.host.Status(context.Background())
	if status.Forwarding {
		confirmed, err := m.dialog.YesNo("IPv4 forwarding", "Turn IPv4 forwarding OFF?\n\nEvery port forward stops passing traffic.")
		if err != nil || !confirmed {
			return err
		}
	}
	m.report("IPv4 forwarding turned "+onOff(!status.Forwarding)+" (saved for reboots)", m.host.SetForwarding(context.Background(), !status.Forwarding))
	return nil
}

func onOff(on bool) string {
	if on {
		return "ON"
	}
	return "OFF"
}

func withNotice(message, notice string) string {
	if notice == "" {
		return message
	}
	return message + ". " + notice
}
