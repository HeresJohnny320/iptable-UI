package tui

import "github.com/charmbracelet/lipgloss"

// The TUI's styles. applyTheme sets them from a theme, so every screen
// changes look at once.
var (
	brandStyle, sectionStyle, mutedStyle, labelStyle, selectedStyle lipgloss.Style
	publicStyle, addressStyle, portStyle, protocolStyle             lipgloss.Style
	enabledStyle, disabledStyle, keyStyle, messageStyle             lipgloss.Style
	valueStyle, focusedStyle                                        lipgloss.Style
	accentBorder, quietBorder, selectedBorder                       lipgloss.TerminalColor
)

// tuiTheme is one look for the TUI. Plain themes use no colors at all and
// show emphasis with bold and reverse video instead.
type tuiTheme struct {
	name, label                                        string
	plain                                              bool
	brandFG, brandBG, section, muted, label_, selected string
	public, address, port, protocol, enabled, disabled string
	keyFG, keyBG, message, messageBorder               string
	accent, quiet, selectedBorder, value, focused      string
}

// tuiThemes are offered in this order; the first is the default.
var tuiThemes = []tuiTheme{
	{name: "classic", label: "Classic",
		brandFG: "#F2F7F3", brandBG: "#176B4B", section: "#75D6A3", muted: "#8B9A91", label_: "#96A79C", selected: "#F5F8F5",
		public: "#E5B85C", address: "#61C7D4", port: "#81D69F", protocol: "#C5A7EF", enabled: "#66D494", disabled: "#D9A36A",
		keyFG: "#12241A", keyBG: "#80D6A5", message: "#F0D28A", messageBorder: "#D9A64F",
		accent: "#3B7557", quiet: "#394940", selectedBorder: "#58B981", value: "#DDE7DF", focused: "#F2C96D"},
	// Readable: bright, high-contrast colors and no dim grey text.
	{name: "readable", label: "Readable",
		brandFG: "#000000", brandBG: "#FFD75F", section: "#FFFFFF", muted: "#D0D0D0", label_: "#E4E4E4", selected: "#FFFFFF",
		public: "#FFD75F", address: "#5FD7FF", port: "#87FF87", protocol: "#FF87FF", enabled: "#5FFF5F", disabled: "#FF8700",
		keyFG: "#000000", keyBG: "#FFFFFF", message: "#FFFFFF", messageBorder: "#FFD75F",
		accent: "#FFFFFF", quiet: "#8A8A8A", selectedBorder: "#FFD75F", value: "#FFFFFF", focused: "#FFD75F"},
	// Light: dark text for terminals with a white background.
	{name: "light", label: "Light terminal",
		brandFG: "#FFFFFF", brandBG: "#176B4B", section: "#0E5A3A", muted: "#4E5D55", label_: "#3D4A43", selected: "#000000",
		public: "#8A5A00", address: "#005F87", port: "#1F6B3A", protocol: "#6B2FA0", enabled: "#1E7A44", disabled: "#A0461C",
		keyFG: "#FFFFFF", keyBG: "#176B4B", message: "#5A3C00", messageBorder: "#B07A1A",
		accent: "#176B4B", quiet: "#9AA59E", selectedBorder: "#0E5A3A", value: "#1A1A1A", focused: "#8A3C00"},
	{name: "ocean", label: "Ocean",
		brandFG: "#F4F8FC", brandBG: "#1F5F99", section: "#7FB8F0", muted: "#8C9BAD", label_: "#9FB0C4", selected: "#F4F8FC",
		public: "#F0C674", address: "#7FDBEB", port: "#8FE3B8", protocol: "#C9A7F5", enabled: "#6FD0A0", disabled: "#E8A06A",
		keyFG: "#0B1B2B", keyBG: "#7FB8F0", message: "#F0D28A", messageBorder: "#7FB8F0",
		accent: "#2A5D8F", quiet: "#2C3E50", selectedBorder: "#7FB8F0", value: "#DCE6F0", focused: "#F0C674"},
	// Plain: no colors, for monochrome terminals and screen readers.
	{name: "plain", label: "Plain (no colors)", plain: true},
}

func findTheme(name string) tuiTheme {
	for _, theme := range tuiThemes {
		if theme.name == name {
			return theme
		}
	}
	return tuiThemes[0]
}

// nextTheme is the theme after the named one, wrapping around.
func nextTheme(name string) tuiTheme {
	for index, theme := range tuiThemes {
		if theme.name == name {
			return tuiThemes[(index+1)%len(tuiThemes)]
		}
	}
	return tuiThemes[0]
}

func applyTheme(theme tuiTheme) {
	color := func(value string) lipgloss.TerminalColor {
		if theme.plain || value == "" {
			return lipgloss.NoColor{}
		}
		return lipgloss.Color(value)
	}
	text := func(value string, bold bool) lipgloss.Style {
		return lipgloss.NewStyle().Bold(bold).Foreground(color(value))
	}
	brandStyle = lipgloss.NewStyle().Bold(true).Foreground(color(theme.brandFG)).Background(color(theme.brandBG)).Padding(0, 1)
	keyStyle = lipgloss.NewStyle().Bold(true).Foreground(color(theme.keyFG)).Background(color(theme.keyBG)).Padding(0, 1)
	if theme.plain {
		brandStyle = brandStyle.Reverse(true)
		keyStyle = keyStyle.Reverse(true)
	}
	sectionStyle = text(theme.section, true)
	mutedStyle = text(theme.muted, false)
	labelStyle = text(theme.label_, false)
	selectedStyle = text(theme.selected, true)
	publicStyle = text(theme.public, true)
	addressStyle = text(theme.address, true)
	portStyle = text(theme.port, true)
	protocolStyle = text(theme.protocol, true)
	enabledStyle = text(theme.enabled, true)
	disabledStyle = text(theme.disabled, true)
	if theme.plain {
		disabledStyle = disabledStyle.Underline(true)
	}
	messageStyle = lipgloss.NewStyle().Foreground(color(theme.message)).BorderLeft(true).BorderForeground(color(theme.messageBorder)).PaddingLeft(1)
	valueStyle = text(theme.value, false)
	focusedStyle = text(theme.focused, true)
	if theme.plain {
		focusedStyle = focusedStyle.Underline(true)
	}
	accentBorder, quietBorder, selectedBorder = color(theme.accent), color(theme.quiet), color(theme.selectedBorder)
}

func init() { applyTheme(tuiThemes[0]) }
