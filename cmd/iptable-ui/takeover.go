package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/HeresJohnny320/iptable-ui/internal/firewall"
)

// introSetting records that the first-run notice was shown and accepted.
const introSetting = "intro.seen"

// legacyRules are the discovered forwards made by something other than
// iptable-ui; taking them over removes the originals.
func legacyRules(discovered []firewall.ExistingRule) []firewall.ExistingRule {
	legacy := make([]firewall.ExistingRule, 0)
	for _, existing := range discovered {
		if existing.Legacy {
			legacy = append(legacy, existing)
		}
	}
	return legacy
}

// withoutLegacy keeps only iptable-ui's own forwards, so other tools' rules
// are left exactly as they are.
func withoutLegacy(discovered []firewall.ExistingRule) []firewall.ExistingRule {
	kept := make([]firewall.ExistingRule, 0, len(discovered))
	for _, existing := range discovered {
		if !existing.Legacy {
			kept = append(kept, existing)
		}
	}
	return kept
}

// takeoverNotice tells the user, before anything changes, what iptable-ui
// is about to do to this server's firewall. The first run gets the full
// explanation; later runs only hear about newly found forwards.
func takeoverNotice(out io.Writer, firstRun bool, legacy []firewall.ExistingRule, publicIF, snapshotDir string) {
	line := strings.Repeat("-", 72)
	fmt.Fprintln(out, line)
	if firstRun {
		fmt.Fprintln(out, "Before iptable-ui starts, here is what it does to this server:")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "  * It manages port forwards with its own firewall rules (the IPTUI_* chains)")
		fmt.Fprintln(out, "    and rebuilds them every time you change something.")
		fmt.Fprintln(out, "  * It looks for port forwards made by other scripts or by hand. The ones it")
		fmt.Fprintln(out, "    recognizes are imported, rebuilt in its own rules, and the originals are")
		fmt.Fprintln(out, "    removed so nothing runs twice.")
		fmt.Fprintln(out, "  * After that, older scripts that manage those forwards will not find them")
		fmt.Fprintln(out, "    any more, and scripts that remove rules by line number may remove the")
		fmt.Fprintln(out, "    wrong ones. Stop using them on this server.")
		fmt.Fprintln(out, "  * Rules it does not recognize, and rules from Docker, ufw or Tailscale,")
		fmt.Fprintln(out, "    are left alone.")
		fmt.Fprintf(out, "  * A copy of the whole firewall is saved before every change, in\n    %s. To put an old copy back:\n    sudo iptables-restore < %s/<file>\n", snapshotDir, snapshotDir)
		fmt.Fprintln(out)
	}
	if len(legacy) == 0 {
		fmt.Fprintln(out, "No port forwards from other tools were found, so nothing will be imported.")
	} else {
		if firstRun {
			fmt.Fprintf(out, "Found %d port forward(s) made by another tool. These will be taken over:\n", len(legacy))
		} else {
			fmt.Fprintf(out, "Found %d new port forward(s) made by another tool since last time:\n", len(legacy))
		}
		for _, existing := range legacy {
			fmt.Fprintln(out, "  "+describeLegacy(existing, publicIF))
		}
		fmt.Fprintln(out, "Taking them over removes the originals, so the tool that made them will no")
		fmt.Fprintln(out, "longer see them.")
	}
	fmt.Fprintln(out, line)
}

// describeLegacy is one found forward, for example
// "25565/tcp -> 10.66.0.2:25565 (any adapter)".
func describeLegacy(existing firewall.ExistingRule, publicIF string) string {
	where := "on " + publicIF
	if existing.AnyCount > 0 && existing.Count == 0 {
		where = "any adapter"
	}
	return fmt.Sprintf("%d/%s -> %s:%d (%s)", existing.Rule.PublicPort, existing.Rule.Protocol, existing.Rule.DestIP, existing.Rule.DestPort, where)
}
