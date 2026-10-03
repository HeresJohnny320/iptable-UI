package firewall

import (
	"strconv"
	"strings"
)

// LiveEntry is one rule from `iptables -L -n -v --line-numbers` output.
type LiveEntry struct {
	Number      int    `json:"number"`
	Packets     string `json:"packets"`
	Bytes       string `json:"bytes"`
	Target      string `json:"target"`
	Protocol    string `json:"protocol"`
	In          string `json:"in"`
	Out         string `json:"out"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	// PublicPort and ForwardTo come from "dpt:25565 to:10.66.0.2:25565".
	PublicPort string `json:"publicPort"`
	ForwardTo  string `json:"forwardTo"`
	// Extra is anything else on the line.
	Extra string `json:"extra"`
	// Active is true when the rule has matched any packets.
	Active bool `json:"active"`
}

// LiveTable is a parsed iptables chain listing.
type LiveTable struct {
	Chain   string      `json:"chain"`
	Entries []LiveEntry `json:"entries"`
}

// protocolNames maps the protocol numbers newer iptables prints to names.
var protocolNames = map[string]string{"0": "all", "1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6"}

// ParseLiveRules turns `iptables -t nat -L CHAIN -n -v --line-numbers`
// output into rows that are easy to show. ok is false when the output does
// not look like a listing, so the raw text can be shown instead.
func ParseLiveRules(output string) (LiveTable, bool) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "Chain ") {
		return LiveTable{}, false
	}
	table := LiveTable{Chain: strings.Fields(lines[0])[1], Entries: []LiveEntry{}}
	header := strings.Fields(lines[1])
	if len(header) < 10 || header[0] != "num" || header[1] != "pkts" {
		return LiveTable{}, false
	}
	for _, text := range lines[2:] {
		fields := strings.Fields(text)
		if len(fields) < 10 {
			continue
		}
		number, err := strconv.Atoi(fields[0])
		if err != nil {
			return LiveTable{}, false
		}
		protocol := fields[4]
		if name, known := protocolNames[protocol]; known {
			protocol = name
		}
		entry := LiveEntry{
			Number: number, Packets: fields[1], Bytes: fields[2], Target: fields[3], Protocol: protocol,
			In: fields[6], Out: fields[7], Source: fields[8], Destination: fields[9], Active: fields[1] != "0",
		}
		extra := make([]string, 0)
		for _, word := range fields[10:] {
			switch {
			case strings.HasPrefix(word, "dpt:"):
				entry.PublicPort = strings.TrimPrefix(word, "dpt:")
			case strings.HasPrefix(word, "to:"):
				entry.ForwardTo = strings.TrimPrefix(word, "to:")
			case word == entry.Protocol || word == fields[4]:
				// "tcp" repeated before dpt: adds nothing
			default:
				extra = append(extra, word)
			}
		}
		entry.Extra = strings.Join(extra, " ")
		table.Entries = append(table.Entries, entry)
	}
	return table, true
}
