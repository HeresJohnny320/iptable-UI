// Package traffic measures how fast data moves through the network adapters
// and through each port forward, from counters the kernel already keeps.
package traffic

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Interval is how often counters are sampled.
const Interval = 2 * time.Second

// Runner runs a command and returns its output.
type Runner interface {
	Run(context.Context, ...string) ([]byte, error)
}

// Forward identifies one forward and protocol.
type Forward struct {
	PublicPort uint16
	Protocol   string
	DestIP     string
}

// Counter is a pair of byte counts. For an adapter In is received (RX) and
// Out is sent (TX); for a forward In flows to your server and Out flows back
// to visitors.
type Counter struct {
	In  uint64 `json:"in"`
	Out uint64 `json:"out"`
}

// Rate is bytes per second in each direction, plus the counters behind it.
type Rate struct {
	InPerSecond  float64 `json:"inPerSecond"`
	OutPerSecond float64 `json:"outPerSecond"`
	InTotal      uint64  `json:"inTotal"`
	OutTotal     uint64  `json:"outTotal"`
}

// Adapter is the traffic on one network adapter.
type Adapter struct {
	Name string `json:"name"`
	Rate
}

// Snapshot is the latest measured traffic.
type Snapshot struct {
	Adapters []Adapter        `json:"adapters"`
	Forwards map[Forward]Rate `json:"-"`
	When     time.Time        `json:"when"`
}

// ForwardRate adds up a rule's traffic; a "both" rule covers TCP and UDP.
func (s Snapshot) ForwardRate(publicPort uint16, protocol, destIP string) (Rate, bool) {
	protocols := []string{protocol}
	if protocol == "both" {
		protocols = []string{"tcp", "udp"}
	}
	var total Rate
	found := false
	for _, name := range protocols {
		if rate, ok := s.Forwards[Forward{publicPort, name, destIP}]; ok {
			total.InPerSecond += rate.InPerSecond
			total.OutPerSecond += rate.OutPerSecond
			total.InTotal += rate.InTotal
			total.OutTotal += rate.OutTotal
			found = true
		}
	}
	return total, found
}

// Monitor samples the counters in the background.
type Monitor struct {
	// Root prefixes /sys paths; empty means "/". Tests point it at a temp dir.
	Root   string
	Runner Runner
	// Adapters lists the adapters to measure, such as the public and VPN ones.
	Adapters func() []string
	// Now reads the clock; nil uses time.Now. Tests replace it.
	Now func() time.Time

	mu       sync.Mutex
	previous sample
	latest   Snapshot
}

type sample struct {
	when     time.Time
	adapters map[string]Counter
	forwards map[Forward]Counter
}

// Run samples every Interval until ctx is done.
func (m *Monitor) Run(ctx context.Context) {
	m.Sample(ctx)
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Sample(ctx)
		}
	}
}

// Snapshot returns the latest measurement.
func (m *Monitor) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.latest
}

// Sample reads the counters once and updates the rates.
func (m *Monitor) Sample(ctx context.Context) {
	now := time.Now
	if m.Now != nil {
		now = m.Now
	}
	current := sample{when: now(), adapters: make(map[string]Counter), forwards: map[Forward]Counter{}}
	if m.Adapters != nil {
		for _, name := range m.Adapters() {
			if counter, ok := m.adapterCounter(name); ok {
				current.adapters[name] = counter
			}
		}
	}
	if m.Runner != nil {
		if output, err := m.Runner.Run(ctx, "iptables-save", "-c", "-t", "filter"); err == nil {
			current.forwards = ParseForwardCounters(string(output))
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	seconds := current.when.Sub(m.previous.when).Seconds()
	snapshot := Snapshot{Forwards: make(map[Forward]Rate), When: current.when}
	if m.Adapters != nil {
		for _, name := range m.Adapters() {
			counter, ok := current.adapters[name]
			if !ok {
				continue
			}
			snapshot.Adapters = append(snapshot.Adapters, Adapter{Name: name, Rate: rate(m.previous.adapters[name], counter, seconds, m.previous.when.IsZero())})
		}
	}
	for key, counter := range current.forwards {
		snapshot.Forwards[key] = rate(m.previous.forwards[key], counter, seconds, m.previous.when.IsZero())
	}
	m.previous, m.latest = current, snapshot
}

// rate turns two readings into bytes per second. A counter that went down
// was reset (rules are rebuilt on every change), so it counts from zero.
func rate(before, after Counter, seconds float64, first bool) Rate {
	result := Rate{InTotal: after.In, OutTotal: after.Out}
	if first || seconds <= 0 {
		return result
	}
	if after.In >= before.In {
		result.InPerSecond = float64(after.In-before.In) / seconds
	}
	if after.Out >= before.Out {
		result.OutPerSecond = float64(after.Out-before.Out) / seconds
	}
	return result
}

func (m *Monitor) adapterCounter(name string) (Counter, bool) {
	if name == "" || strings.ContainsAny(name, "/") {
		return Counter{}, false
	}
	read := func(file string) (uint64, bool) {
		path := filepath.Join("/sys/class/net", name, "statistics", file)
		if m.Root != "" {
			path = filepath.Join(m.Root, path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return 0, false
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		return value, err == nil
	}
	received, okReceived := read("rx_bytes")
	sent, okSent := read("tx_bytes")
	return Counter{In: received, Out: sent}, okReceived && okSent
}

var counterLine = regexp.MustCompile(`^\[(\d+):(\d+)\] -A IPTUI_FWD (.*)$`)

// ParseForwardCounters reads the byte counters of iptable-ui's FORWARD rules
// from `iptables-save -c -t filter`. The rule toward a destination (-d)
// counts traffic to your server; the reply rule (-s) counts traffic back.
func ParseForwardCounters(ruleset string) map[Forward]Counter {
	counters := make(map[Forward]Counter)
	for _, line := range strings.Split(ruleset, "\n") {
		match := counterLine.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil || !strings.HasSuffix(match[3], "-j ACCEPT") {
			continue
		}
		bytes, err := strconv.ParseUint(match[2], 10, 64)
		if err != nil {
			continue
		}
		fields := strings.Fields(match[3])
		var protocol, destination, source string
		var port uint64
		for index := 0; index+1 < len(fields); index++ {
			switch fields[index] {
			case "-p":
				protocol = fields[index+1]
			case "-d":
				destination = strings.TrimSuffix(fields[index+1], "/32")
			case "-s":
				source = strings.TrimSuffix(fields[index+1], "/32")
			case "--ctorigdstport":
				port, _ = strconv.ParseUint(fields[index+1], 10, 16)
			}
		}
		if port == 0 || protocol == "" {
			continue
		}
		switch {
		case destination != "":
			key := Forward{uint16(port), protocol, destination}
			counter := counters[key]
			counter.In += bytes
			counters[key] = counter
		case source != "":
			key := Forward{uint16(port), protocol, source}
			counter := counters[key]
			counter.Out += bytes
			counters[key] = counter
		}
	}
	return counters
}

// FormatRate shows bytes per second the way people read speeds.
func FormatRate(bytesPerSecond float64) string {
	return FormatBytes(bytesPerSecond) + "/s"
}

// FormatBytes shows a byte count with a readable unit.
func FormatBytes(bytes float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	unit := 0
	for bytes >= 1000 && unit < len(units)-1 {
		bytes /= 1000
		unit++
	}
	if unit == 0 || bytes >= 100 {
		return fmt.Sprintf("%.0f %s", bytes, units[unit])
	}
	return strings.TrimSuffix(fmt.Sprintf("%.1f", bytes), ".0") + " " + units[unit]
}
