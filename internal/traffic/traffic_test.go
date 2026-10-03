package traffic

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type fakeRunner struct{ output string }

func (f *fakeRunner) Run(context.Context, ...string) ([]byte, error) { return []byte(f.output), nil }

func counters(toServer, toVisitors uint64) string {
	return "*filter\n:IPTUI_FWD - [0:0]\n" +
		"[10:" + strconv.FormatUint(toServer, 10) + "] -A IPTUI_FWD -d 10.66.0.2/32 -i eth0 -o wg0 -p tcp -m tcp --dport 25565 -m conntrack --ctstate NEW,RELATED,ESTABLISHED --ctorigdstport 25565 -j ACCEPT\n" +
		"[20:" + strconv.FormatUint(toVisitors, 10) + "] -A IPTUI_FWD -s 10.66.0.2/32 -i wg0 -o eth0 -p tcp -m conntrack --ctstate RELATED,ESTABLISHED --ctorigdstport 25565 -j ACCEPT\n" +
		"[5:500] -A IPTUI_FWD -d 10.66.0.2/32 -i eth0 -o wg0 -p udp -m udp --dport 25565 -m conntrack --ctstate NEW,RELATED,ESTABLISHED --ctorigdstport 25565 -j ACCEPT\n" +
		"[9:900] -A IPTUI_FWD -p udp -m conntrack --ctstate DNAT --ctreplsrc 10.66.0.5 --ctorigdstport 9000 -j DROP\nCOMMIT\n"
}

func TestParseForwardCounters(t *testing.T) {
	parsed := ParseForwardCounters(counters(1000, 50000))
	tcp := parsed[Forward{25565, "tcp", "10.66.0.2"}]
	if tcp.In != 1000 || tcp.Out != 50000 {
		t.Fatalf("tcp counters %+v", tcp)
	}
	if udp := parsed[Forward{25565, "udp", "10.66.0.2"}]; udp.In != 500 || udp.Out != 0 {
		t.Fatalf("udp counters %+v", udp)
	}
	if len(parsed) != 2 {
		t.Fatalf("the DROP rule of a disabled forward must be ignored: %+v", parsed)
	}
}

func writeAdapter(t *testing.T, root, name string, received, sent uint64) {
	t.Helper()
	dir := filepath.Join(root, "sys/class/net", name, "statistics")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "rx_bytes"), []byte(strconv.FormatUint(received, 10)+"\n"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "tx_bytes"), []byte(strconv.FormatUint(sent, 10)+"\n"), 0644)
}

func TestMonitorComputesSpeeds(t *testing.T) {
	root := t.TempDir()
	runner := &fakeRunner{output: counters(1000, 50000)}
	clock := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	monitor := &Monitor{Root: root, Runner: runner, Adapters: func() []string { return []string{"eth0", "wg0", "missing0"} }, Now: func() time.Time { return clock }}
	writeAdapter(t, root, "eth0", 1_000_000, 2_000_000)
	writeAdapter(t, root, "wg0", 0, 0)
	monitor.Sample(context.Background())
	if first := monitor.Snapshot(); len(first.Adapters) != 2 || first.Adapters[0].InPerSecond != 0 {
		t.Fatalf("the first sample has totals but no speed yet: %+v", first.Adapters)
	}

	clock = clock.Add(2 * time.Second)
	writeAdapter(t, root, "eth0", 3_000_000, 2_500_000)
	runner.output = counters(3000, 250000)
	monitor.Sample(context.Background())
	snapshot := monitor.Snapshot()
	if eth := snapshot.Adapters[0]; eth.Name != "eth0" || eth.InPerSecond != 1_000_000 || eth.OutPerSecond != 250_000 || eth.InTotal != 3_000_000 {
		t.Fatalf("eth0 rate %+v", eth)
	}
	rate, ok := snapshot.ForwardRate(25565, "both", "10.66.0.2")
	if !ok || rate.InPerSecond != 1000 || rate.OutPerSecond != 100000 {
		t.Fatalf("forward rate %+v", rate)
	}

	// Rules are rebuilt on every change, which resets their counters.
	clock = clock.Add(2 * time.Second)
	runner.output = counters(100, 200)
	monitor.Sample(context.Background())
	if rate, _ := monitor.Snapshot().ForwardRate(25565, "tcp", "10.66.0.2"); rate.InPerSecond != 0 || rate.OutPerSecond != 0 {
		t.Fatalf("a reset counter must not show a negative or huge speed: %+v", rate)
	}
	if _, ok := monitor.Snapshot().ForwardRate(8080, "tcp", "10.66.0.3"); ok {
		t.Fatal("an unknown forward has no traffic")
	}
}

func TestFormat(t *testing.T) {
	for value, want := range map[float64]string{0: "0 B", 999: "999 B", 1500: "1.5 KB", 250_000: "250 KB", 12_340_000: "12.3 MB", 2e9: "2 GB", 73_000: "73 KB"} {
		if got := FormatBytes(value); got != want {
			t.Errorf("FormatBytes(%v) = %q, want %q", value, got, want)
		}
	}
	if got := FormatRate(1500); got != "1.5 KB/s" {
		t.Errorf("FormatRate = %q", got)
	}
}
