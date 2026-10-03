package system

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const defaultVPNIF = "wg0"

// vpnPrefixes match common tunnel interfaces: WireGuard, Tailscale, OpenVPN,
// ZeroTier, Nebula, NetBird and PPP.
var vpnPrefixes = []string{"wg", "tailscale", "tun", "tap", "zt", "nebula", "wt", "ppp"}

// Interface is a network interface as seen by detection.
type Interface struct {
	Name      string
	Up        bool
	IPv4      bool
	WireGuard bool
}

// Detection is an auto-detected interface and why it was chosen.
type Detection struct {
	Name   string
	Reason string
	// NotFound means nothing was detected and Name is only a default.
	NotFound bool
}

func (i Interface) vpnLike() bool { return i.WireGuard || hasVPNPrefix(i.Name) }

// Interfaces lists the host's network interfaces with their link state.
func (h Host) Interfaces() []Interface {
	entries, err := os.ReadDir(h.path(sysClassNet))
	if err != nil {
		return nil
	}
	result := make([]Interface, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		result = append(result, Interface{Name: name, Up: h.interfaceUp(name), IPv4: h.hasIPv4(name), WireGuard: h.isWireGuard(name)})
	}
	return result
}

// DetectPublicInterface finds the interface that carries internet traffic:
// the lowest-metric default route in the main table, skipping VPN interfaces
// (such as a Tailscale exit node), then whatever `ip route get` reports.
func (h Host) DetectPublicInterface(ctx context.Context) (Detection, error) {
	byName := make(map[string]Interface)
	for _, iface := range h.Interfaces() {
		byName[iface.Name] = iface
	}
	best, bestMetric := "", math.MaxInt
	if contents, err := os.ReadFile(h.path("/proc/net/route")); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(contents))
		scanner.Scan() // header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
				continue
			}
			flags, flagErr := strconv.ParseUint(fields[3], 16, 32)
			metric, metricErr := strconv.Atoi(fields[6])
			iface, known := byName[fields[0]]
			if flagErr != nil || metricErr != nil || flags&0x1 == 0 || !known || !iface.Up || iface.vpnLike() {
				continue
			}
			if metric < bestMetric {
				best, bestMetric = iface.Name, metric
			}
		}
	}
	if best != "" {
		return Detection{Name: best, Reason: "default route"}, nil
	}
	if device := h.routeDevice(ctx, "1.1.1.1"); device != "" && device != "lo" && !byName[device].vpnLike() && !hasVPNPrefix(device) {
		return Detection{Name: device, Reason: "route to the internet"}, nil
	}
	return Detection{}, errors.New("could not detect the public interface; specify --public-if")
}

// DetectVPNInterface picks the tunnel interface that forwarded traffic should
// leave through. The interface the kernel routes rule destinations through
// wins; otherwise an active (up, with IPv4) tunnel, preferring wg0 and
// WireGuard devices. It falls back to wg0 when nothing is found.
func (h Host) DetectVPNInterface(ctx context.Context, publicInterface string, destinations []string) Detection {
	unique := make(map[string]bool)
	routed := make(map[string]int)
	for _, destination := range destinations {
		if unique[destination] {
			continue
		}
		unique[destination] = true
		if device := h.routeDevice(ctx, destination); device != "" && device != "lo" && device != publicInterface {
			routed[device]++
		}
	}
	candidates := make([]Interface, 0)
	for _, iface := range h.Interfaces() {
		if iface.Name != "lo" && iface.Name != publicInterface && (iface.vpnLike() || routed[iface.Name] > 0) {
			candidates = append(candidates, iface)
		}
	}
	if len(candidates) == 0 {
		return Detection{Name: defaultVPNIF, Reason: "no VPN interface found; using the default", NotFound: true}
	}
	sort.SliceStable(candidates, func(a, b int) bool {
		first, second := candidates[a], candidates[b]
		switch {
		case routed[first.Name] != routed[second.Name]:
			return routed[first.Name] > routed[second.Name]
		case (first.Up && first.IPv4) != (second.Up && second.IPv4):
			return first.Up && first.IPv4
		case first.Up != second.Up:
			return first.Up
		case (first.Name == defaultVPNIF) != (second.Name == defaultVPNIF):
			return first.Name == defaultVPNIF
		case first.WireGuard != second.WireGuard:
			return first.WireGuard
		default:
			return first.Name < second.Name
		}
	})
	best := candidates[0]
	switch {
	case routed[best.Name] > 0:
		return Detection{Name: best.Name, Reason: fmt.Sprintf("routes to %d of %d forward destination(s)", routed[best.Name], len(unique))}
	case best.Up && best.IPv4:
		return Detection{Name: best.Name, Reason: "active VPN interface"}
	case best.Up:
		return Detection{Name: best.Name, Reason: "VPN interface is up but has no IPv4 address"}
	default:
		return Detection{Name: best.Name, Reason: "VPN interface found but it is down"}
	}
}

// routeDevice returns the interface the kernel would use to reach address.
func (h Host) routeDevice(ctx context.Context, address string) string {
	parsed, err := netip.ParseAddr(address)
	if h.Runner == nil || err != nil || !parsed.Is4() {
		return ""
	}
	output, err := h.Runner.Run(ctx, "ip", "-4", "route", "get", parsed.String())
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(output))
	for index, field := range fields {
		if field == "dev" && index+1 < len(fields) {
			return fields[index+1]
		}
	}
	return ""
}

func (h Host) hasIPv4(name string) bool {
	if h.IPv4Lookup != nil {
		return h.IPv4Lookup(name)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && network.IP.To4() != nil {
			return true
		}
	}
	return false
}

// VPNKind names the VPN behind an interface. NetBird runs on WireGuard, so
// names are checked before the WireGuard device type.
func VPNKind(name string, wireGuard bool) string {
	switch {
	case name == "":
		return ""
	case strings.HasPrefix(name, "tailscale"):
		return "Tailscale"
	case strings.HasPrefix(name, "wt"):
		return "NetBird"
	case strings.HasPrefix(name, "zt"):
		return "ZeroTier"
	case strings.HasPrefix(name, "nebula"):
		return "Nebula"
	case wireGuard || strings.HasPrefix(name, "wg"):
		return "WireGuard"
	case strings.HasPrefix(name, "tun"), strings.HasPrefix(name, "tap"):
		return "OpenVPN"
	case strings.HasPrefix(name, "ppp"):
		return "PPP"
	default:
		return "VPN"
	}
}

func (h Host) ipv4Address(name string) string {
	if h.IPv4Address != nil {
		return h.IPv4Address(name)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && network.IP.To4() != nil {
			return network.IP.String()
		}
	}
	return ""
}

func (h Host) isWireGuard(name string) bool {
	uevent, err := os.ReadFile(h.path(filepath.Join(sysClassNet, name, "uevent")))
	return err == nil && strings.Contains(string(uevent), "DEVTYPE=wireguard")
}

func hasVPNPrefix(name string) bool {
	for _, prefix := range vpnPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
