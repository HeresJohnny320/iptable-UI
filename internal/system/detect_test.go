package system

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// routeRunner answers `ip -4 route get <address>` from a fixed table.
type routeRunner map[string]string

func (r routeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	if len(args) == 5 && strings.Join(args[:4], " ") == "ip -4 route get" {
		if device, ok := r[args[4]]; ok {
			return []byte(args[4] + " via 10.0.0.1 dev " + device + " src 10.0.0.9 uid 0\n    cache\n"), nil
		}
	}
	return nil, errors.New("no route")
}

type fakeInterface struct {
	name      string
	up        bool
	ipv4      bool
	wireGuard bool
}

// fakeHost builds a /sys/class/net tree under a temp root.
func fakeHost(t *testing.T, routes routeRunner, interfaces ...fakeInterface) Host {
	t.Helper()
	root := t.TempDir()
	addresses := make(map[string]bool)
	for _, iface := range interfaces {
		flags := "0x1002"
		if iface.up {
			flags = "0x1003"
		}
		writeFile(t, root, filepath.Join(sysClassNet, iface.name, "flags"), flags+"\n")
		if iface.up {
			writeFile(t, root, filepath.Join(sysClassNet, iface.name, "carrier"), "1\n")
		}
		if iface.wireGuard {
			writeFile(t, root, filepath.Join(sysClassNet, iface.name, "uevent"), "DEVTYPE=wireguard\n")
		}
		addresses[iface.name] = iface.ipv4
	}
	return Host{Root: root, Runner: routes, IPv4Lookup: func(name string) bool { return addresses[name] }}
}

func TestDetectPublicInterfaceUsesLowestMetricDefaultRoute(t *testing.T) {
	host := fakeHost(t, nil,
		fakeInterface{name: "ens3", up: true, ipv4: true},
		fakeInterface{name: "ens4", up: true, ipv4: true},
		fakeInterface{name: "tailscale0", up: true, ipv4: true},
		fakeInterface{name: "eth9", up: false, ipv4: true},
	)
	writeFile(t, host.Root, "/proc/net/route", "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"+
		"tailscale0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"+
		"eth9\t00000000\t0101A8C0\t0003\t0\t0\t10\t00000000\t0\t0\t0\n"+
		"ens4\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n"+
		"ens3\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"+
		"ens3\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
	detected, err := host.DetectPublicInterface(context.Background())
	if err != nil || detected.Name != "ens3" {
		t.Fatalf("detected %+v, %v; want ens3 (skip VPN exit node and down eth9, lowest metric wins)", detected, err)
	}
}

func TestDetectPublicInterfaceFallsBackToRouteLookup(t *testing.T) {
	host := fakeHost(t, routeRunner{"1.1.1.1": "enp1s0"}, fakeInterface{name: "enp1s0", up: true, ipv4: true})
	detected, err := host.DetectPublicInterface(context.Background())
	if err != nil || detected.Name != "enp1s0" {
		t.Fatalf("detected %+v, %v; want enp1s0", detected, err)
	}
	vpnOnly := fakeHost(t, routeRunner{"1.1.1.1": "wg0"}, fakeInterface{name: "wg0", up: true, ipv4: true})
	if _, err := vpnOnly.DetectPublicInterface(context.Background()); err == nil {
		t.Fatal("a VPN interface must never be picked as the public interface")
	}
}

func TestDetectVPNInterfacePrefersRouteToDestinations(t *testing.T) {
	host := fakeHost(t, routeRunner{"100.64.0.5": "tailscale0", "100.64.0.6": "tailscale0", "10.66.0.2": "wg0", "8.8.8.8": "ens3"},
		fakeInterface{name: "ens3", up: true, ipv4: true},
		fakeInterface{name: "wg0", up: true, ipv4: true, wireGuard: true},
		fakeInterface{name: "tailscale0", up: true, ipv4: true},
	)
	detected := host.DetectVPNInterface(context.Background(), "ens3", []string{"100.64.0.5", "100.64.0.6", "100.64.0.5", "10.66.0.2", "8.8.8.8"})
	if detected.Name != "tailscale0" || detected.Reason != "routes to 2 of 4 forward destination(s)" {
		t.Fatalf("detected %+v; want tailscale0 chosen by routes", detected)
	}
}

func TestDetectVPNInterfaceAcceptsCustomNamedTunnelThatCarriesRoutes(t *testing.T) {
	host := fakeHost(t, routeRunner{"192.168.50.10": "homelink"},
		fakeInterface{name: "ens3", up: true, ipv4: true},
		fakeInterface{name: "homelink", up: true, ipv4: true},
	)
	if detected := host.DetectVPNInterface(context.Background(), "ens3", []string{"192.168.50.10"}); detected.Name != "homelink" {
		t.Fatalf("detected %+v; want the interface that routes to the destination", detected)
	}
}

func TestDetectVPNInterfacePrefersActiveTunnelWithoutRules(t *testing.T) {
	tests := []struct {
		name       string
		interfaces []fakeInterface
		want       string
		reason     string
	}{
		{"active beats down wg0", []fakeInterface{{name: "wg0"}, {name: "tailscale0", up: true, ipv4: true}}, "tailscale0", "active VPN interface"},
		{"wg0 preferred among active", []fakeInterface{{name: "tun0", up: true, ipv4: true}, {name: "wg0", up: true, ipv4: true}}, "wg0", "active VPN interface"},
		{"WireGuard device preferred among active", []fakeInterface{{name: "tun0", up: true, ipv4: true}, {name: "vpn", up: true, ipv4: true, wireGuard: true}}, "vpn", "active VPN interface"},
		{"up without address", []fakeInterface{{name: "wg1", up: true}}, "wg1", "VPN interface is up but has no IPv4 address"},
		{"only down tunnels", []fakeInterface{{name: "wg1"}}, "wg1", "VPN interface found but it is down"},
		{"nothing found", []fakeInterface{{name: "ens3", up: true, ipv4: true}}, "wg0", "no VPN interface found; using the default"},
	}
	for _, test := range tests {
		host := fakeHost(t, routeRunner{}, test.interfaces...)
		if detected := host.DetectVPNInterface(context.Background(), "ens3", nil); detected.Name != test.want || detected.Reason != test.reason {
			t.Errorf("%s: detected %+v, want %s (%s)", test.name, detected, test.want, test.reason)
		}
	}
}
