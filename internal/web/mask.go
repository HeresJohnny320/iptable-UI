package web

import (
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// MaskURL hides most of the IP address in a web UI link so it can be shown
// on screen (screenshots, screen sharing) without giving the server away:
// http://203.0.113.5:8787/ becomes http://203.•••.•••.•••:8787/. Loopback
// and placeholder addresses are not secret and stay as they are.
func MaskURL(link string) string {
	parsed, err := url.Parse(link)
	if err != nil {
		return link
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		return link
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.IsLoopback() {
		return link
	}
	masked := host
	if address.Is4() {
		masked = strings.SplitN(host, ".", 2)[0] + ".•••.•••.•••"
	} else {
		masked = strings.SplitN(host, ":", 2)[0] + ":••••"
	}
	return strings.Replace(link, parsed.Host, net.JoinHostPort(masked, port), 1)
}

// MaskToken shows only the start of the sign-in token.
func MaskToken(token string) string {
	if len(token) <= 4 {
		return strings.Repeat("•", len(token))
	}
	return token[:4] + "••••••••"
}
