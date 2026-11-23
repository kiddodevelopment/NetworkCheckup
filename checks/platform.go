package checks

import (
	"net"
	"strings"
)

// Route is a default route.
type Route struct {
	Gateway string
	Iface   string
	V6      bool
	Scoped  bool // macOS interface-scoped duplicate
}

// IfaceMeta is OS-specific detail about an interface.
type IfaceMeta struct {
	Kind        string // Wi-Fi, Ethernet, VPN/tunnel, Loopback, Other
	Description string
	Speed       string
}

// DNSServer is one configured resolver.
type DNSServer struct {
	Addr   string
	Iface  string
	Domain string // non-empty for split/scoped DNS
}

// ProxySetting is one proxy configuration item.
type ProxySetting struct {
	Source string
	Kind   string
	Value  string
}

// Listener is a socket waiting for connections.
type Listener struct {
	Proto   string
	Addr    string
	Port    int
	PID     int
	Process string
}

var tunnelPrefixes = []string{"utun", "tun", "tap", "wg", "ppp", "ipsec", "gpd", "zt", "tailscale", "nordlynx", "proton", "vpn", "cscotun", "ham"}

func looksLikeTunnel(name, desc string) bool {
	n := strings.ToLower(name)
	for _, p := range tunnelPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	d := strings.ToLower(desc + " " + name)
	for _, k := range []string{"vpn", "wireguard", "tap-windows", "tunnel", "openvpn", "anyconnect", "globalprotect", "fortinet", "zscaler", "tailscale", "zerotier", "wintun"} {
		if strings.Contains(d, k) {
			return true
		}
	}
	return false
}

// usableAddrs lists an interface's addresses, skipping IPv6 link-local.
func usableAddrs(ifc net.Interface) (v4, v6 []*net.IPNet, linkLocal4 bool) {
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if n.IP.To4() != nil {
			v4 = append(v4, n)
			if n.IP.IsLinkLocalUnicast() {
				linkLocal4 = true
			}
		} else if !n.IP.IsLinkLocalUnicast() {
			v6 = append(v6, n)
		}
	}
	return
}
