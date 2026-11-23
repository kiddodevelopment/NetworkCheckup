package checks

import (
	"context"
	"net"
	"sync"
	"time"
)

// facts are gathered once per run and shared by checks.
type facts struct {
	once     sync.Once
	routes   []Route
	routeErr error
	meta     map[string]IfaceMeta
	primary  *net.Interface // interface carrying the IPv4 default route
	local4   net.IP
	local6   net.IP
	gateway4 string
	gateway6 string

	gwOnce  sync.Once
	gwStats Stats
}

func (f *facts) load(ctx context.Context) {
	f.once.Do(func() {
		f.routes, f.routeErr = defaultRoutes(ctx)
		f.meta = ifaceInfo(ctx)
		// Ask the OS which source address it would use; UDP "connect" sends no packets.
		if c, err := net.Dial("udp4", "1.1.1.1:53"); err == nil {
			f.local4 = c.LocalAddr().(*net.UDPAddr).IP
			c.Close()
		}
		if c, err := net.Dial("udp6", "[2606:4700:4700::1111]:53"); err == nil {
			f.local6 = c.LocalAddr().(*net.UDPAddr).IP
			c.Close()
		}
		ifs, _ := net.Interfaces()
		for i := range ifs {
			addrs, _ := ifs[i].Addrs()
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && f.local4 != nil && n.IP.Equal(f.local4) {
					f.primary = &ifs[i]
				}
			}
		}
		for _, r := range f.routes {
			if r.V6 {
				if f.gateway6 == "" && (f.primary == nil || r.Iface == "" || r.Iface == f.primary.Name) {
					f.gateway6 = r.Gateway
				}
				continue
			}
			if f.gateway4 == "" && !r.Scoped && (f.primary == nil || r.Iface == f.primary.Name) {
				f.gateway4 = r.Gateway
			}
		}
		if f.gateway4 == "" {
			for _, r := range f.routes {
				if !r.V6 {
					f.gateway4 = r.Gateway
					break
				}
			}
		}
		if f.primary == nil && f.gateway4 != "" {
			for _, r := range f.routes {
				if r.Gateway == f.gateway4 {
					if i, err := net.InterfaceByName(r.Iface); err == nil {
						f.primary = i
					}
				}
			}
		}
	})
}

func (f *facts) kind(name string) IfaceMeta {
	if m, ok := f.meta[name]; ok {
		if m.Kind == "Other" && looksLikeTunnel(name, m.Description) {
			m.Kind = "VPN/tunnel"
		}
		return m
	}
	if looksLikeTunnel(name, "") {
		return IfaceMeta{Kind: "VPN/tunnel"}
	}
	return IfaceMeta{Kind: "Other"}
}

// gateway pings the IPv4 gateway once and caches the result for other checks.
func (f *facts) gateway(ctx context.Context) Stats {
	f.gwOnce.Do(func() {
		if f.gateway4 == "" {
			return
		}
		f.gwStats = probe(ctx, f.gateway4, 20, 150*time.Millisecond, []string{"80", "443", "53"})
	})
	return f.gwStats
}
