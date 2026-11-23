package checks

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"netcheckup/engine"
)

func (f *facts) linkCheck(ctx context.Context, _ *engine.Env, r *engine.Result) {
	f.load(ctx)
	if f.routeErr != nil {
		r.Limit("Could not read the routing table: " + f.routeErr.Error())
	}
	if f.primary == nil {
		r.Summary = "No active network connection found."
		r.Add(engine.Bad, "Not connected", "This computer has no route to the internet. Check that Wi-Fi is on and joined, or that the network cable is plugged in.")
		f.interfaceTable(r)
		return
	}
	meta := f.kind(f.primary.Name)
	v4, v6, ll4 := usableAddrs(*f.primary)
	kind := meta.Kind
	if kind == "Other" {
		kind = "network"
	}
	r.Summary = fmt.Sprintf("Connected over %s (%s)", kind, f.primary.Name)
	if len(v4) > 0 {
		r.Summary += ", IP " + v4[0].IP.String()
	}
	r.Status = engine.Good
	r.Detail("Interface", f.primary.Name)
	if meta.Description != "" {
		r.Detail("Adapter", meta.Description)
	}
	r.Detail("Type", meta.Kind)
	for _, a := range v4 {
		ones, _ := a.Mask.Size()
		r.Detail("IPv4 address", fmt.Sprintf("%s/%d (mask %s)", a.IP, ones, net.IP(a.Mask).String()))
	}
	for _, a := range v6 {
		r.Detail("IPv6 address", a.String())
	}
	r.Detail("Default gateway (IPv4)", orDash(f.gateway4))
	r.Detail("Default gateway (IPv6)", orDash(f.gateway6))
	r.Detail("MAC address", orDash(f.primary.HardwareAddr.String()))
	r.Detail("MTU", fmt.Sprint(f.primary.MTU))
	if meta.Speed != "" {
		r.Detail("Link speed", meta.Speed)
	}
	if ll4 && (len(v4) == 1) {
		r.Add(engine.Bad, "Self-assigned address (169.254.x.x)", "The router never handed this computer an address (DHCP failed). Try turning Wi-Fi off and on, reconnecting the cable, or restarting the router.")
	}
	if f.gateway4 == "" && len(v4) > 0 {
		r.Add(engine.Bad, "No default gateway", "The computer has an address but no router to send internet traffic to. Usually a DHCP or router problem.")
	}
	if len(v4) == 0 && len(v6) > 0 {
		r.Add(engine.Warn, "IPv6 only", "There is no IPv4 address. Most sites still work, but some older services and devices need IPv4.")
	}
	if meta.Kind == "VPN/tunnel" {
		r.Add(engine.Info, "Traffic leaves through a VPN", "The main route goes through a VPN or tunnel, so speed and reachability depend on the VPN server, not only your local network.")
	}
	if meta.Kind == "Wi-Fi" {
		r.Limit("Wi-Fi signal strength and channel details are planned for a later version.")
	}
	if !strings.EqualFold(meta.Kind, "VPN/tunnel") && len(v4) > 0 && !isPrivate(v4[0].IP) && !v4[0].IP.IsLinkLocalUnicast() {
		r.Add(engine.Info, "Public IP directly on this computer", "This computer has a public address with no router translating for it. That is unusual at home; make sure the firewall is on.")
	}
	f.interfaceTable(r)
}

func (f *facts) interfaceTable(r *engine.Result) {
	ifs, _ := net.Interfaces()
	t := engine.Table{Title: "All interfaces", Columns: []string{"Name", "Type", "Status", "IPv4", "IPv6 (global)", "MAC", "MTU"}}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		v4, v6, _ := usableAddrs(i)
		if len(v4) == 0 && len(v6) == 0 && i.Flags&net.FlagUp == 0 {
			continue
		}
		status := "down"
		if i.Flags&net.FlagUp != 0 {
			status = "up"
		}
		t.Rows = append(t.Rows, []string{i.Name, f.kind(i.Name).Kind, status, joinNets(v4), joinNets(v6), i.HardwareAddr.String(), fmt.Sprint(i.MTU)})
	}
	r.Tables = append(r.Tables, t)
}

func joinNets(ns []*net.IPNet) string {
	var s []string
	for _, n := range ns {
		s = append(s, n.String())
	}
	return strings.Join(s, ", ")
}

func orDash(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func (f *facts) vpnCheck(ctx context.Context, _ *engine.Env, r *engine.Result) {
	f.load(ctx)
	r.Status = engine.Good
	// Tunnel interfaces that carry a real (non link-local) address.
	var tunnels []string
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		m := f.kind(i.Name)
		v4, v6, _ := usableAddrs(i)
		if m.Kind == "VPN/tunnel" && (len(v4) > 0 || len(v6) > 0) {
			tunnels = append(tunnels, i.Name)
			r.Detail("Tunnel interface", fmt.Sprintf("%s %s %s", i.Name, joinNets(v4), m.Description))
		}
	}
	services, err := vpnServices(ctx)
	for _, s := range services {
		r.Detail("Connected VPN profile", s)
	}
	if err != nil && len(services) == 0 {
		r.Limits = append(r.Limits, "Could not list system VPN profiles; tunnel interfaces were still checked.")
	}
	full := f.primary != nil && f.kind(f.primary.Name).Kind == "VPN/tunnel"
	switch {
	case full:
		r.Summary = "A VPN is carrying all internet traffic."
		r.Add(engine.Info, "Full-tunnel VPN active", "All traffic goes through the VPN. This can hide local devices like printers and TVs, block hotel or guest Wi-Fi login pages, and make speed depend on the VPN server's distance.")
	case len(tunnels) > 0 || len(services) > 0:
		r.Summary = "A VPN or tunnel is connected, but normal internet traffic goes around it (split tunnel)."
		r.Add(engine.Info, "Split-tunnel VPN active", "Only some destinations (often work networks) go through the VPN. If a work site fails, the VPN's routes or DNS are the first thing to check.")
	default:
		r.Summary = "No VPN detected."
	}

	// Proxies: environment variables plus OS settings.
	var proxies []ProxySetting
	seenEnv := map[string]bool{}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if v := os.Getenv(k); v != "" && !seenEnv[strings.ToUpper(k)+v] {
			seenEnv[strings.ToUpper(k)+v] = true
			proxies = append(proxies, ProxySetting{"Environment variable", k, v})
		}
	}
	sys, err := proxySettings(ctx)
	if err != nil {
		r.Limits = append(r.Limits, "Could not read system proxy settings: "+err.Error())
	}
	proxies = append(proxies, sys...)
	if len(proxies) > 0 {
		t := engine.Table{Title: "Proxy settings", Columns: []string{"Source", "Kind", "Value"}}
		for _, p := range proxies {
			t.Rows = append(t.Rows, []string{p.Source, p.Kind, p.Value})
		}
		r.Tables = append(r.Tables, t)
		reach := ""
		for _, p := range proxies {
			if strings.Contains(p.Kind, "PAC") || strings.Contains(p.Kind, "WPAD") {
				continue
			}
			host := p.Value
			if i := strings.Index(host, "://"); i >= 0 {
				host = host[i+3:]
			}
			host = strings.TrimSuffix(strings.SplitN(host, "/", 2)[0], ";")
			if strings.Contains(host, "=") { // Windows "http=host:port;https=..."
				host = strings.SplitN(strings.SplitN(host, ";", 2)[0], "=", 2)[1]
			}
			d := net.Dialer{Timeout: 2 * time.Second}
			if c, err := d.DialContext(ctx, "tcp", host); err == nil {
				c.Close()
			} else {
				reach = host
			}
		}
		if reach != "" {
			r.Add(engine.Bad, "Proxy server not reachable", fmt.Sprintf("Apps are told to send web traffic through %s, but it does not answer. This is a classic \"Wi-Fi works but nothing loads\" cause, often left over from a work network.", reach))
		} else {
			r.Add(engine.Warn, "A proxy is configured", "Web traffic is routed through a proxy. That is normal on work networks; elsewhere a stale proxy can slow browsing or break login pages.")
		}
		r.Summary += fmt.Sprintf(" %d proxy setting(s) found.", len(proxies))
	} else {
		r.Summary += " No proxy configured."
	}
}

// ipv6Check compares connection setup time over IPv4 and IPv6 to the same sites.
func (f *facts) ipv6Check(ctx context.Context, _ *engine.Env, r *engine.Result) {
	f.load(ctx)
	hosts := []string{"www.google.com", "www.cloudflare.com", "www.wikipedia.org"}
	has6 := f.local6 != nil && !f.local6.IsLinkLocalUnicast()
	type res struct {
		host, fam string
		d         time.Duration
		err       error
	}
	var mu sync.Mutex
	var all []res
	var wg sync.WaitGroup
	for _, h := range hosts {
		for _, fam := range []string{"tcp4", "tcp6"} {
			if fam == "tcp6" && !has6 {
				continue
			}
			wg.Add(1)
			go func(h, fam string) {
				defer wg.Done()
				best := time.Duration(0)
				var lastErr error
				for i := 0; i < 3; i++ {
					d := net.Dialer{Timeout: 3 * time.Second}
					start := time.Now()
					c, err := d.DialContext(ctx, fam, h+":443")
					el := time.Since(start)
					if err != nil {
						lastErr = err
						continue
					}
					c.Close()
					if best == 0 || el < best {
						best = el
					}
				}
				mu.Lock()
				if best > 0 {
					all = append(all, res{h, fam, best, nil})
				} else {
					all = append(all, res{h, fam, 0, lastErr})
				}
				mu.Unlock()
			}(h, fam)
		}
	}
	wg.Wait()
	sort.Slice(all, func(a, b int) bool { return all[a].host+all[a].fam < all[b].host+all[b].fam })
	t := engine.Table{Title: "Connection setup time (best of 3, TCP 443)", Columns: []string{"Site", "Family", "Time (ms)", "Result"}}
	var ok4, ok6, fail4, fail6 int
	var sum4, sum6 float64
	for _, x := range all {
		status, tm := "ok", f1(ms(x.d))
		if x.err != nil {
			status, tm = shortErr(x.err), "-"
		}
		fam := "IPv4"
		if x.fam == "tcp6" {
			fam = "IPv6"
		}
		t.Rows = append(t.Rows, []string{x.host, fam, tm, status})
		switch {
		case x.fam == "tcp4" && x.err == nil:
			ok4++
			sum4 += ms(x.d)
		case x.fam == "tcp4":
			fail4++
		case x.err == nil:
			ok6++
			sum6 += ms(x.d)
		default:
			fail6++
		}
	}
	r.Tables = append(r.Tables, t)
	r.Status = engine.Good
	switch {
	case !has6:
		r.Summary = "IPv4 only. That is fine; nothing will stall waiting on IPv6."
		r.Status = engine.Info
	case ok6 == 0 && fail6 > 0:
		r.Summary = "IPv6 is configured but does not work."
		r.Add(engine.Bad, "Broken IPv6", "This computer has an IPv6 address but cannot reach sites over it. Apps may try IPv6 first and wait for it to time out, which feels like slow page loads. Restarting the router or turning off IPv6 on it usually fixes this.")
	case fail6 > 0:
		r.Summary = "IPv6 works only partly."
		r.Add(engine.Warn, "Patchy IPv6", "Some sites failed over IPv6 while working over IPv4. That can cause occasional slow loads.")
	case ok4 > 0 && ok6 > 0 && sum6/float64(ok6) > 1.5*sum4/float64(ok4)+30:
		r.Summary = fmt.Sprintf("IPv6 works but is slower (%.0f ms vs %.0f ms).", sum6/float64(ok6), sum4/float64(ok4))
		r.Add(engine.Warn, "IPv6 slower than IPv4", "Most apps prefer IPv6, so a slower IPv6 path makes everything feel a little slower.")
	default:
		r.Summary = "IPv4 and IPv6 both work cleanly."
	}
	if ok4 == 0 && fail4 > 0 {
		nameFail := true
		for _, x := range all {
			if x.err != nil && shortErr(x.err) != "name not found" {
				nameFail = false
			}
		}
		if nameFail {
			r.Status = engine.Limited
			r.Summary = "Could not compare IPv4 and IPv6 because the test site names did not resolve. See the DNS cards."
		} else {
			r.Summary = "Secure web connections are failing."
			r.Add(engine.Bad, "Web connections failing", "Secure (HTTPS) connections to major sites did not complete. See the internet and captive portal cards.")
		}
	}
	r.Detail("Source IPv4", ipOrNone(f.local4))
	r.Detail("Source IPv6", ipOrNone(f.local6))
}

func ipOrNone(ip net.IP) string {
	if ip == nil {
		return "none"
	}
	return ip.String()
}

func shortErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "i/o timeout"):
		return "timed out"
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "no such host"):
		return "name not found"
	case strings.Contains(s, "unreachable"):
		return "unreachable"
	}
	if len(s) > 60 {
		s = s[len(s)-60:]
	}
	return s
}
