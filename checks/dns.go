package checks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"netcheckup/engine"
)

type dnsAnswer struct {
	RCode dnsmessage.RCode
	IPs   []string
	RTT   time.Duration
}

// dnsQuery sends one UDP DNS query for an A record directly to server.
func dnsQuery(ctx context.Context, server, name string, timeout time.Duration) (dnsAnswer, error) {
	var a dnsAnswer
	idb := make([]byte, 2)
	rand.Read(idb)
	id := uint16(idb[0])<<8 | uint16(idb[1])
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	b, err := msg.Pack()
	if err != nil {
		return a, err
	}
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return a, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := c.Write(b); err != nil {
		return a, err
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return a, err
		}
		var resp dnsmessage.Message
		if err := resp.Unpack(buf[:n]); err != nil || resp.ID != id {
			continue
		}
		a.RTT = time.Since(start)
		a.RCode = resp.RCode
		for _, ans := range resp.Answers {
			if r, ok := ans.Body.(*dnsmessage.AResource); ok {
				a.IPs = append(a.IPs, net.IP(r.A[:]).String())
			}
		}
		return a, nil
	}
}

var knownResolvers = map[string]string{
	"1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "1.1.1.2": "Cloudflare (malware filter)", "1.1.1.3": "Cloudflare (family filter)",
	"8.8.8.8": "Google", "8.8.4.4": "Google", "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
	"208.67.222.222": "Cisco OpenDNS", "208.67.220.220": "Cisco OpenDNS", "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
	"2606:4700:4700::1111": "Cloudflare", "2001:4860:4860::8888": "Google", "2620:fe::fe": "Quad9",
}

func describeServer(addr, gateway string) string {
	if n, ok := knownResolvers[addr]; ok {
		return n + " public DNS"
	}
	ip := net.ParseIP(strings.SplitN(addr, "%", 2)[0])
	switch {
	case ip == nil:
		return "unknown"
	case addr == gateway:
		return "your router (forwards to your provider)"
	case ip.IsLoopback():
		return "local resolver on this computer (VPN client, filter, or OS stub)"
	case ip.IsPrivate() || ip.IsLinkLocalUnicast():
		return "private network server (router, Pi-hole, or work DNS)"
	}
	return "public server (likely your internet provider)"
}

// usableServers returns unique unscoped servers worth querying directly.
func usableServers(servers []DNSServer) (out []string, skipped []string) {
	seen := map[string]bool{}
	for _, s := range servers {
		if s.Domain != "" || seen[s.Addr] {
			continue
		}
		seen[s.Addr] = true
		if strings.HasPrefix(strings.ToLower(s.Addr), "fec0:") {
			skipped = append(skipped, s.Addr)
			continue
		}
		out = append(out, s.Addr)
	}
	return
}

func (f *facts) dnsConfigCheck(ctx context.Context, _ *engine.Env, r *engine.Result) {
	f.load(ctx)
	servers, notes, err := dnsServers(ctx)
	if err != nil {
		r.Limit("Could not read DNS settings: " + err.Error())
	}
	r.Limits = append(r.Limits, notes...)
	if len(servers) == 0 && err == nil {
		r.Summary = "No DNS servers are configured."
		r.Add(engine.Bad, "No DNS servers", "Without DNS, names like google.com cannot be turned into addresses, so almost nothing loads.")
		return
	}
	t := engine.Table{Title: "Configured DNS servers", Columns: []string{"Server", "Interface", "Applies to", "What it is"}}
	var main []string
	vpnDNS := false
	for _, s := range servers {
		scope := "all lookups"
		if s.Domain != "" {
			scope = "only " + s.Domain
		}
		t.Rows = append(t.Rows, []string{s.Addr, orDash(s.Iface), scope, describeServer(s.Addr, f.gateway4)})
		if s.Domain == "" {
			main = append(main, s.Addr)
		}
		if s.Iface != "" && f.kind(s.Iface).Kind == "VPN/tunnel" {
			vpnDNS = true
		}
	}
	r.Tables = append(r.Tables, t)
	r.Status = engine.Good
	if len(main) > 0 {
		r.Summary = "Using " + strings.Join(uniq(main), ", ")
		r.Summary += " (" + describeServer(main[0], f.gateway4) + ")."
	} else {
		r.Summary = fmt.Sprintf("%d DNS server(s), all limited to specific domains.", len(servers))
	}
	if vpnDNS {
		r.Add(engine.Info, "VPN supplies DNS", "A VPN has installed its own DNS servers. If local names or some sites fail only while the VPN is on, its DNS is the likely cause.")
	}
	scoped := 0
	for _, s := range servers {
		if s.Domain != "" {
			scoped++
		}
	}
	if scoped > 0 {
		r.Add(engine.Info, "Split DNS in use", fmt.Sprintf("%d server(s) answer only for specific domains (common with work VPNs). Lookups for those domains bypass your normal DNS.", scoped))
	}
	if _, skipped := usableServers(servers); len(skipped) > 0 {
		r.Detail("Ignored placeholder servers", strings.Join(skipped, ", ")+" (Windows default when no IPv6 DNS is set)")
	}
	// Which resolver actually reaches the internet: Akamai answers with the resolver's own address.
	lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if ips, err := net.DefaultResolver.LookupHost(lctx, "whoami.akamai.net"); err == nil && len(ips) > 0 {
		eff := ips[0]
		r.Detail("Upstream resolver seen by the internet", eff)
		if names, err := net.DefaultResolver.LookupAddr(lctx, eff); err == nil && len(names) > 0 {
			r.Detail("Upstream resolver name", strings.TrimSuffix(names[0], "."))
		}
	} else {
		r.Limits = append(r.Limits, "Could not identify the upstream resolver (whoami lookup failed).")
	}
}

func uniq(s []string) []string {
	seen := map[string]bool{}
	var o []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			o = append(o, x)
		}
	}
	return o
}

var speedNames = []string{"google.com", "youtube.com", "wikipedia.org", "amazon.com", "microsoft.com", "apple.com", "netflix.com", "github.com"}

type serverTiming struct {
	server, label      string
	rtts               []time.Duration
	timeouts, servfail int
	err                error
}

func timeServer(ctx context.Context, server string) serverTiming {
	st := serverTiming{server: server}
	for round := 0; round < 2; round++ { // first pass may be uncached, second should be cached
		for _, n := range speedNames {
			a, err := dnsQuery(ctx, server, n, 2*time.Second)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					st.timeouts++
				} else {
					st.err = err
				}
				continue
			}
			if a.RCode == dnsmessage.RCodeServerFailure {
				st.servfail++
			}
			st.rtts = append(st.rtts, a.RTT)
		}
	}
	return st
}

func (f *facts) dnsSpeedCheck(ctx context.Context, _ *engine.Env, r *engine.Result) {
	f.load(ctx)
	servers, _, err := dnsServers(ctx)
	if err != nil {
		r.Limit("Could not read DNS settings, so only the system resolver was timed.")
	}
	direct, _ := usableServers(servers)
	if len(direct) > 4 {
		direct = direct[:4]
	}
	targets := append([]string{}, direct...)
	ref := "1.1.1.1"
	hasRef := false
	for _, d := range direct {
		if d == ref {
			hasRef = true
		}
	}
	if !hasRef {
		targets = append(targets, ref)
	}
	res := make([]serverTiming, len(targets))
	var wg sync.WaitGroup
	for i, s := range targets {
		wg.Add(1)
		go func(i int, s string) { defer wg.Done(); res[i] = timeServer(ctx, s) }(i, s)
	}
	// System resolver: includes the OS cache, which is what apps actually experience.
	var sysRTT []time.Duration
	sysFail := 0
	for _, n := range speedNames {
		start := time.Now()
		lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		_, err := net.DefaultResolver.LookupHost(lctx, n)
		cancel()
		if err != nil {
			sysFail++
		} else {
			sysRTT = append(sysRTT, time.Since(start))
		}
	}
	wg.Wait()
	t := engine.Table{Title: "Lookup times (8 names x 2 rounds, A records)", Columns: []string{"Server", "Role", "Answered", "Timeouts", "Median ms", "Slowest ms"}}
	t.Rows = append(t.Rows, []string{"system resolver", "what apps use (incl. OS cache)", fmt.Sprintf("%d/%d", len(sysRTT), len(speedNames)), fmt.Sprint(sysFail), f1(median(sysRTT)), f1(maxD(sysRTT))})
	r.Status = engine.Good
	var worst string
	for i, s := range res {
		role := "configured"
		if i >= len(direct) {
			role = "reference (Cloudflare)"
		}
		total := 2 * len(speedNames)
		t.Rows = append(t.Rows, []string{s.server, role, fmt.Sprintf("%d/%d", len(s.rtts), total), fmt.Sprint(s.timeouts), f1(median(s.rtts)), f1(maxD(s.rtts))})
		if role != "configured" {
			continue
		}
		med := median(s.rtts)
		switch {
		case len(s.rtts) == 0:
			if s.timeouts > 0 {
				r.Add(engine.Warn, "No direct answer from "+s.server, "This server did not answer direct queries. Some VPNs and security tools only let the system resolver through; if the system resolver row is healthy, browsing is unaffected.")
			} else if s.err != nil {
				r.Limits = append(r.Limits, "Could not query "+s.server+" directly: "+shortErr(s.err))
			}
		case s.timeouts >= 3:
			r.Add(engine.Bad, "DNS server drops queries: "+s.server, fmt.Sprintf("%d of %d lookups timed out. Each timeout stalls a page for a second or more (\"resolving host...\").", s.timeouts, total))
			worst = s.server
		case s.timeouts > 0:
			r.Add(engine.Warn, "Occasional DNS timeouts: "+s.server, fmt.Sprintf("%d of %d lookups timed out.", s.timeouts, total))
		case med > 150:
			r.Add(engine.Warn, "Slow DNS server: "+s.server, fmt.Sprintf("Median lookup %s ms. Healthy resolvers answer in under 50 ms; every new site you open waits on this.", f1(med)))
		}
		if s.servfail > 2 {
			r.Add(engine.Warn, "DNS server errors: "+s.server, fmt.Sprintf("%d lookups returned a server failure.", s.servfail))
		}
	}
	r.Tables = append(r.Tables, t)
	if sysFail > len(speedNames)/2 {
		r.Add(engine.Bad, "Name lookups failing", "Most test names did not resolve through the system. Browsing will fail even if the connection itself is up.")
	}
	sm := median(sysRTT)
	switch {
	case len(sysRTT) == 0 || sysFail > len(speedNames)/2:
		r.Summary = fmt.Sprintf("Name lookups are failing (%d of %d did not resolve).", sysFail, len(speedNames))
	case worst != "":
		r.Summary = fmt.Sprintf("Lookups work (median %s ms) but %s is dropping queries.", f1(sm), worst)
	default:
		r.Summary = fmt.Sprintf("Lookups take %s ms (median) through the system resolver.", f1(sm))
	}
	if sm > 200 {
		r.Add(engine.Warn, "Slow name lookups overall", "Apps wait over 200 ms just to find each site. Switching to a faster DNS provider often helps.")
	}
}

func maxD(ds []time.Duration) float64 {
	var m time.Duration
	for _, d := range ds {
		if d > m {
			m = d
		}
	}
	return ms(m)
}

func randLabel() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "nc-" + hex.EncodeToString(b)
}

func (f *facts) dnsIntegrityCheck(ctx context.Context, _ *engine.Env, r *engine.Result) {
	f.load(ctx)
	servers, _, _ := dnsServers(ctx)
	direct, _ := usableServers(servers)
	r.Status = engine.Good
	t := engine.Table{Title: "Integrity tests", Columns: []string{"Test", "Server", "Expected", "Got"}}

	// 1. A made-up name must not exist. Answers mean NXDOMAIN rewriting (ad/search pages).
	fake := randLabel() + ".com"
	lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	ips, err := net.DefaultResolver.LookupHost(lctx, fake)
	cancel()
	got := "not found"
	if err == nil {
		got = strings.Join(ips, ", ")
		r.Add(engine.Warn, "Made-up names resolve", "Looking up a name that does not exist returned an address. Some providers do this to show search or ad pages. It can break apps that rely on \"name not found\" errors and is a privacy concern.")
	}
	t.Rows = append(t.Rows, []string{"Nonexistent name " + fake, "system resolver", "not found", got})
	for _, s := range direct {
		a, err := dnsQuery(ctx, s, fake, 2*time.Second)
		g := "no answer"
		if err == nil {
			g = a.RCode.String()
			if len(a.IPs) > 0 {
				g = strings.Join(a.IPs, ", ")
			}
		}
		t.Rows = append(t.Rows, []string{"Nonexistent name", s, "RCodeNameError", g})
	}

	// 2. Filtering: a well-known ad domain answered with 0.0.0.0 or blocked = DNS filtering.
	lctx, cancel = context.WithTimeout(ctx, 4*time.Second)
	ips, err = net.DefaultResolver.LookupHost(lctx, "doubleclick.net")
	cancel()
	refAns, refErr := dnsQuery(ctx, "1.1.1.1", "doubleclick.net", 2*time.Second)
	filtered := false
	g := strings.Join(ips, ", ")
	if err != nil {
		g = shortErr(err)
		filtered = refErr == nil && len(refAns.IPs) > 0
	}
	for _, ip := range ips {
		if ip == "0.0.0.0" || strings.HasPrefix(ip, "127.") || ip == "::" {
			filtered = true
		}
	}
	t.Rows = append(t.Rows, []string{"Ad domain doubleclick.net", "system resolver", "real address unless filtered", g})
	if filtered {
		r.Add(engine.Info, "DNS filtering active", "A known ad/tracking domain is blocked at the DNS level (Pi-hole, NextDNS, router filter, or security software). Usually intentional; if a specific site breaks, this filter is a suspect.")
	}

	// 3. Interception: ask an address that runs no DNS server. Any answer means the
	// network silently redirects DNS traffic.
	a, err := dnsQuery(ctx, "192.0.2.53", "example.com", 1500*time.Millisecond)
	g = "no answer"
	if err == nil {
		g = fmt.Sprintf("answered (%s)", a.RCode)
		r.Add(engine.Warn, "DNS traffic is intercepted", "A query sent to an address with no DNS server still got an answer. The network (or security software) is redirecting all DNS, which overrides any DNS server you choose.")
	}
	t.Rows = append(t.Rows, []string{"Query to a non-DNS address 192.0.2.53", "-", "no answer", g})

	// 4. Agreement: configured servers should broadly agree with a reference for a stable name.
	var refIPs []string
	if ra, err := dnsQuery(ctx, "1.1.1.1", "example.com", 2*time.Second); err == nil {
		refIPs = ra.IPs
		sort.Strings(refIPs)
	}
	for _, s := range direct {
		ca, err := dnsQuery(ctx, s, "example.com", 2*time.Second)
		if err != nil || len(refIPs) == 0 {
			continue
		}
		sort.Strings(ca.IPs)
		g := strings.Join(ca.IPs, ", ")
		t.Rows = append(t.Rows, []string{"example.com matches reference", s, strings.Join(refIPs, ", "), g})
		if len(ca.IPs) > 0 && !overlap(ca.IPs, refIPs) {
			r.Add(engine.Warn, "Unexpected answer from "+s, "This server returned a different address for example.com than public DNS. That can mean a captive portal, a corporate override, or DNS hijacking.")
		}
	}
	r.Tables = append(r.Tables, t)
	if len(r.Findings) == 0 {
		r.Summary = "No signs of DNS tampering or filtering."
	} else {
		r.Summary = fmt.Sprintf("%d DNS behaviour(s) worth knowing about.", len(r.Findings))
	}
	r.Limits = append(r.Limits, "Encrypted DNS (DoH/DoT) posture is planned for a later version.")
}

func overlap(a, b []string) bool {
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if m[x] {
			return true
		}
	}
	return false
}
