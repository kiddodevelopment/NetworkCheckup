//go:build darwin

package checks

import (
	"bufio"
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"
)

func ifaceNames() map[string]bool {
	m := map[string]bool{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		m[i.Name] = true
	}
	return m
}

func defaultRoutes(ctx context.Context) ([]Route, error) {
	names := ifaceNames()
	var routes []Route
	var lastErr error
	for _, fam := range []string{"inet", "inet6"} {
		out, err := run(ctx, "netstat", "-rn", "-f", fam)
		if err != nil {
			lastErr = err
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 3 || f[0] != "default" || strings.HasPrefix(f[1], "link#") {
				continue
			}
			r := Route{Gateway: f[1], V6: fam == "inet6", Scoped: strings.Contains(f[2], "I")}
			for _, x := range f[2:] {
				if names[x] {
					r.Iface = x
				}
			}
			if i := strings.Index(r.Gateway, "%"); i > 0 && r.Iface == "" {
				r.Iface = r.Gateway[i+1:]
			}
			routes = append(routes, r)
		}
	}
	if len(routes) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return routes, nil
}

func ifaceInfo(ctx context.Context) map[string]IfaceMeta {
	m := map[string]IfaceMeta{}
	out, err := run(ctx, "networksetup", "-listallhardwareports")
	if err == nil {
		var port string
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "Hardware Port:") {
				port = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
			}
			if strings.HasPrefix(line, "Device:") {
				dev := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
				kind := "Other"
				pl := strings.ToLower(port)
				switch {
				case strings.Contains(pl, "wi-fi") || strings.Contains(pl, "airport"):
					kind = "Wi-Fi"
				case strings.Contains(pl, "ethernet") || strings.Contains(pl, "lan") || strings.Contains(pl, "thunderbolt"):
					kind = "Ethernet"
				}
				m[dev] = IfaceMeta{Kind: kind, Description: port}
			}
		}
	}
	// Ethernet negotiated speed from ifconfig media line.
	for dev, meta := range m {
		if meta.Kind != "Ethernet" {
			continue
		}
		if o, err := run(ctx, "ifconfig", dev); err == nil {
			if mm := regexp.MustCompile(`media: .*\((\S+)`).FindStringSubmatch(o); mm != nil {
				meta.Speed = mm[1]
				m[dev] = meta
			}
		}
	}
	return m
}

func dnsServers(ctx context.Context) ([]DNSServer, []string, error) {
	out, err := run(ctx, "scutil", "--dns")
	if err != nil {
		return nil, nil, err
	}
	// Only the first block ("DNS configuration") describes what the system uses.
	if i := strings.Index(out, "DNS configuration (for scoped queries)"); i > 0 {
		out = out[:i]
	}
	var res []DNSServer
	seen := map[string]bool{}
	for _, block := range strings.Split(out, "resolver #")[1:] {
		var domain, iface string
		var servers []string
		mdns := false
		for _, line := range strings.Split(block, "\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch {
			case k == "domain":
				domain = v
			case strings.HasPrefix(k, "nameserver["):
				servers = append(servers, v)
			case k == "if_index":
				if a, b, ok := strings.Cut(v, "("); ok {
					_ = a
					iface = strings.TrimSuffix(strings.TrimSpace(b), ")")
				}
			case k == "options" && strings.Contains(v, "mdns"):
				mdns = true
			}
		}
		if mdns {
			continue
		}
		for _, s := range servers {
			key := s + "|" + domain
			if seen[key] {
				continue
			}
			seen[key] = true
			res = append(res, DNSServer{Addr: s, Iface: iface, Domain: domain})
		}
	}
	return res, nil, nil
}

func proxySettings(ctx context.Context) ([]ProxySetting, error) {
	out, err := run(ctx, "scutil", "--proxy")
	if err != nil {
		return nil, err
	}
	kv := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), " : "); ok {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	var ps []ProxySetting
	for _, p := range []struct{ en, host, port, kind string }{
		{"HTTPEnable", "HTTPProxy", "HTTPPort", "HTTP proxy"},
		{"HTTPSEnable", "HTTPSProxy", "HTTPSPort", "HTTPS proxy"},
		{"SOCKSEnable", "SOCKSProxy", "SOCKSPort", "SOCKS proxy"},
	} {
		if kv[p.en] == "1" {
			ps = append(ps, ProxySetting{"System (macOS)", p.kind, kv[p.host] + ":" + kv[p.port]})
		}
	}
	if kv["ProxyAutoConfigEnable"] == "1" {
		ps = append(ps, ProxySetting{"System (macOS)", "Auto-config (PAC) file", kv["ProxyAutoConfigURLString"]})
	}
	if kv["ProxyAutoDiscoveryEnable"] == "1" {
		ps = append(ps, ProxySetting{"System (macOS)", "Auto proxy discovery (WPAD)", "on"})
	}
	return ps, nil
}

func vpnServices(ctx context.Context) ([]string, error) {
	out, err := run(ctx, "scutil", "--nc", "list")
	if err != nil {
		return nil, err
	}
	var names []string
	re := regexp.MustCompile(`"([^"]+)"`)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "(Connected)") {
			if m := re.FindStringSubmatch(line); m != nil {
				names = append(names, m[1])
			}
		}
	}
	return names, nil
}

// splitHostPort parses netstat/lsof style "addr.port" or "addr:port".
func splitDotPort(s string) (string, int) {
	i := strings.LastIndexAny(s, ".:")
	if i < 0 {
		return s, 0
	}
	p, _ := strconv.Atoi(s[i+1:])
	return s[:i], p
}

func listeners(ctx context.Context) ([]Listener, []string, error) {
	var ls []Listener
	var limits []string
	// netstat sees every socket, without process names.
	for _, proto := range []string{"tcp", "udp"} {
		out, err := run(ctx, "netstat", "-an", "-p", proto)
		if err != nil {
			return nil, nil, err
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 5 || !strings.HasPrefix(f[0], proto) {
				continue
			}
			if proto == "tcp" && (len(f) < 6 || f[5] != "LISTEN") {
				continue
			}
			if proto == "udp" && f[4] != "*.*" {
				continue
			}
			addr, port := splitDotPort(f[3])
			if addr == "*" {
				if strings.HasSuffix(f[0], "6") && !strings.HasSuffix(f[0], "46") {
					addr = "::"
				} else {
					addr = "0.0.0.0"
				}
			}
			ls = append(ls, Listener{Proto: proto, Addr: addr, Port: port})
		}
	}
	// lsof adds process names for this user's own processes.
	names := map[string]Listener{}
	for pi, args := range [][]string{{"-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"}, {"-nP", "-iUDP", "-F", "pcn"}} {
		proto := []string{"tcp", "udp"}[pi]
		out, _ := run(ctx, "lsof", args...)
		var pid int
		var cmd string
		for _, line := range strings.Split(out, "\n") {
			if line == "" {
				continue
			}
			switch line[0] {
			case 'p':
				pid, _ = strconv.Atoi(line[1:])
			case 'c':
				cmd = line[1:]
			case 'n':
				if strings.Contains(line, "->") {
					continue
				}
				_, port := splitDotPort(line[1:])
				names[proto+strconv.Itoa(port)] = Listener{PID: pid, Process: cmd}
			}
		}
	}
	missing := 0
	for i := range ls {
		if n, ok := names[ls[i].Proto+strconv.Itoa(ls[i].Port)]; ok {
			ls[i].PID, ls[i].Process = n.PID, n.Process
		} else {
			missing++
		}
	}
	if missing > 0 {
		limits = append(limits, "macOS only shows process names for your own apps without admin rights, so system services appear without a name.")
	}
	return ls, limits, nil
}
