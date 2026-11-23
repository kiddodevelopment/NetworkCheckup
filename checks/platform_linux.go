//go:build linux

package checks

import (
	"context"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
)

// Linux support exists for development and testing; Windows and macOS are the targets.

func defaultRoutes(ctx context.Context) ([]Route, error) {
	var rs []Route
	for _, fam := range []string{"-4", "-6"} {
		out, err := run(ctx, "ip", fam, "route", "show", "default")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			r := Route{V6: fam == "-6"}
			for i := 0; i+1 < len(f); i++ {
				switch f[i] {
				case "via":
					r.Gateway = f[i+1]
				case "dev":
					r.Iface = f[i+1]
				}
			}
			if r.Gateway != "" {
				rs = append(rs, r)
			}
		}
	}
	if len(rs) == 0 { // fallback: /proc/net/route
		b, err := os.ReadFile("/proc/net/route")
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) > 2 && f[1] == "00000000" {
				g, _ := hex.DecodeString(f[2])
				if len(g) == 4 {
					rs = append(rs, Route{Gateway: net.IPv4(g[3], g[2], g[1], g[0]).String(), Iface: f[0]})
				}
			}
		}
	}
	return rs, nil
}

func ifaceInfo(ctx context.Context) map[string]IfaceMeta {
	m := map[string]IfaceMeta{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		meta := IfaceMeta{Kind: "Other"}
		switch {
		case i.Flags&net.FlagLoopback != 0:
			meta.Kind = "Loopback"
		case looksLikeTunnel(i.Name, ""):
			meta.Kind = "VPN/tunnel"
		default:
			if _, err := os.Stat("/sys/class/net/" + i.Name + "/wireless"); err == nil {
				meta.Kind = "Wi-Fi"
			} else if _, err := os.Stat("/sys/class/net/" + i.Name + "/device"); err == nil {
				meta.Kind = "Ethernet"
			}
		}
		if b, err := os.ReadFile("/sys/class/net/" + i.Name + "/speed"); err == nil {
			if v, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && v > 0 {
				meta.Speed = strconv.Itoa(v) + " Mbps"
			}
		}
		m[i.Name] = meta
	}
	return m
}

func dnsServers(ctx context.Context) ([]DNSServer, []string, error) {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, nil, err
	}
	var res []DNSServer
	var notes []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			res = append(res, DNSServer{Addr: f[1]})
			if f[1] == "127.0.0.53" {
				notes = append(notes, "systemd-resolved stub (127.0.0.53) forwards to the real upstream servers.")
			}
		}
	}
	return res, notes, nil
}

func proxySettings(ctx context.Context) ([]ProxySetting, error) { return nil, nil }

func vpnServices(ctx context.Context) ([]string, error) { return nil, nil }

func listeners(ctx context.Context) ([]Listener, []string, error) {
	var ls []Listener
	for _, f := range []struct{ file, proto, state string }{
		{"/proc/net/tcp", "tcp", "0A"}, {"/proc/net/tcp6", "tcp", "0A"},
		{"/proc/net/udp", "udp", "07"}, {"/proc/net/udp6", "udp", "07"},
	} {
		b, err := os.ReadFile(f.file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			x := strings.Fields(line)
			if len(x) < 4 || x[3] != f.state {
				continue
			}
			if f.proto == "udp" && x[2] != "00000000:0000" && !strings.HasPrefix(x[2], "0000000000000000") {
				continue
			}
			h, p, _ := strings.Cut(x[1], ":")
			port, _ := strconv.ParseInt(p, 16, 32)
			raw, _ := hex.DecodeString(h)
			ip := make(net.IP, len(raw))
			for i := 0; i < len(raw); i += 4 { // each 32-bit word is little-endian
				for j := 0; j < 4 && i+j < len(raw); j++ {
					ip[i+j] = raw[i+3-j]
				}
			}
			ls = append(ls, Listener{Proto: f.proto, Addr: ip.String(), Port: int(port)})
		}
	}
	return ls, []string{"Process names are not collected on Linux in this build."}, nil
}
