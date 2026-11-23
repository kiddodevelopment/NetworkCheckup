package checks

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"

	"netcheckup/engine"
)

type portInfo struct {
	name string
	risk engine.Status // status when exposed beyond loopback
	why  string
}

var cleartextWhy = "sends logins and data unencrypted; anyone on the same network can read them."
var dbWhy = "databases and caches usually have weak or no passwords by default and should listen on 127.0.0.1 only."
var devWhy = "looks like a development or app web server. Other devices on this network can open it; bind it to 127.0.0.1 unless you mean to share it."

var knownPorts = map[int]portInfo{
	21:    {"FTP file transfer", engine.Warn, cleartextWhy},
	22:    {"SSH remote login", engine.Info, "secure remote login. Fine if you turned it on; otherwise switch off Remote Login."},
	23:    {"Telnet", engine.Bad, cleartextWhy},
	53:    {"DNS server", engine.Info, "this computer answers DNS queries for others."},
	80:    {"Web server (HTTP)", engine.Warn, "an unencrypted web page other devices can open. If it is an admin page, its password travels in clear text."},
	135:   {"Windows RPC", engine.Info, "standard Windows system service."},
	139:   {"NetBIOS file sharing", engine.Info, "legacy Windows file sharing. Fine at home, best off on public Wi-Fi."},
	445:   {"SMB file sharing", engine.Info, "Windows/Mac file sharing. Normal at home and work; make sure the network is set to Public when on hotel or cafe Wi-Fi."},
	548:   {"AFP file sharing", engine.Info, "older Mac file sharing."},
	631:   {"Printer sharing (IPP)", engine.Info, "shares a printer with the network."},
	3000:  {"Dev web server", engine.Warn, devWhy},
	3283:  {"Apple Remote Desktop", engine.Warn, "remote control of this Mac. Turn it off if you do not use it."},
	3306:  {"MySQL database", engine.Warn, dbWhy},
	3389:  {"Remote Desktop (RDP)", engine.Warn, "remote control of this PC. A frequent attack target; keep it off unless you need it."},
	4200:  {"Dev web server", engine.Warn, devWhy},
	5000:  {"AirPlay receiver / app server", engine.Info, "on a Mac this is usually AirPlay Receiver; elsewhere often a development server."},
	5040:  {"Windows Connected Devices", engine.Info, "standard Windows service."},
	5173:  {"Dev web server (Vite)", engine.Warn, devWhy},
	5355:  {"LLMNR name lookup", engine.Info, "Windows local name lookup."},
	5357:  {"Windows network discovery", engine.Info, "standard Windows service."},
	5432:  {"PostgreSQL database", engine.Warn, dbWhy},
	5900:  {"VNC / Screen Sharing", engine.Warn, "remote screen control. Classic VNC is weakly protected; turn it off if you do not use it."},
	6379:  {"Redis", engine.Warn, dbWhy},
	7000:  {"AirPlay receiver", engine.Info, "lets nearby devices stream to this Mac."},
	7680:  {"Windows Update sharing", engine.Info, "Delivery Optimization shares updates with nearby PCs."},
	8000:  {"Dev web server", engine.Warn, devWhy},
	8080:  {"Web server (alt HTTP)", engine.Warn, devWhy},
	8888:  {"Dev web server / Jupyter", engine.Warn, devWhy},
	9200:  {"Elasticsearch", engine.Warn, dbWhy},
	11211: {"Memcached", engine.Warn, dbWhy},
	27017: {"MongoDB", engine.Warn, dbWhy},
}

func reachClass(addr string) (label string, exposed bool) {
	a := strings.SplitN(addr, "%", 2)[0]
	switch a {
	case "0.0.0.0", "::", "*", "":
		return "all interfaces (other devices can connect)", true
	}
	ip := net.ParseIP(a)
	if ip == nil {
		return addr, true
	}
	if ip.IsLoopback() {
		return "this computer only", false
	}
	return "network address " + a + " (devices on that network can connect)", true
}

func (f *facts) listenerCheck(ctx context.Context, _ *engine.Env, r *engine.Result) {
	ls, limits, err := listeners(ctx)
	for _, l := range limits {
		r.Limit(l)
	}
	if err != nil {
		r.Limit("Could not list listening sockets: " + err.Error())
		r.Summary = "Listening services could not be read."
		return
	}
	type key struct {
		proto string
		port  int
		exp   bool
	}
	seen := map[key]bool{}
	var rows [][]string
	var exposedTCP, localTCP, exposedUDP int
	sort.Slice(ls, func(a, b int) bool {
		if ls[a].Proto != ls[b].Proto {
			return ls[a].Proto < ls[b].Proto
		}
		return ls[a].Port < ls[b].Port
	})
	flagged := map[int]bool{}
	for _, l := range ls {
		label, exposed := reachClass(l.Addr)
		k := key{l.Proto, l.Port, exposed}
		if seen[k] {
			continue
		}
		seen[k] = true
		if l.Proto == "udp" && (l.Port >= 49152 || !exposed) {
			continue // ephemeral or local-only UDP is noise
		}
		if runtime.GOOS == "windows" && l.Proto == "tcp" && l.Port >= 49664 && l.Port <= 49700 && exposed {
			label += "; Windows system RPC"
		}
		svc := ""
		if p, ok := knownPorts[l.Port]; ok {
			svc = p.name
		}
		proc := l.Process
		if l.PID > 0 {
			proc = fmt.Sprintf("%s (pid %d)", orDash(l.Process), l.PID)
		}
		rows = append(rows, []string{strings.ToUpper(l.Proto), fmt.Sprint(l.Port), l.Addr, label, orDash(proc), svc})
		switch {
		case l.Proto == "tcp" && exposed:
			exposedTCP++
			if p, ok := knownPorts[l.Port]; ok && p.risk != engine.Info && !flagged[l.Port] {
				flagged[l.Port] = true
				who := ""
				if l.Process != "" {
					who = " (" + l.Process + ")"
				}
				r.Add(p.risk, fmt.Sprintf("%s open to the network on port %d%s", p.name, l.Port, who), "This "+p.why)
			}
		case l.Proto == "tcp":
			localTCP++
		default:
			exposedUDP++
		}
	}
	r.Tables = append(r.Tables, engine.Table{
		Title:   "Listening sockets",
		Columns: []string{"Proto", "Port", "Bound to", "Who can reach it", "Process", "Likely service"},
		Rows:    rows,
	})
	if r.Status == "" || r.Status == engine.Limited {
		if r.Status == "" {
			r.Status = engine.Good
		}
	}
	r.Summary = fmt.Sprintf("%d TCP service(s) reachable from other devices, %d local-only. %d UDP port(s) open to the network.", exposedTCP, localTCP, exposedUDP)
	r.Detail("Note", "\"Reachable\" means the program accepts outside connections. The OS firewall may still block them; firewall status is planned for a later version.")
}
