package checks

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"netcheckup/engine"
)

const (
	SecLAN = "Local Network Devices & Services"

	maxScanHosts = 1024 // a /22; bigger subnets only use the neighbor table
	probesPerSec = 50
)

// Device is one thing found on the local network.
type Device struct {
	IP, MAC, Vendor string
	Random          bool
	Gateway, Self   bool
	Names           []string // best first
	Services        []string // mDNS service types
	Model           string
	UPnP            *ssdpInfo
	Ports           []portResult
	Type, Label     string
	Unidentified    bool
}

type lanScan struct {
	f        *facts
	progress func(string)
	once     sync.Once
	devices  []*Device
	limits   []string
	scanned  int
	subnet   string
	err      string
}

// LAN returns the opt-in network scan checks. progress may be nil.
func LAN(progress func(string)) []engine.Check {
	s := &lanScan{f: &facts{}, progress: progress}
	return []engine.Check{
		{ID: "lan-devices", Section: SecLAN, Title: "Devices on your network", Timeout: 150 * time.Second, Run: s.devicesCheck},
		{ID: "lan-services", Section: SecLAN, Title: "Services other devices expose", Timeout: 150 * time.Second, Run: s.servicesCheck},
	}
}

func (s *lanScan) say(msg string) {
	if s.progress != nil {
		s.progress(msg)
	}
}

func (s *lanScan) run(ctx context.Context) {
	s.once.Do(func() { s.scan(ctx) })
}

func (s *lanScan) scan(ctx context.Context) {
	f := s.f
	f.load(ctx)
	if f.primary == nil {
		s.err = "This computer is not connected to a network."
		return
	}
	if f.kind(f.primary.Name).Kind == "VPN/tunnel" {
		s.err = "All traffic is going through a VPN, so your local network can't be seen. Disconnect the VPN and scan again."
		return
	}
	var subnet *net.IPNet
	v4, _, _ := usableAddrs(*f.primary)
	for _, n := range v4 {
		if !n.IP.IsLinkLocalUnicast() {
			subnet = n
		}
	}
	if subnet == nil {
		s.err = "This computer has no usable IPv4 address on the local network."
		return
	}
	if !subnet.IP.IsPrivate() {
		s.err = "The scan only runs on private home or office networks (addresses like 192.168.x.x or 10.x.x.x)."
		return
	}
	ones, bits := subnet.Mask.Size()
	s.subnet = fmt.Sprintf("%s/%d", subnet.IP.Mask(subnet.Mask), ones)
	self := subnet.IP.String()

	lim := newLimiter(probesPerSec)
	defer lim.stop()

	// 1. Gentle sweep so the neighbor table fills in.
	hosts := hostsIn(subnet)
	if bits-ones > 10 {
		s.limits = append(s.limits, fmt.Sprintf("Your network (%s) is larger than %d addresses, so only devices this computer has recently talked to were checked.", s.subnet, maxScanHosts))
		hosts = nil
	}
	if len(hosts) > 0 {
		s.say(fmt.Sprintf("Saying hello to %d addresses on %s…", len(hosts), s.subnet))
	}
	var alive map[string]bool
	var md map[string]*mdnsInfo
	var ss map[string]*ssdpInfo
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); alive = sweep(ctx, hosts, lim) }()
	go func() { defer wg.Done(); md = mdnsDiscover(ctx, 4*time.Second) }()
	go func() { defer wg.Done(); ss = ssdpDiscover(ctx, 4*time.Second) }()
	wg.Wait()
	s.scanned = len(hosts)

	neigh, err := neighborTable(ctx)
	if err != nil {
		s.limits = append(s.limits, "Could not read the neighbor (ARP) table: "+err.Error())
	}

	// 2. Merge everything we heard about into devices.
	byIP := map[string]*Device{}
	add := func(ip string) *Device {
		p := net.ParseIP(ip)
		if p == nil || p.To4() == nil || !subnet.Contains(p) {
			return nil
		}
		d := byIP[ip]
		if d == nil {
			d = &Device{IP: ip}
			byIP[ip] = d
		}
		return d
	}
	for ip, mac := range neigh {
		if d := add(ip); d != nil {
			d.MAC = mac
		}
	}
	for ip := range alive {
		add(ip)
	}
	for ip := range md {
		add(ip)
	}
	for ip := range ss {
		add(ip)
	}
	if d := add(self); d != nil {
		d.Self = true
		d.MAC = f.primary.HardwareAddr.String()
	}
	if d := add(f.gateway4); d != nil {
		d.Gateway = true
	}

	// 3. Names, vendors and services.
	s.say(fmt.Sprintf("Found %d devices. Looking up names and checking common services…", len(byIP)))
	var mu sync.Mutex
	sem := make(chan struct{}, 8)
	for _, d := range byIP {
		if d.MAC != "" {
			d.Vendor = macVendor(d.MAC)
			d.Random = randomMAC(d.MAC)
		}
		if m := md[d.IP]; m != nil {
			for h := range m.Hosts {
				d.Names = append(d.Names, h)
			}
			for inst := range m.Instances {
				d.Names = append([]string{inst}, d.Names...)
			}
			for svc := range m.Services {
				d.Services = append(d.Services, svc)
			}
			sort.Strings(d.Services)
			for _, k := range []string{"model", "md", "usb_mdl", "ty", "am", "product"} {
				if v := m.TXT[k]; v != "" {
					d.Model = v
					break
				}
			}
		}
		d.UPnP = ss[d.IP]
		wg.Add(1)
		go func(d *Device) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			names, _ := net.DefaultResolver.LookupAddr(lctx, d.IP)
			cancel()
			nb := ""
			if !d.Self {
				nb = netbiosName(ctx, d.IP)
			}
			var ports []portResult
			if !d.Self {
				ports = probeHost(ctx, d.IP, lim)
			}
			mu.Lock()
			for _, n := range names {
				n = strings.TrimSuffix(n, ".")
				if n != "" && !strings.HasSuffix(n, ".in-addr.arpa") {
					d.Names = append(d.Names, n)
				}
			}
			if nb != "" {
				d.Names = append(d.Names, nb)
			}
			sort.Slice(ports, func(a, b int) bool { return ports[a].Port < ports[b].Port })
			d.Ports = ports
			mu.Unlock()
		}(d)
	}
	wg.Wait()

	for _, d := range byIP {
		d.Names = uniq(d.Names)
		classify(d)
		s.devices = append(s.devices, d)
	}
	sort.Slice(s.devices, func(a, b int) bool { return ipLess(s.devices[a].IP, s.devices[b].IP) })
}

func hostsIn(n *net.IPNet) []net.IP {
	ones, bits := n.Mask.Size()
	if bits-ones > 10 || bits != 32 {
		return nil
	}
	base := binary.BigEndian.Uint32(n.IP.Mask(n.Mask).To4())
	size := uint32(1) << uint(bits-ones)
	var out []net.IP
	for i := uint32(1); i+1 < size; i++ { // skip network and broadcast
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base+i)
		out = append(out, ip)
	}
	return out
}

func ipLess(a, b string) bool {
	x, y := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if x == nil || y == nil {
		return a < b
	}
	return binary.BigEndian.Uint32(x) < binary.BigEndian.Uint32(y)
}

func (d *Device) has(svc ...string) bool {
	for _, s := range d.Services {
		for _, x := range svc {
			if s == x {
				return true
			}
		}
	}
	return false
}

func (d *Device) open(ports ...int) bool {
	for _, p := range d.Ports {
		for _, x := range ports {
			if p.Port == x {
				return true
			}
		}
	}
	return false
}

func containsAny(s string, words ...string) bool {
	s = strings.ToLower(s)
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// classify turns everything known about a device into a plain-English type.
func classify(d *Device) {
	up := ""
	if d.UPnP != nil {
		up = strings.Join([]string{d.UPnP.FriendlyName, d.UPnP.Manufacturer, d.UPnP.Model, d.UPnP.DeviceType, d.UPnP.Server}, " ")
	}
	all := strings.Join(append([]string{d.Vendor, d.Model, up}, d.Names...), " ")
	switch {
	case d.Self:
		d.Type = "This computer"
	case d.Gateway:
		d.Type = "Router / gateway"
	case d.has("_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp") || d.open(9100) || containsAny(up, "printer"):
		d.Type = "Printer"
	case d.has("_googlecast._tcp") || d.open(8008) && containsAny(all, "google"):
		d.Type = "Chromecast / Google TV or speaker"
	case d.has("_sonos._tcp") || containsAny(all, "sonos"):
		d.Type = "Sonos speaker"
	case d.has("_roku._tcp") || containsAny(all, "roku"):
		d.Type = "Roku streaming device"
	case d.has("_amzn-wplay._tcp") || containsAny(all, "amazon technologies", "echo", "fire tv"):
		d.Type = "Amazon Echo / Fire TV"
	case d.has("_airplay._tcp") && containsAny(all, "appletv", "apple tv"):
		d.Type = "Apple TV"
	case d.has("_airplay._tcp", "_raop._tcp") && !d.has("_companion-link._tcp", "_smb._tcp"):
		d.Type = "AirPlay TV or speaker"
	case containsAny(all, "mediarenderer", "smart tv", "smarttv", "lg electronics", "samsung electronics", "vizio", "tcl", "hisense") && (d.UPnP != nil || d.has("_airplay._tcp")):
		d.Type = "Smart TV"
	case d.has("_rtsp._tcp") || d.open(554) || containsAny(all, "hikvision", "dahua", "reolink", "wyze", "ring", "arlo", "amcrest", "camera", "ipcam"):
		d.Type = "Camera or doorbell"
	case d.has("_hap._tcp", "_matter._tcp", "_home-assistant._tcp") || containsAny(all, "philips lighting", "signify", "ecobee", "nest", "tuya", "espressif", "shelly", "lifx", "tp-link smart", "wemo"):
		d.Type = "Smart home device"
	case d.open(62078) || containsAny(all, "iphone", "ipad"):
		d.Type = "iPhone or iPad"
	case containsAny(all, "synology", "qnap", "western digital", "nas", "truenas", "unraid") || d.open(5000) && d.open(445) && !d.has("_companion-link._tcp"):
		d.Type = "Network storage (NAS)"
	case d.open(32400):
		d.Type = "Media server (Plex)"
	case containsAny(all, "raspberry pi"):
		d.Type = "Raspberry Pi"
	case d.has("_companion-link._tcp") || d.has("_smb._tcp", "_afpovertcp._tcp") && containsAny(all, "apple", "mac"):
		d.Type = "Mac or Apple device"
	case d.open(3389) || d.open(445) && d.open(139) || containsAny(all, "desktop-", "laptop-"):
		d.Type = "Windows PC"
	case containsAny(all, "android", "galaxy", "pixel"):
		d.Type = "Phone or tablet"
	case containsAny(all, "netgear", "ubiquiti", "eero", "tp-link", "linksys", "asus", "aruba", "mikrotik", "google fiber") && (d.open(80) || d.open(443)):
		d.Type = "Wi-Fi access point or mesh node"
	case d.open(22):
		d.Type = "Computer or server"
	case d.Random:
		d.Type = "Phone, tablet or laptop (private address)"
	default:
		d.Type = "Unknown device"
	}
	name := ""
	if len(d.Names) > 0 {
		name = d.Names[0]
	} else if d.UPnP != nil && d.UPnP.FriendlyName != "" {
		name = d.UPnP.FriendlyName
	}
	d.Label = d.Type
	if name != "" {
		d.Label = name
	}
	d.Unidentified = name == "" && d.Vendor == "" && !d.Random && d.Type == "Unknown device"
}

func (s *lanScan) devicesCheck(ctx context.Context, _ *engine.Env, r *engine.Result) {
	s.run(ctx)
	if s.err != "" {
		r.Summary = "Network scan skipped."
		r.Limit(s.err)
		return
	}
	for _, l := range s.limits {
		r.Limit(l)
	}
	if r.Status == "" {
		r.Status = engine.Good
	}
	counts := map[string]int{}
	t := engine.Table{Title: "Devices", Columns: []string{"IP", "Name", "Type", "Maker (from MAC)", "MAC", "Announces"}}
	var unknown, private []string
	for _, d := range s.devices {
		counts[d.Type]++
		vendor := d.Vendor
		if d.Random {
			vendor = "private address (hidden)"
		}
		ann := strings.Join(d.Services, " ")
		if d.UPnP != nil {
			u := strings.TrimSpace(d.UPnP.Manufacturer + " " + d.UPnP.Model)
			if u == "" {
				u = d.UPnP.Server
			}
			ann = strings.TrimSpace(ann + " UPnP: " + u)
		}
		if d.Model != "" {
			ann = strings.TrimSpace("model " + d.Model + " " + ann)
		}
		name := ""
		if len(d.Names) > 0 {
			name = strings.Join(d.Names, ", ")
		}
		t.Rows = append(t.Rows, []string{d.IP, orDash(name), d.Type, orDash(vendor), orDash(d.MAC), ann})
		if d.Unidentified {
			unknown = append(unknown, d.IP)
		}
		if d.Type == "Phone, tablet or laptop (private address)" && len(d.Names) == 0 {
			private = append(private, d.IP)
		}
		if strings.HasPrefix(d.IP, "169.254.") {
			r.Add(engine.Warn, "Device without a proper address: "+d.IP, "This device gave itself a 169.254 address because the router did not hand it one. It probably can't reach the internet.")
		}
	}
	r.Tables = append(r.Tables, t)
	macs := map[string][]string{}
	for _, d := range s.devices {
		if d.MAC != "" && !d.Self {
			macs[d.MAC] = append(macs[d.MAC], d.IP)
		}
	}
	for mac, ips := range macs {
		if len(ips) > 1 {
			r.Add(engine.Info, "One device on several addresses", fmt.Sprintf("MAC %s answers for %s. Usually a device with more than one address (or a Wi-Fi extender); rarely, a sign of address spoofing.", mac, strings.Join(ips, ", ")))
		}
	}
	if len(unknown) > 0 {
		r.Add(engine.Warn, fmt.Sprintf("%d unidentified device(s)", len(unknown)), "No name, maker or announcement for: "+strings.Join(unknown, ", ")+". Often a smart plug or a device that keeps quiet, but if you don't recognise it, check your router's device list.")
	}
	if len(private) > 0 {
		r.Add(engine.Info, fmt.Sprintf("%d device(s) using private Wi-Fi addresses", len(private)), "Phones, tablets and laptops hide their real hardware address for privacy, so their maker can't be shown: "+strings.Join(private, ", ")+".")
	}
	var kinds []string
	for k, v := range counts {
		kinds = append(kinds, fmt.Sprintf("%d %s", v, strings.ToLower(k)))
	}
	sort.Strings(kinds)
	r.Summary = fmt.Sprintf("%d devices found on %s.", len(s.devices), s.subnet)
	r.Detail("Subnet", s.subnet)
	r.Detail("Addresses checked", fmt.Sprint(s.scanned))
	r.Detail("By type", strings.Join(kinds, "; "))
	r.Detail("Method", "neighbor table, one ping per address, mDNS/Bonjour, SSDP/UPnP, reverse DNS, NetBIOS names. No logins.")
}

func (s *lanScan) servicesCheck(ctx context.Context, _ *engine.Env, r *engine.Result) {
	s.run(ctx)
	if s.err != "" {
		r.Summary = "Network scan skipped."
		r.Limit(s.err)
		return
	}
	r.Status = engine.Good
	t := engine.Table{Title: "Open services", Columns: []string{"Device", "IP", "Port", "Service", "What it showed"}}
	group := map[string][]string{}
	total := 0
	for _, d := range s.devices {
		if d.Self {
			continue
		}
		hasTLS := d.open(443, 8443)
		for _, p := range d.Ports {
			total++
			t.Rows = append(t.Rows, []string{d.Label, d.IP, fmt.Sprint(p.Port), p.Name, p.Detail})
			who := fmt.Sprintf("%s (%s)", d.Label, d.IP)
			switch p.Port {
			case 23:
				group["telnet"] = append(group["telnet"], who)
			case 21:
				group["ftp"] = append(group["ftp"], who)
			case 80, 8080:
				if !hasTLS && !strings.Contains(p.Detail, "redirects to https") {
					group["http"] = append(group["http"], who)
				}
			case 3389, 5900:
				group["remote"] = append(group["remote"], fmt.Sprintf("%s port %d", who, p.Port))
			case 1883:
				group["mqtt"] = append(group["mqtt"], who)
			case 554:
				group["rtsp"] = append(group["rtsp"], who)
			}
		}
		if d.Gateway && d.UPnP != nil && d.UPnP.IGD {
			r.Add(engine.Info, "Router allows automatic port opening (UPnP)", "Your router lets devices on the network open ports to the internet by themselves. Games and video calls like this, but a compromised device could use it too. Turn UPnP off in the router if you don't need it.")
		}
	}
	r.Tables = append(r.Tables, t)
	if v := group["telnet"]; len(v) > 0 {
		r.Add(engine.Bad, "Telnet login open", "These accept Telnet, which sends passwords in plain text and is a favourite target of malware: "+strings.Join(v, "; ")+". Disable Telnet in the device's settings or update its firmware.")
	}
	if v := group["ftp"]; len(v) > 0 {
		r.Add(engine.Warn, "Unencrypted file transfer (FTP)", "FTP sends passwords and files unencrypted: "+strings.Join(v, "; ")+".")
	}
	if v := group["http"]; len(v) > 0 {
		r.Add(engine.Warn, "Admin pages without encryption", "These offer a web page over plain HTTP with no HTTPS option. A password typed there can be read by anyone else on the network: "+strings.Join(v, "; ")+".")
	}
	if v := group["remote"]; len(v) > 0 {
		r.Add(engine.Warn, "Remote control open on the network", "Remote Desktop or VNC is reachable from other devices: "+strings.Join(v, "; ")+". Turn it off where you don't use it, and make sure strong passwords are set where you do.")
	}
	if v := group["mqtt"]; len(v) > 0 {
		r.Add(engine.Info, "Smart home messaging (MQTT) without encryption", "An MQTT broker is running on "+strings.Join(v, "; ")+". Fine inside a home if it requires a password.")
	}
	if v := group["rtsp"]; len(v) > 0 {
		r.Add(engine.Info, "Video streams available", "These offer RTSP video streams, typical of cameras: "+strings.Join(v, "; ")+". Make sure each camera's default password was changed.")
	}
	r.Summary = fmt.Sprintf("%d open service(s) across %d device(s).", total, len(s.devices)-1)
	r.Detail("Ports checked per device", portList())
	r.Detail("Limits", fmt.Sprintf("at most %d new connections per second overall and 4 per device; one banner read or one page request per service; no logins.", probesPerSec))
}

func portList() string {
	var s []string
	for _, p := range lanPorts {
		s = append(s, fmt.Sprint(p.port))
	}
	return strings.Join(s, ", ")
}
