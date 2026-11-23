package checks

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ---- MAC addresses and vendors ----

// Vendor prefixes derived from the IEEE OUI registry (via nmap-mac-prefixes).
//
//go:embed oui.txt.gz
var ouiGz []byte

var (
	ouiOnce sync.Once
	ouiMap  map[string]string
)

func normMAC(s string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(s)), ":")
	if len(parts) != 6 {
		return ""
	}
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		} else if len(p) != 2 {
			return ""
		}
	}
	mac := strings.Join(parts, ":")
	if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" || strings.HasPrefix(mac, "01:00:5e") || strings.HasPrefix(mac, "33:33") {
		return ""
	}
	return mac
}

// randomMAC reports a locally administered address: phones, tablets and
// laptops use these for Wi-Fi privacy, so the vendor cannot be known.
func randomMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	b, err := strconv.ParseUint(mac[:2], 16, 8)
	return err == nil && b&0x02 != 0
}

func macVendor(mac string) string {
	ouiOnce.Do(func() {
		ouiMap = map[string]string{}
		zr, err := gzip.NewReader(bytes.NewReader(ouiGz))
		if err != nil {
			return
		}
		sc := bufio.NewScanner(zr)
		for sc.Scan() {
			if k, v, ok := strings.Cut(sc.Text(), " "); ok {
				ouiMap[k] = v
			}
		}
	})
	if len(mac) < 8 {
		return ""
	}
	return ouiMap[strings.ToUpper(strings.ReplaceAll(mac[:8], ":", ""))]
}

// ---- Rate limiting shared by every probe in a scan ----

type limiter struct{ t *time.Ticker }

func newLimiter(perSecond int) *limiter {
	return &limiter{time.NewTicker(time.Second / time.Duration(perSecond))}
}

func (l *limiter) wait(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-l.t.C:
		return true
	}
}

func (l *limiter) stop() { l.t.Stop() }

// sweep sends one echo (or, if ICMP is not allowed, one TCP connect) to each
// address. Replies matter less than the side effect: the OS learns each
// device's MAC address, which then shows up in the neighbor table.
func sweep(ctx context.Context, hosts []net.IP, lim *limiter) map[string]bool {
	alive := map[string]bool{}
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	for w := 0; w < 32; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				ok := false
				if st, err := icmpPing(ctx, ip, 1, 0); err == nil {
					ok = st.Received > 0
				} else {
					d := net.Dialer{Timeout: 700 * time.Millisecond}
					c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "80"))
					if err == nil {
						c.Close()
						ok = true
					} else if isRefused(err) {
						ok = true
					}
				}
				if ok {
					mu.Lock()
					alive[ip] = true
					mu.Unlock()
				}
			}
		}()
	}
	for _, h := range hosts {
		if !lim.wait(ctx) {
			break
		}
		jobs <- h.String()
	}
	close(jobs)
	wg.Wait()
	return alive
}

// ---- mDNS / Bonjour ----

type mdnsInfo struct {
	Hosts     map[string]bool
	Services  map[string]bool // e.g. _airplay._tcp
	Instances map[string]bool // friendly instance names, e.g. "Living Room"
	TXT       map[string]string
}

var mdnsTypes = []string{
	"_services._dns-sd._udp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_ipp._tcp", "_ipps._tcp",
	"_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp", "_uscan._tcp", "_smb._tcp", "_afpovertcp._tcp",
	"_hap._tcp", "_companion-link._tcp", "_device-info._tcp", "_sonos._tcp", "_spotify-connect._tcp",
	"_http._tcp", "_ssh._tcp", "_rfb._tcp", "_amzn-wplay._tcp", "_matter._tcp", "_workstation._tcp",
	"_rtsp._tcp", "_androidtvremote2._tcp", "_roku._tcp", "_nvstream._tcp", "_home-assistant._tcp",
}

func mdnsDiscover(ctx context.Context, wait time.Duration) map[string]*mdnsInfo {
	res := map[string]*mdnsInfo{}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return res
	}
	defer c.Close()
	msg := dnsmessage.Message{}
	for _, t := range mdnsTypes {
		// Class with the top bit set asks responders to reply directly to us (QU).
		msg.Questions = append(msg.Questions, dnsmessage.Question{Name: dnsmessage.MustNewName(t + ".local."), Type: dnsmessage.TypePTR, Class: dnsmessage.Class(0x8001)})
	}
	pkt, err := msg.Pack()
	if err != nil {
		return res
	}
	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	c.WriteTo(pkt, dst)
	go func() {
		sleepCtx(ctx, 1200*time.Millisecond)
		c.WriteTo(pkt, dst)
	}()
	deadline := time.Now().Add(wait)
	buf := make([]byte, 9000)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		c.SetReadDeadline(deadline)
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			break
		}
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil {
			continue
		}
		ip := from.IP.String()
		info := res[ip]
		if info == nil {
			info = &mdnsInfo{Hosts: map[string]bool{}, Services: map[string]bool{}, Instances: map[string]bool{}, TXT: map[string]string{}}
			res[ip] = info
		}
		for _, rr := range append(append(m.Answers, m.Additionals...), m.Authorities...) {
			name := strings.TrimSuffix(rr.Header.Name.String(), ".")
			switch b := rr.Body.(type) {
			case *dnsmessage.AResource:
				if net.IP(b.A[:]).String() == ip {
					info.Hosts[strings.TrimSuffix(name, ".local")] = true
				}
			case *dnsmessage.PTRResource:
				target := strings.TrimSuffix(b.PTR.String(), ".")
				if strings.HasPrefix(name, "_services._dns-sd") {
					info.Services[svcType(target)] = true
				} else {
					info.Services[svcType(name)] = true
					if inst := instanceName(target); inst != "" {
						info.Instances[inst] = true
					}
				}
			case *dnsmessage.SRVResource:
				info.Services[svcType(name)] = true
				if inst := instanceName(name); inst != "" {
					info.Instances[inst] = true
				}
				info.Hosts[strings.TrimSuffix(strings.TrimSuffix(b.Target.String(), "."), ".local")] = true
			case *dnsmessage.TXTResource:
				for _, kv := range b.TXT {
					if k, v, ok := strings.Cut(kv, "="); ok && v != "" {
						switch strings.ToLower(k) {
						case "model", "md", "fn", "ty", "usb_mdl", "am", "manufacturer", "product":
							info.TXT[strings.ToLower(k)] = v
						}
					}
				}
			}
		}
	}
	return res
}

// svcType turns "Name._airplay._tcp.local" or "_airplay._tcp.local" into "_airplay._tcp".
func svcType(name string) string {
	name = strings.TrimSuffix(name, ".local")
	parts := strings.Split(name, ".")
	for i := 0; i+1 < len(parts); i++ {
		if strings.HasPrefix(parts[i], "_") && (parts[i+1] == "_tcp" || parts[i+1] == "_udp") {
			return parts[i] + "." + parts[i+1]
		}
	}
	return name
}

func instanceName(full string) string {
	i := strings.Index(full, "._")
	if i <= 0 {
		return ""
	}
	return strings.ReplaceAll(full[:i], `\032`, " ")
}

// ---- SSDP / UPnP ----

type ssdpInfo struct {
	Server       string
	Location     string
	IGD          bool // router offers UPnP port mapping
	FriendlyName string
	Manufacturer string
	Model        string
	DeviceType   string
}

func ssdpDiscover(ctx context.Context, wait time.Duration) map[string]*ssdpInfo {
	res := map[string]*ssdpInfo{}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return res
	}
	defer c.Close()
	req := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
	dst := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	c.WriteTo([]byte(req), dst)
	deadline := time.Now().Add(wait)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		c.SetReadDeadline(deadline)
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			break
		}
		ip := from.IP.String()
		info := res[ip]
		if info == nil {
			info = &ssdpInfo{}
			res[ip] = info
		}
		for _, line := range strings.Split(string(buf[:n]), "\r\n") {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch strings.ToUpper(strings.TrimSpace(k)) {
			case "SERVER":
				info.Server = v
			case "LOCATION":
				if info.Location == "" {
					info.Location = v
				}
			case "ST", "NT":
				if strings.Contains(v, "InternetGatewayDevice") || strings.Contains(v, "WANIPConnection") {
					info.IGD = true
				}
			}
		}
	}
	// One GET of each device's own description file, only on the device that announced it.
	var wg sync.WaitGroup
	var mu sync.Mutex
	client := &http.Client{Timeout: 2500 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for ip, info := range res {
		u := info.Location
		if u == "" || !strings.Contains(u, "//"+ip+":") && !strings.Contains(u, "//"+ip+"/") {
			continue
		}
		wg.Add(1)
		go func(info *ssdpInfo, u string) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			mu.Lock()
			info.FriendlyName = xmlTag(b, "friendlyName")
			info.Manufacturer = xmlTag(b, "manufacturer")
			info.Model = strings.TrimSpace(xmlTag(b, "modelName") + " " + xmlTag(b, "modelNumber"))
			info.DeviceType = xmlTag(b, "deviceType")
			if strings.Contains(string(b), "InternetGatewayDevice") {
				info.IGD = true
			}
			mu.Unlock()
		}(info, u)
	}
	wg.Wait()
	return res
}

func xmlTag(b []byte, tag string) string {
	re := regexp.MustCompile(`(?s)<` + tag + `>([^<]{1,120})</` + tag + `>`)
	if m := re.FindSubmatch(b); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

// ---- NetBIOS name (Windows PCs, NAS boxes) ----

func netbiosName(ctx context.Context, ip string) string {
	c, err := net.DialTimeout("udp4", net.JoinHostPort(ip, "137"), time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	q := []byte{0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, 'C', 'K'}
	q = append(q, bytes.Repeat([]byte("A"), 30)...)
	q = append(q, 0, 0, 0x21, 0, 1)
	c.SetDeadline(time.Now().Add(800 * time.Millisecond))
	if _, err := c.Write(q); err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil || n < 57 {
		return ""
	}
	off := 56 // header 12 + name 34 + type/class/ttl/len 10
	count := int(buf[off])
	off++
	for i := 0; i < count && off+18 <= n; i++ {
		name := strings.TrimSpace(string(buf[off : off+15]))
		suffix := buf[off+15]
		flags := binary.BigEndian.Uint16(buf[off+16 : off+18])
		off += 18
		if suffix == 0 && flags&0x8000 == 0 && name != "" {
			return name
		}
	}
	return ""
}

// ---- Service probes ----

type portDef struct {
	port int
	name string
	kind string // web, tls, banner, plain
}

var lanPorts = []portDef{
	{21, "FTP", "banner"}, {22, "SSH", "banner"}, {23, "Telnet", "plain"}, {53, "DNS", "plain"},
	{80, "Web (HTTP)", "web"}, {139, "NetBIOS file sharing", "plain"}, {443, "Web (HTTPS)", "tls"},
	{445, "SMB file sharing", "plain"}, {548, "AFP file sharing", "plain"}, {554, "RTSP video stream", "plain"},
	{631, "IPP printing", "plain"}, {1883, "MQTT (smart home, unencrypted)", "plain"}, {3389, "Remote Desktop", "plain"},
	{5000, "Web / AirPlay", "plain"}, {5900, "VNC screen sharing", "plain"}, {7000, "AirPlay", "plain"},
	{8008, "Chromecast", "plain"}, {8080, "Web (HTTP alt)", "web"}, {8443, "Web (HTTPS alt)", "tls"},
	{9100, "Raw printing (JetDirect)", "plain"}, {32400, "Plex media server", "plain"}, {62078, "Apple iPhone/iPad sync", "plain"},
}

type portResult struct {
	Port   int
	Name   string
	Detail string
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>\s*([^<]{1,100}?)\s*</title>`)

func probeHost(ctx context.Context, ip string, lim *limiter) []portResult {
	var out []portResult
	var mu sync.Mutex
	sem := make(chan struct{}, 4) // at most 4 connections per device
	var wg sync.WaitGroup
	for _, p := range lanPorts {
		if !lim.wait(ctx) {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(p portDef) {
			defer wg.Done()
			defer func() { <-sem }()
			addr := net.JoinHostPort(ip, strconv.Itoa(p.port))
			d := net.Dialer{Timeout: time.Second}
			c, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return
			}
			r := portResult{Port: p.port, Name: p.name}
			switch p.kind {
			case "banner":
				c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
				b := make([]byte, 200)
				n, _ := c.Read(b)
				r.Detail = strings.TrimSpace(strings.SplitN(string(b[:n]), "\n", 2)[0])
				c.Close()
			case "web":
				c.Close()
				r.Detail = httpSummary(ctx, "http://"+addr+"/")
			case "tls":
				c.Close()
				r.Detail = tlsSummary(ctx, addr)
				if t := httpSummary(ctx, "https://"+addr+"/"); t != "" {
					r.Detail = strings.TrimSpace(t + "; " + r.Detail)
				}
			default:
				c.Close()
			}
			mu.Lock()
			out = append(out, r)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return out
}

func httpSummary(ctx context.Context, u string) string {
	client := &http.Client{Timeout: 3 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "NetworkCheckup/0.3 (read-only check)")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var parts []string
	if m := titleRe.FindSubmatch(b); m != nil {
		parts = append(parts, fmt.Sprintf("%q", strings.Join(strings.Fields(string(m[1])), " ")))
	}
	if s := resp.Header.Get("Server"); s != "" {
		parts = append(parts, "server "+s)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		parts = append(parts, "redirects to "+resp.Header.Get("Location"))
	}
	if resp.StatusCode == 401 {
		parts = append(parts, "asks for a password")
	}
	return strings.Join(parts, ", ")
}

func tlsSummary(ctx context.Context, addr string) string {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: &tls.Config{InsecureSkipVerify: true}}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer c.Close()
	st := c.(*tls.Conn).ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return ""
	}
	cert := st.PeerCertificates[0]
	s := "certificate " + cert.Subject.CommonName
	if cert.Subject.String() == cert.Issuer.String() {
		s += " (self-signed)"
	}
	if time.Now().After(cert.NotAfter) {
		s += " (expired)"
	}
	return s
}
