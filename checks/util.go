package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// run executes a command and returns stdout. It never needs admin rights.
func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil && out.Len() == 0 {
		return "", fmt.Errorf("%s: %v %s", name, err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

// psJSON runs a PowerShell snippet and decodes its ConvertTo-Json output into v.
// A single object is wrapped into a one-element array when v is a slice pointer.
func psJSON(ctx context.Context, script string, v any) error {
	out, err := run(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"$ProgressPreference='SilentlyContinue'; "+script)
	if err != nil {
		return err
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	if strings.HasPrefix(out, "{") {
		out = "[" + out + "]"
	}
	return json.Unmarshal([]byte(out), v)
}

// Stats summarises a series of round-trip probes.
type Stats struct {
	Sent, Received int
	RTTs           []time.Duration
	Method         string
}

func (s Stats) LossPct() float64 {
	if s.Sent == 0 {
		return 0
	}
	return 100 * float64(s.Sent-s.Received) / float64(s.Sent)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func (s Stats) Min() float64 {
	if len(s.RTTs) == 0 {
		return 0
	}
	m := s.RTTs[0]
	for _, r := range s.RTTs {
		if r < m {
			m = r
		}
	}
	return ms(m)
}

func (s Stats) Max() float64 {
	m := time.Duration(0)
	for _, r := range s.RTTs {
		if r > m {
			m = r
		}
	}
	return ms(m)
}

func (s Stats) Avg() float64 {
	if len(s.RTTs) == 0 {
		return 0
	}
	var t time.Duration
	for _, r := range s.RTTs {
		t += r
	}
	return ms(t) / float64(len(s.RTTs))
}

// Jitter is the mean absolute difference between consecutive samples (RFC 3550 style).
func (s Stats) Jitter() float64 {
	if len(s.RTTs) < 2 {
		return 0
	}
	var t float64
	for i := 1; i < len(s.RTTs); i++ {
		t += math.Abs(ms(s.RTTs[i]) - ms(s.RTTs[i-1]))
	}
	return t / float64(len(s.RTTs)-1)
}

func median(ds []time.Duration) float64 {
	if len(ds) == 0 {
		return 0
	}
	c := append([]time.Duration(nil), ds...)
	sort.Slice(c, func(a, b int) bool { return c[a] < c[b] })
	return ms(c[len(c)/2])
}

func f1(v float64) string { return fmt.Sprintf("%.1f", v) }

// tcpProbe measures TCP connect time. A refused connection still proves
// the host answered, so it counts as a reply.
func tcpProbe(ctx context.Context, host string, ports []string, count int, gap time.Duration) Stats {
	st := Stats{Method: "TCP connect"}
	port := ""
	for _, p := range ports { // find a port that answers (open or refused)
		d := net.Dialer{Timeout: 800 * time.Millisecond}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, p))
		if err == nil {
			c.Close()
			port = p
			break
		}
		if isRefused(err) {
			port = p
			break
		}
	}
	if port == "" {
		st.Sent = count
		return st
	}
	st.Method = "TCP connect to port " + port
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		st.Sent++
		d := net.Dialer{Timeout: 1500 * time.Millisecond}
		start := time.Now()
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		rtt := time.Since(start)
		if err == nil {
			c.Close()
		}
		if err == nil || isRefused(err) {
			st.Received++
			st.RTTs = append(st.RTTs, rtt)
		}
		sleepCtx(ctx, gap)
	}
	return st
}

func isRefused(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "refused") || strings.Contains(s, "actively refused")
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// probe pings with ICMP when the OS allows it unprivileged, else falls back to TCP.
func probe(ctx context.Context, ip string, count int, gap time.Duration, tcpPorts []string) Stats {
	st, err := icmpPing(ctx, ip, count, gap)
	if err == nil && st.Received > 0 {
		return st
	}
	t := tcpProbe(ctx, ip, tcpPorts, count, gap)
	if t.Received > 0 || err != nil {
		return t
	}
	return st // ICMP worked but nothing came back
}

func isPrivate(ip net.IP) bool { return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() }
