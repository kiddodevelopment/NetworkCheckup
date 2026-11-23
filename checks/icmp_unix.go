//go:build !windows

package checks

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func hideWindow(*exec.Cmd) {}

// icmpPing uses an unprivileged ICMP datagram socket (always allowed on macOS,
// allowed on Linux when net.ipv4.ping_group_range covers the user).
func icmpPing(ctx context.Context, ip string, count int, gap time.Duration) (Stats, error) {
	st := Stats{Method: "ICMP echo"}
	dst := net.ParseIP(ip)
	if dst == nil || dst.To4() == nil {
		return st, errors.New("ICMP probe supports IPv4 only")
	}
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return st, err
	}
	defer c.Close()
	id := os.Getpid() & 0xffff
	buf := make([]byte, 1500)
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: i + 1, Data: []byte("netcheckup")}}
		b, _ := msg.Marshal(nil)
		st.Sent++
		start := time.Now()
		if _, err := c.WriteTo(b, &net.UDPAddr{IP: dst}); err != nil {
			return st, err
		}
		deadline := start.Add(1500 * time.Millisecond)
		for {
			c.SetReadDeadline(deadline)
			n, peer, err := c.ReadFrom(buf)
			if err != nil {
				break // timeout = lost
			}
			rm, err := icmp.ParseMessage(1, buf[:n])
			if err != nil || rm.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			echo, ok := rm.Body.(*icmp.Echo)
			if !ok || echo.Seq != i+1 {
				continue
			}
			if u, ok := peer.(*net.UDPAddr); ok && !u.IP.Equal(dst) {
				continue
			}
			st.Received++
			st.RTTs = append(st.RTTs, time.Since(start))
			break
		}
		sleepCtx(ctx, gap)
	}
	return st, nil
}
