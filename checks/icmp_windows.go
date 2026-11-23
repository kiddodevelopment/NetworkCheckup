//go:build windows

package checks

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

var (
	iphlpapi        = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreate  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose   = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEch = iphlpapi.NewProc("IcmpSendEcho")
)

// icmpPing uses the IP Helper ICMP API, which Windows allows without admin.
func icmpPing(ctx context.Context, ip string, count int, gap time.Duration) (Stats, error) {
	st := Stats{Method: "ICMP echo"}
	dst := net.ParseIP(ip).To4()
	if dst == nil {
		return st, errors.New("ICMP probe supports IPv4 only")
	}
	if err := procIcmpCreate.Find(); err != nil {
		return st, err
	}
	h, _, err := procIcmpCreate.Call()
	if h == 0 || h == ^uintptr(0) {
		return st, err
	}
	defer procIcmpClose.Call(h)
	addr := binary.LittleEndian.Uint32(dst)
	data := []byte("netcheckup")
	reply := make([]byte, 256+len(data))
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		st.Sent++
		start := time.Now()
		n, _, _ := procIcmpSendEch.Call(h, uintptr(addr),
			uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), 1500)
		rtt := time.Since(start)
		status := binary.LittleEndian.Uint32(reply[4:8])
		if n > 0 && status == 0 {
			st.Received++
			st.RTTs = append(st.RTTs, rtt)
		}
		sleepCtx(ctx, gap)
	}
	return st, nil
}
