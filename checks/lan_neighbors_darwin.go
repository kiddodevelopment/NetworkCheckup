//go:build darwin

package checks

import (
	"context"
	"strings"
)

func neighborTable(ctx context.Context) (map[string]string, error) {
	out, err := run(ctx, "arp", "-an")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		// ? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]
		f := strings.Fields(line)
		if len(f) < 4 || f[2] != "at" {
			continue
		}
		ip := strings.Trim(f[1], "()")
		if mac := normMAC(f[3]); mac != "" {
			m[ip] = mac
		}
	}
	return m, nil
}
