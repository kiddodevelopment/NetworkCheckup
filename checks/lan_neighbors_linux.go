//go:build linux

package checks

import (
	"context"
	"os"
	"strings"
)

func neighborTable(ctx context.Context) (map[string]string, error) {
	b, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 4 && f[2] == "0x2" {
			if mac := normMAC(f[3]); mac != "" {
				m[f[0]] = mac
			}
		}
	}
	return m, nil
}
