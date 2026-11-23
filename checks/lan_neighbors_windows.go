//go:build windows

package checks

import (
	"context"
	"strings"
)

func neighborTable(ctx context.Context) (map[string]string, error) {
	var rows []struct {
		IPAddress        string
		LinkLayerAddress string
		State            int
	}
	// State: 0 Unreachable, 1 Incomplete, 2 Probe, 3 Delay, 4 Stale, 5 Reachable, 6 Permanent
	err := psJSON(ctx, `Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress,LinkLayerAddress,@{n='State';e={[int]$_.State}} | ConvertTo-Json -Compress`, &rows)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, r := range rows {
		if r.State <= 1 {
			continue
		}
		if mac := normMAC(strings.ReplaceAll(r.LinkLayerAddress, "-", ":")); mac != "" {
			m[r.IPAddress] = mac
		}
	}
	return m, nil
}
