//go:build windows

package checks

import (
	"context"
	"fmt"
	"strings"
)

func defaultRoutes(ctx context.Context) ([]Route, error) {
	var rows []struct {
		NextHop        string
		InterfaceAlias string
		RouteMetric    int
	}
	err := psJSON(ctx, `Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object NextHop,InterfaceAlias,RouteMetric | ConvertTo-Json -Compress`, &rows)
	if err != nil {
		return nil, err
	}
	var rs []Route
	for _, r := range rows {
		if r.NextHop == "0.0.0.0" || r.NextHop == "::" || r.NextHop == "" {
			continue
		}
		rs = append(rs, Route{Gateway: r.NextHop, Iface: r.InterfaceAlias, V6: strings.Contains(r.NextHop, ":")})
	}
	return rs, nil
}

func ifaceInfo(ctx context.Context) map[string]IfaceMeta {
	m := map[string]IfaceMeta{}
	var rows []struct {
		Name                 string
		InterfaceDescription string
		PhysicalMediaType    string
		LinkSpeed            string
	}
	if err := psJSON(ctx, `Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Select-Object Name,InterfaceDescription,PhysicalMediaType,LinkSpeed | ConvertTo-Json -Compress`, &rows); err != nil {
		return m
	}
	for _, r := range rows {
		kind := "Other"
		pm := strings.ToLower(r.PhysicalMediaType)
		switch {
		case looksLikeTunnel(r.Name, r.InterfaceDescription):
			kind = "VPN/tunnel"
		case strings.Contains(pm, "802.11") || strings.Contains(strings.ToLower(r.InterfaceDescription), "wi-fi") || strings.Contains(strings.ToLower(r.InterfaceDescription), "wireless"):
			kind = "Wi-Fi"
		case strings.Contains(pm, "802.3"):
			kind = "Ethernet"
		}
		m[r.Name] = IfaceMeta{Kind: kind, Description: r.InterfaceDescription, Speed: r.LinkSpeed}
	}
	return m
}

func dnsServers(ctx context.Context) ([]DNSServer, []string, error) {
	var rows []struct {
		InterfaceAlias  string
		ServerAddresses []string
	}
	err := psJSON(ctx, `Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress -Depth 3`, &rows)
	if err != nil {
		return nil, nil, err
	}
	var res []DNSServer
	for _, r := range rows {
		if strings.HasPrefix(strings.ToLower(r.InterfaceAlias), "loopback") {
			continue
		}
		for _, s := range r.ServerAddresses {
			res = append(res, DNSServer{Addr: s, Iface: r.InterfaceAlias})
		}
	}
	var notes []string
	var nrpt []struct {
		Namespace   []string
		NameServers []string
	}
	if psJSON(ctx, `Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | Select-Object Namespace,NameServers | ConvertTo-Json -Compress -Depth 3`, &nrpt) == nil {
		for _, n := range nrpt {
			for _, ns := range n.NameServers {
				res = append(res, DNSServer{Addr: ns, Iface: "NRPT policy", Domain: strings.Join(n.Namespace, ",")})
			}
		}
	}
	return res, notes, nil
}

func proxySettings(ctx context.Context) ([]ProxySetting, error) {
	var rows []struct {
		ProxyEnable   *int
		ProxyServer   string
		AutoConfigURL string
	}
	err := psJSON(ctx, `Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL | ConvertTo-Json -Compress`, &rows)
	if err != nil {
		return nil, err
	}
	var ps []ProxySetting
	for _, r := range rows {
		if r.ProxyEnable != nil && *r.ProxyEnable == 1 && r.ProxyServer != "" {
			ps = append(ps, ProxySetting{"Windows (user)", "Manual proxy", r.ProxyServer})
		}
		if r.AutoConfigURL != "" {
			ps = append(ps, ProxySetting{"Windows (user)", "Auto-config (PAC) script", r.AutoConfigURL})
		}
	}
	return ps, nil
}

func vpnServices(ctx context.Context) ([]string, error) {
	var rows []struct{ Name string }
	err := psJSON(ctx, `Get-VpnConnection -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionStatus -eq 'Connected' } | Select-Object Name | ConvertTo-Json -Compress`, &rows)
	var names []string
	for _, r := range rows {
		names = append(names, r.Name)
	}
	return names, err
}

func listeners(ctx context.Context) ([]Listener, []string, error) {
	var rows []struct {
		Proto   string
		Addr    string
		Port    int
		PID     int
		Process string
	}
	script := `$p=@{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $p[[int]$_.Id]=$_.ProcessName };
$t=Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{Proto='tcp';Addr=$_.LocalAddress;Port=[int]$_.LocalPort;PID=[int]$_.OwningProcess;Process=$p[[int]$_.OwningProcess]} };
$u=Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{Proto='udp';Addr=$_.LocalAddress;Port=[int]$_.LocalPort;PID=[int]$_.OwningProcess;Process=$p[[int]$_.OwningProcess]} };
@($t)+@($u) | ConvertTo-Json -Compress`
	if err := psJSON(ctx, script, &rows); err != nil {
		return nil, nil, fmt.Errorf("listing sockets: %w", err)
	}
	var ls []Listener
	var limits []string
	missing := false
	for _, r := range rows {
		if r.Process == "" {
			missing = true
		}
		ls = append(ls, Listener{Proto: r.Proto, Addr: r.Addr, Port: r.Port, PID: r.PID, Process: r.Process})
	}
	if missing {
		limits = append(limits, "Some process names are hidden from standard (non-admin) accounts.")
	}
	return ls, limits, nil
}
