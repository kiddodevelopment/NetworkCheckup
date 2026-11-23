// Package checks holds every Network Checkup diagnostic.
package checks

import (
	"time"

	"netcheckup/engine"
)

const (
	SecConnection = "Connection & Interface Health"
	SecPath       = "Gateway, Internet & Path Quality"
	SecDNS        = "DNS Health & Resolution"
	SecExposure   = "Local Machine Exposure"
)

// All returns a fresh set of checks sharing one facts cache.
func All() []engine.Check {
	f := &facts{}
	return []engine.Check{
		{ID: "link", Section: SecConnection, Title: "Active connection", Timeout: 15 * time.Second, Run: f.linkCheck},
		{ID: "vpn", Section: SecConnection, Title: "VPN, proxy and tunnels", Timeout: 15 * time.Second, Run: f.vpnCheck},
		{ID: "ipv6", Section: SecConnection, Title: "IPv6 vs IPv4", Timeout: 20 * time.Second, Run: f.ipv6Check},
		{ID: "gateway", Section: SecPath, Title: "Router (default gateway)", Timeout: 20 * time.Second, Run: f.gatewayCheck},
		{ID: "internet", Section: SecPath, Title: "Internet quality", Timeout: 25 * time.Second, Run: f.internetCheck},
		{ID: "captive", Section: SecPath, Title: "Captive portal and real internet", Timeout: 15 * time.Second, Run: f.captiveCheck},
		{ID: "dns-config", Section: SecDNS, Title: "DNS servers in use", Timeout: 15 * time.Second, Run: f.dnsConfigCheck},
		{ID: "dns-speed", Section: SecDNS, Title: "DNS lookup speed", Timeout: 25 * time.Second, Run: f.dnsSpeedCheck},
		{ID: "dns-integrity", Section: SecDNS, Title: "DNS interference and filtering", Timeout: 20 * time.Second, Run: f.dnsIntegrityCheck},
		{ID: "listeners", Section: SecExposure, Title: "Listening services on this computer", Timeout: 20 * time.Second, Run: f.listenerCheck},
	}
}
