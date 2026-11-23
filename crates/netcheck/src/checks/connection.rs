use super::*;
use crate::facts::{display_name, fmt_speed, usable_addrs, Loaded};
use crate::platform::{self, ProxySetting};
use std::net::IpAddr;
use tokio::net::TcpStream;

pub async fn link(f: Arc<Facts>, mut r: CheckResult) -> CheckResult {
    let l = f.load().await;
    let Some(p) = l.primary.clone() else {
        r.summary = "No active network connection found.".into();
        r.add(Status::Bad, "Not connected", "This computer has no route to the internet. Check that Wi-Fi is on and joined, or that the network cable is plugged in.");
        interface_table(&l, &mut r);
        return r;
    };
    let meta = l.kind(&p);
    let a = usable_addrs(&p);
    let name = display_name(&p);
    let kind = if meta.kind == "Other" { "network".to_string() } else { meta.kind.clone() };
    r.summary = format!("Connected over {kind} ({name})");
    if let Some((ip, _, _)) = a.v4.first() {
        r.summary += &format!(", IP {ip}");
    }
    r.set(Status::Good);
    r.detail("Interface", name.clone());
    if !meta.description.is_empty() {
        r.detail("Adapter", meta.description.clone());
    }
    r.detail("Type", meta.kind.clone());
    for (ip, pfx, mask) in &a.v4 {
        r.detail("IPv4 address", format!("{ip}/{pfx} (mask {mask})"));
    }
    for (ip, pfx) in &a.v6 {
        r.detail("IPv6 address", format!("{ip}/{pfx}"));
    }
    r.detail("Default gateway (IPv4)", or_dash(&l.gateway4));
    r.detail("Default gateway (IPv6)", or_dash(&l.gateway6));
    r.detail("MAC address", p.mac_addr.map(|m| m.to_string()).unwrap_or_else(|| "none".into()));
    if let Some(mtu) = p.mtu {
        r.detail("MTU", mtu.to_string());
    }
    if let Some(s) = p.transmit_speed.filter(|s| *s > 0) {
        r.detail("Link speed", fmt_speed(s));
    }
    if a.link_local4 && a.v4.len() == 1 {
        r.add(Status::Bad, "Self-assigned address (169.254.x.x)", "The router never handed this computer an address (DHCP failed). Try turning Wi-Fi off and on, reconnecting the cable, or restarting the router.");
    }
    if l.gateway4.is_empty() && !a.v4.is_empty() {
        r.add(Status::Bad, "No default gateway", "The computer has an address but no router to send internet traffic to. Usually a DHCP or router problem.");
    }
    if a.v4.is_empty() && !a.v6.is_empty() {
        r.add(Status::Warn, "IPv6 only", "There is no IPv4 address. Most sites still work, but some older services and devices need IPv4.");
    }
    if meta.kind == "VPN/tunnel" {
        r.add(Status::Info, "Traffic leaves through a VPN", "The main route goes through a VPN or tunnel, so speed and reachability depend on the VPN server, not only your local network.");
    }
    if meta.kind == "Wi-Fi" {
        r.note("Wi-Fi signal strength and channel details are planned for a later version.");
    }
    if meta.kind != "VPN/tunnel" {
        if let Some((ip, _, _)) = a.v4.first() {
            if !is_private(IpAddr::V4(*ip)) && !ip.is_link_local() {
                r.add(Status::Info, "Public IP directly on this computer", "This computer has a public address with no router translating for it. That is unusual at home; make sure the firewall is on.");
            }
        }
    }
    interface_table(&l, &mut r);
    r
}

fn interface_table(l: &Loaded, r: &mut CheckResult) {
    let mut t = Table::new("All interfaces", &["Name", "Type", "Status", "IPv4", "IPv6 (global)", "MAC", "MTU"]);
    for i in &l.ifaces {
        if i.is_loopback() {
            continue;
        }
        let a = usable_addrs(i);
        if a.v4.is_empty() && a.v6.is_empty() {
            continue;
        }
        let v4: Vec<String> = a.v4.iter().map(|(ip, p, _)| format!("{ip}/{p}")).collect();
        let v6: Vec<String> = a.v6.iter().map(|(ip, p)| format!("{ip}/{p}")).collect();
        t.row(vec![
            display_name(i),
            l.kind(i).kind,
            if i.is_up() { "up".into() } else { "down".into() },
            v4.join(", "),
            v6.join(", "),
            i.mac_addr.map(|m| m.to_string()).unwrap_or_default(),
            i.mtu.map(|m| m.to_string()).unwrap_or_default(),
        ]);
    }
    r.tables.push(t);
}

fn proxy_host(value: &str) -> String {
    let mut host = value;
    if let Some(i) = host.find("://") {
        host = &host[i + 3..];
    }
    let mut host = host.split('/').next().unwrap_or("").trim_end_matches(';').to_string();
    if host.contains('=') {
        // Windows "http=host:port;https=..."
        host = host.split(';').next().unwrap_or("").split_once('=').map(|x| x.1.to_string()).unwrap_or_default();
    }
    if !host.contains(':') {
        host += ":80";
    }
    host
}

pub async fn vpn(f: Arc<Facts>, mut r: CheckResult) -> CheckResult {
    let l = f.load().await;
    r.set(Status::Good);
    let mut tunnels = vec![];
    for i in &l.ifaces {
        if !i.is_up() {
            continue;
        }
        let m = l.kind(i);
        let a = usable_addrs(i);
        if m.kind == "VPN/tunnel" && (!a.v4.is_empty() || !a.v6.is_empty()) {
            let v4: Vec<String> = a.v4.iter().map(|(ip, p, _)| format!("{ip}/{p}")).collect();
            tunnels.push(display_name(i));
            r.detail("Tunnel interface", format!("{} {} {}", display_name(i), v4.join(", "), m.description).trim().to_string());
        }
    }
    let services = platform::vpn_services().await;
    let services = match services {
        Ok(s) => s,
        Err(_) => {
            r.note("Could not list system VPN profiles; tunnel interfaces were still checked.");
            vec![]
        }
    };
    for s in &services {
        r.detail("Connected VPN profile", s.clone());
    }
    let full = l.primary_kind() == "VPN/tunnel";
    if full {
        r.summary = "A VPN is carrying all internet traffic.".into();
        r.add(Status::Info, "Full-tunnel VPN active", "All traffic goes through the VPN. This can hide local devices like printers and TVs, block hotel or guest Wi-Fi login pages, and make speed depend on the VPN server's distance.");
    } else if !tunnels.is_empty() || !services.is_empty() {
        r.summary = "A VPN or tunnel is connected, but normal internet traffic goes around it (split tunnel).".into();
        r.add(Status::Info, "Split-tunnel VPN active", "Only some destinations (often work networks) go through the VPN. If a work site fails, the VPN's routes or DNS are the first thing to check.");
    } else {
        r.summary = "No VPN detected.".into();
    }

    let mut proxies: Vec<ProxySetting> = vec![];
    let mut seen = std::collections::HashSet::new();
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() && seen.insert(format!("{}{v}", k.to_uppercase())) {
                proxies.push(ProxySetting { source: "Environment variable".into(), kind: k.into(), value: v });
            }
        }
    }
    match platform::proxy_settings().await {
        Ok(s) => proxies.extend(s),
        Err(e) => r.note(format!("Could not read system proxy settings: {e}")),
    }
    if proxies.is_empty() {
        r.summary += " No proxy configured.";
        return r;
    }
    let mut t = Table::new("Proxy settings", &["Source", "Kind", "Value"]);
    for p in &proxies {
        t.row(vec![p.source.clone(), p.kind.clone(), p.value.clone()]);
    }
    r.tables.push(t);
    let mut unreachable = String::new();
    for p in &proxies {
        if p.kind.contains("PAC") || p.kind.contains("WPAD") {
            continue;
        }
        let host = proxy_host(&p.value);
        let ok = matches!(tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(host.as_str())).await, Ok(Ok(_)));
        if !ok {
            unreachable = host;
        }
    }
    if !unreachable.is_empty() {
        r.add(Status::Bad, "Proxy server not reachable", format!("Apps are told to send web traffic through {unreachable}, but it does not answer. This is a classic \"Wi-Fi works but nothing loads\" cause, often left over from a work network."));
    } else {
        r.add(Status::Warn, "A proxy is configured", "Web traffic is routed through a proxy. That is normal on work networks; elsewhere a stale proxy can slow browsing or break login pages.");
    }
    r.summary += &format!(" {} proxy setting(s) found.", proxies.len());
    r
}

/// Best-of-3 TCP 443 connect time to a host over one address family.
async fn connect_time(host: &str, v6: bool) -> Result<Duration, String> {
    let addrs = tokio::net::lookup_host(format!("{host}:443")).await.map_err(|e| short_err(&e.to_string()))?;
    let Some(addr) = addrs.into_iter().find(|a| a.is_ipv6() == v6) else {
        return Err(if v6 { "no IPv6 address".into() } else { "no IPv4 address".into() });
    };
    let mut best: Option<Duration> = None;
    let mut last = String::new();
    for _ in 0..3 {
        let t0 = Instant::now();
        match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                let el = t0.elapsed();
                best = Some(best.map_or(el, |b| b.min(el)));
            }
            Ok(Err(e)) => last = short_err(&e.to_string()),
            Err(_) => last = "timed out".into(),
        }
    }
    best.ok_or(last)
}

pub async fn ipv6(f: Arc<Facts>, mut r: CheckResult) -> CheckResult {
    let l = f.load().await;
    let hosts = ["www.google.com", "www.cloudflare.com", "www.wikipedia.org"];
    let has6 = matches!(l.local6, Some(IpAddr::V6(a)) if (a.segments()[0] & 0xffc0) != 0xfe80);
    let mut jobs = vec![];
    for h in hosts {
        for v6 in [false, true] {
            if v6 && !has6 {
                continue;
            }
            jobs.push(async move { (h, v6, connect_time(h, v6).await) });
        }
    }
    let mut all = futures::future::join_all(jobs).await;
    all.sort_by_key(|x| (x.0, x.1));
    let mut t = Table::new("Connection setup time (best of 3, TCP 443)", &["Site", "Family", "Time (ms)", "Result"]);
    let (mut ok4, mut ok6, mut fail4, mut fail6) = (0, 0, 0, 0);
    let (mut sum4, mut sum6) = (0.0, 0.0);
    for (h, v6, res) in &all {
        let fam = if *v6 { "IPv6" } else { "IPv4" };
        match res {
            Ok(d) => {
                t.row(vec![h.to_string(), fam.into(), f1(ms(*d)), "ok".into()]);
                if *v6 { ok6 += 1; sum6 += ms(*d) } else { ok4 += 1; sum4 += ms(*d) }
            }
            Err(e) => {
                t.row(vec![h.to_string(), fam.into(), "-".into(), e.clone()]);
                if *v6 { fail6 += 1 } else { fail4 += 1 }
            }
        }
    }
    r.tables.push(t);
    r.set(Status::Good);
    if !has6 {
        r.summary = "IPv4 only. That is fine; nothing will stall waiting on IPv6.".into();
        r.set(Status::Info);
    } else if ok6 == 0 && fail6 > 0 {
        r.summary = "IPv6 is configured but does not work.".into();
        r.add(Status::Bad, "Broken IPv6", "This computer has an IPv6 address but cannot reach sites over it. Apps may try IPv6 first and wait for it to time out, which feels like slow page loads. Restarting the router or turning off IPv6 on it usually fixes this.");
    } else if fail6 > 0 {
        r.summary = "IPv6 works only partly.".into();
        r.add(Status::Warn, "Patchy IPv6", "Some sites failed over IPv6 while working over IPv4. That can cause occasional slow loads.");
    } else if ok4 > 0 && ok6 > 0 && sum6 / ok6 as f64 > 1.5 * sum4 / ok4 as f64 + 30.0 {
        r.summary = format!("IPv6 works but is slower ({:.0} ms vs {:.0} ms).", sum6 / ok6 as f64, sum4 / ok4 as f64);
        r.add(Status::Warn, "IPv6 slower than IPv4", "Most apps prefer IPv6, so a slower IPv6 path makes everything feel a little slower.");
    } else {
        r.summary = "IPv4 and IPv6 both work cleanly.".into();
    }
    if ok4 == 0 && fail4 > 0 {
        let name_fail = all.iter().all(|(_, _, res)| res.as_ref().err().is_none_or(|e| e == "name not found"));
        if name_fail {
            r.set(Status::Limited);
            r.summary = "Could not compare IPv4 and IPv6 because the test site names did not resolve. See the DNS cards.".into();
        } else {
            r.summary = "Secure web connections are failing.".into();
            r.add(Status::Bad, "Web connections failing", "Secure (HTTPS) connections to major sites did not complete. See the internet and captive portal cards.");
        }
    }
    r.detail("Source IPv4", l.local4.map(|a| a.to_string()).unwrap_or_else(|| "none".into()));
    r.detail("Source IPv6", l.local6.map(|a| a.to_string()).unwrap_or_else(|| "none".into()));
    r
}
