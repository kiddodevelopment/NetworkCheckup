use super::*;
use crate::dnsmsg::{self, RData, TYPE_A, TYPE_PTR};
use crate::platform::{self, DnsServer};
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;

pub struct DnsAnswer {
    pub rcode: u8,
    pub ips: Vec<String>,
    pub names: Vec<String>,
    pub rtt: Duration,
}

#[derive(Debug)]
pub enum DnsErr {
    Timeout,
    Other(String),
}

impl std::fmt::Display for DnsErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsErr::Timeout => write!(f, "timed out"),
            DnsErr::Other(s) => write!(f, "{s}"),
        }
    }
}

/// Sends one UDP DNS query straight to `server`.
pub async fn dns_query(server: &str, name: &str, qtype: u16, timeout: Duration) -> Result<DnsAnswer, DnsErr> {
    let ip: IpAddr = server.split('%').next().unwrap_or("").parse().map_err(|_| DnsErr::Other(format!("bad address {server}")))?;
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await.map_err(|e| DnsErr::Other(e.to_string()))?;
    sock.connect(SocketAddr::new(ip, 53)).await.map_err(|e| DnsErr::Other(e.to_string()))?;
    let id = rand_u64() as u16;
    let q = dnsmsg::build_query(id, &[(name, qtype, 1)], true);
    let t0 = Instant::now();
    sock.send(&q).await.map_err(|e| DnsErr::Other(e.to_string()))?;
    let deadline = t0 + timeout;
    let mut buf = [0u8; 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let n = match tokio::time::timeout(left, sock.recv(&mut buf)).await {
            Err(_) => return Err(DnsErr::Timeout),
            Ok(Err(e)) => return Err(DnsErr::Other(e.to_string())),
            Ok(Ok(n)) => n,
        };
        let Some(m) = dnsmsg::parse(&buf[..n]) else { continue };
        if m.id != id {
            continue;
        }
        let mut a = DnsAnswer { rcode: m.rcode, ips: vec![], names: vec![], rtt: t0.elapsed() };
        for rec in m.answers {
            match rec.data {
                RData::A(ip) => a.ips.push(ip.to_string()),
                RData::Ptr(n) => a.names.push(n.trim_end_matches('.').to_string()),
                _ => {}
            }
        }
        return Ok(a);
    }
}

/// System resolver lookup (includes the OS cache and hosts file).
pub async fn sys_lookup(name: &str, timeout: Duration) -> Result<Vec<String>, String> {
    match tokio::time::timeout(timeout, tokio::net::lookup_host(format!("{name}:0"))).await {
        Err(_) => Err("timed out".into()),
        Ok(Err(e)) => Err(short_err(&e.to_string())),
        Ok(Ok(it)) => {
            let v: Vec<String> = uniq(it.map(|a| a.ip().to_string()).collect());
            if v.is_empty() { Err("name not found".into()) } else { Ok(v) }
        }
    }
}

fn known_resolver(a: &str) -> Option<&'static str> {
    Some(match a {
        "1.1.1.1" | "1.0.0.1" | "2606:4700:4700::1111" => "Cloudflare",
        "1.1.1.2" => "Cloudflare (malware filter)",
        "1.1.1.3" => "Cloudflare (family filter)",
        "8.8.8.8" | "8.8.4.4" | "2001:4860:4860::8888" => "Google",
        "9.9.9.9" | "149.112.112.112" | "2620:fe::fe" => "Quad9",
        "208.67.222.222" | "208.67.220.220" => "Cisco OpenDNS",
        "94.140.14.14" | "94.140.15.15" => "AdGuard",
        _ => return None,
    })
}

pub fn describe_server(addr: &str, gateway: &str) -> String {
    if let Some(n) = known_resolver(addr) {
        return format!("{n} public DNS");
    }
    let Ok(ip) = addr.split('%').next().unwrap_or("").parse::<IpAddr>() else { return "unknown".into() };
    if addr == gateway {
        return "your router (forwards to your provider)".into();
    }
    if ip.is_loopback() {
        return "local resolver on this computer (VPN client, filter, or OS stub)".into();
    }
    if is_private(ip) {
        return "private network server (router, Pi-hole, or work DNS)".into();
    }
    "public server (likely your internet provider)".into()
}

/// Unique unscoped servers worth querying directly, plus skipped placeholders.
pub fn usable_servers(servers: &[DnsServer]) -> (Vec<String>, Vec<String>) {
    let (mut out, mut skipped) = (vec![], vec![]);
    let mut seen = std::collections::HashSet::new();
    for s in servers {
        if !s.domain.is_empty() || !seen.insert(s.addr.clone()) {
            continue;
        }
        if s.addr.to_lowercase().starts_with("fec0:") {
            skipped.push(s.addr.clone());
        } else {
            out.push(s.addr.clone());
        }
    }
    (out, skipped)
}

pub async fn config(f: Arc<Facts>, mut r: CheckResult) -> CheckResult {
    let l = f.load().await;
    let (servers, notes) = match platform::dns_servers().await {
        Ok(x) => x,
        Err(e) => {
            r.limit(format!("Could not read DNS settings: {e}"));
            (vec![], vec![])
        }
    };
    let read_ok = r.limits.is_empty();
    r.limits.extend(notes);
    if servers.is_empty() && read_ok {
        r.summary = "No DNS servers are configured.".into();
        r.add(Status::Bad, "No DNS servers", "Without DNS, names like google.com cannot be turned into addresses, so almost nothing loads.");
        return r;
    }
    let mut t = Table::new("Configured DNS servers", &["Server", "Interface", "Applies to", "What it is"]);
    let mut main = vec![];
    let mut vpn_dns = false;
    for s in &servers {
        let scope = if s.domain.is_empty() { "all lookups".to_string() } else { format!("only {}", s.domain) };
        t.row(vec![s.addr.clone(), or_dash(&s.iface), scope, describe_server(&s.addr, &l.gateway4)]);
        if s.domain.is_empty() {
            main.push(s.addr.clone());
        }
        if !s.iface.is_empty() {
            if let Some(i) = l.ifaces.iter().find(|i| i.name == s.iface || crate::facts::display_name(i) == s.iface) {
                vpn_dns |= l.kind(i).kind == "VPN/tunnel";
            }
        }
    }
    r.tables.push(t);
    if !r.status_set {
        r.set(Status::Good);
    }
    if !main.is_empty() {
        r.summary = format!("Using {} ({}).", uniq(main.clone()).join(", "), describe_server(&main[0], &l.gateway4));
    } else if !servers.is_empty() {
        r.summary = format!("{} DNS server(s), all limited to specific domains.", servers.len());
    } else {
        r.summary = "Could not read the DNS settings.".into();
    }
    if vpn_dns {
        r.add(Status::Info, "VPN supplies DNS", "A VPN has installed its own DNS servers. If local names or some sites fail only while the VPN is on, its DNS is the likely cause.");
    }
    let scoped = servers.iter().filter(|s| !s.domain.is_empty()).count();
    if scoped > 0 {
        r.add(Status::Info, "Split DNS in use", format!("{scoped} server(s) answer only for specific domains (common with work VPNs). Lookups for those domains bypass your normal DNS."));
    }
    let (direct, skipped) = usable_servers(&servers);
    if !skipped.is_empty() {
        r.detail("Ignored placeholder servers", format!("{} (Windows default when no IPv6 DNS is set)", skipped.join(", ")));
    }
    // Which resolver actually reaches the internet: Akamai answers with the resolver's own address.
    match sys_lookup("whoami.akamai.net", Duration::from_secs(4)).await {
        Ok(ips) => {
            let eff = ips.iter().find(|i| !i.contains(':')).unwrap_or(&ips[0]).clone();
            r.detail("Upstream resolver seen by the internet", eff.clone());
            if let Ok(ip) = eff.parse::<IpAddr>() {
                let ptr = match ip {
                    IpAddr::V4(a) => {
                        let o = a.octets();
                        format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
                    }
                    IpAddr::V6(_) => String::new(),
                };
                let via = direct.iter().find(|s| !s.contains(':')).cloned().unwrap_or_else(|| "1.1.1.1".into());
                if !ptr.is_empty() {
                    if let Ok(a) = dns_query(&via, &ptr, TYPE_PTR, Duration::from_secs(2)).await {
                        if let Some(n) = a.names.first() {
                            r.detail("Upstream resolver name", n.clone());
                        }
                    }
                }
            }
        }
        Err(_) => r.note("Could not identify the upstream resolver (whoami lookup failed)."),
    }
    r
}

const SPEED_NAMES: &[&str] = &["google.com", "youtube.com", "wikipedia.org", "amazon.com", "microsoft.com", "apple.com", "netflix.com", "github.com"];

#[derive(Default)]
struct Timing {
    server: String,
    rtts: Vec<Duration>,
    timeouts: usize,
    servfail: usize,
    err: Option<String>,
}

async fn time_server(server: String) -> Timing {
    let mut st = Timing { server: server.clone(), ..Default::default() };
    for _round in 0..2 {
        // first pass may be uncached, second should be cached
        for n in SPEED_NAMES {
            match dns_query(&server, n, TYPE_A, Duration::from_secs(2)).await {
                Err(DnsErr::Timeout) => st.timeouts += 1,
                Err(DnsErr::Other(e)) => st.err = Some(e),
                Ok(a) => {
                    if a.rcode == 2 {
                        st.servfail += 1;
                    }
                    st.rtts.push(a.rtt);
                }
            }
        }
    }
    st
}

pub async fn speed(_f: Arc<Facts>, mut r: CheckResult) -> CheckResult {
    let servers = match platform::dns_servers().await {
        Ok((s, _)) => s,
        Err(_) => {
            r.limit("Could not read DNS settings, so only the system resolver was timed.");
            vec![]
        }
    };
    let (mut direct, _) = usable_servers(&servers);
    direct.truncate(4);
    let mut targets = direct.clone();
    if !direct.iter().any(|d| d == "1.1.1.1") {
        targets.push("1.1.1.1".into());
    }
    let sys = async {
        let (mut rtts, mut fail) = (vec![], 0);
        for n in SPEED_NAMES {
            let t0 = Instant::now();
            match sys_lookup(n, Duration::from_secs(4)).await {
                Ok(_) => rtts.push(t0.elapsed()),
                Err(_) => fail += 1,
            }
        }
        (rtts, fail)
    };
    let (res, (sys_rtt, sys_fail)) = tokio::join!(futures::future::join_all(targets.into_iter().map(time_server)), sys);
    let mut t = Table::new("Lookup times (8 names x 2 rounds, A records)", &["Server", "Role", "Answered", "Timeouts", "Median ms", "Slowest ms"]);
    t.row(vec!["system resolver".into(), "what apps use (incl. OS cache)".into(), format!("{}/{}", sys_rtt.len(), SPEED_NAMES.len()), sys_fail.to_string(), f1(median(&sys_rtt)), f1(max_d(&sys_rtt))]);
    if !r.status_set {
        r.set(Status::Good);
    }
    let mut worst = String::new();
    let total = 2 * SPEED_NAMES.len();
    for (i, s) in res.iter().enumerate() {
        let configured = i < direct.len();
        let role = if configured { "configured" } else { "reference (Cloudflare)" };
        t.row(vec![s.server.clone(), role.into(), format!("{}/{total}", s.rtts.len()), s.timeouts.to_string(), f1(median(&s.rtts)), f1(max_d(&s.rtts))]);
        if !configured {
            continue;
        }
        let med = median(&s.rtts);
        if s.rtts.is_empty() {
            if s.timeouts > 0 {
                r.add(Status::Warn, format!("No direct answer from {}", s.server), "This server did not answer direct queries. Some VPNs and security tools only let the system resolver through; if the system resolver row is healthy, browsing is unaffected.");
            } else if let Some(e) = &s.err {
                r.note(format!("Could not query {} directly: {}", s.server, short_err(e)));
            }
        } else if s.timeouts >= 3 {
            r.add(Status::Bad, format!("DNS server drops queries: {}", s.server), format!("{} of {total} lookups timed out. Each timeout stalls a page for a second or more (\"resolving host...\").", s.timeouts));
            worst = s.server.clone();
        } else if s.timeouts > 0 {
            r.add(Status::Warn, format!("Occasional DNS timeouts: {}", s.server), format!("{} of {total} lookups timed out.", s.timeouts));
        } else if med > 150.0 {
            r.add(Status::Warn, format!("Slow DNS server: {}", s.server), format!("Median lookup {} ms. Healthy resolvers answer in under 50 ms; every new site you open waits on this.", f1(med)));
        }
        if s.servfail > 2 {
            r.add(Status::Warn, format!("DNS server errors: {}", s.server), format!("{} lookups returned a server failure.", s.servfail));
        }
    }
    r.tables.push(t);
    let half = SPEED_NAMES.len() / 2;
    if sys_fail > half {
        r.add(Status::Bad, "Name lookups failing", "Most test names did not resolve through the system. Browsing will fail even if the connection itself is up.");
    }
    let sm = median(&sys_rtt);
    r.summary = if sys_rtt.is_empty() || sys_fail > half {
        format!("Name lookups are failing ({sys_fail} of {} did not resolve).", SPEED_NAMES.len())
    } else if !worst.is_empty() {
        format!("Lookups work (median {} ms) but {worst} is dropping queries.", f1(sm))
    } else {
        format!("Lookups take {} ms (median) through the system resolver.", f1(sm))
    };
    if sm > 200.0 {
        r.add(Status::Warn, "Slow name lookups overall", "Apps wait over 200 ms just to find each site. Switching to a faster DNS provider often helps.");
    }
    r
}

fn rand_label() -> String {
    format!("nc-{:016x}", rand_u64())
}

pub async fn integrity(_f: Arc<Facts>, mut r: CheckResult) -> CheckResult {
    let servers = platform::dns_servers().await.map(|x| x.0).unwrap_or_default();
    let (direct, _) = usable_servers(&servers);
    r.set(Status::Good);
    let mut t = Table::new("Integrity tests", &["Test", "Server", "Expected", "Got"]);

    // 1. A made-up name must not exist. Answers mean NXDOMAIN rewriting (ad/search pages).
    let fake = format!("{}.com", rand_label());
    let got = match sys_lookup(&fake, Duration::from_secs(4)).await {
        Ok(ips) => {
            r.add(Status::Warn, "Made-up names resolve", "Looking up a name that does not exist returned an address. Some providers do this to show search or ad pages. It can break apps that rely on \"name not found\" errors and is a privacy concern.");
            ips.join(", ")
        }
        Err(_) => "not found".into(),
    };
    t.row(vec![format!("Nonexistent name {fake}"), "system resolver".into(), "not found".into(), got]);
    for s in &direct {
        let g = match dns_query(s, &fake, TYPE_A, Duration::from_secs(2)).await {
            Ok(a) if !a.ips.is_empty() => a.ips.join(", "),
            Ok(a) => dnsmsg::rcode_name(a.rcode).into(),
            Err(_) => "no answer".into(),
        };
        t.row(vec!["Nonexistent name".into(), s.clone(), "NXDOMAIN".into(), g]);
    }

    // 2. Filtering: a well-known ad domain answered with 0.0.0.0 or blocked = DNS filtering.
    let (sys, refa) = tokio::join!(sys_lookup("doubleclick.net", Duration::from_secs(4)), dns_query("1.1.1.1", "doubleclick.net", TYPE_A, Duration::from_secs(2)));
    let filtered;
    let g = match &sys {
        Ok(ips) => {
            filtered = ips.iter().any(|ip| ip == "0.0.0.0" || ip.starts_with("127.") || ip == "::");
            ips.join(", ")
        }
        Err(e) => {
            filtered = matches!(&refa, Ok(a) if !a.ips.is_empty());
            e.clone()
        }
    };
    t.row(vec!["Ad domain doubleclick.net".into(), "system resolver".into(), "real address unless filtered".into(), g]);
    if filtered {
        r.add(Status::Info, "DNS filtering active", "A known ad/tracking domain is blocked at the DNS level (Pi-hole, NextDNS, router filter, or security software). Usually intentional; if a specific site breaks, this filter is a suspect.");
    }

    // 3. Interception: ask an address that runs no DNS server. Any answer means the
    // network silently redirects DNS traffic.
    let g = match dns_query("192.0.2.53", "example.com", TYPE_A, Duration::from_millis(1500)).await {
        Ok(a) => {
            r.add(Status::Warn, "DNS traffic is intercepted", "A query sent to an address with no DNS server still got an answer. The network (or security software) is redirecting all DNS, which overrides any DNS server you choose.");
            format!("answered ({})", dnsmsg::rcode_name(a.rcode))
        }
        Err(_) => "no answer".into(),
    };
    t.row(vec!["Query to a non-DNS address 192.0.2.53".into(), "-".into(), "no answer".into(), g]);

    // 4. Agreement: configured servers should broadly agree with a reference for a stable name.
    let mut ref_ips = dns_query("1.1.1.1", "example.com", TYPE_A, Duration::from_secs(2)).await.map(|a| a.ips).unwrap_or_default();
    ref_ips.sort();
    if !ref_ips.is_empty() {
        for s in &direct {
            let Ok(mut ca) = dns_query(s, "example.com", TYPE_A, Duration::from_secs(2)).await else { continue };
            ca.ips.sort();
            t.row(vec!["example.com matches reference".into(), s.clone(), ref_ips.join(", "), ca.ips.join(", ")]);
            if !ca.ips.is_empty() && !ca.ips.iter().any(|x| ref_ips.contains(x)) {
                r.add(Status::Warn, format!("Unexpected answer from {s}"), "This server returned a different address for example.com than public DNS. That can mean a captive portal, a corporate override, or DNS hijacking.");
            }
        }
    }
    r.tables.push(t);
    r.summary = if r.findings.is_empty() { "No signs of DNS tampering or filtering.".into() } else { format!("{} DNS behaviour(s) worth knowing about.", r.findings.len()) };
    r.note("Encrypted DNS (DoH/DoT) posture is planned for a later version.");
    r
}
