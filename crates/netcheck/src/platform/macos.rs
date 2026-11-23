use super::*;
use crate::util::run;

pub async fn iface_meta() -> HashMap<String, IfaceMeta> {
    let mut m = HashMap::new();
    if let Ok(out) = run("networksetup", &["-listallhardwareports"]).await {
        let mut port = String::new();
        for line in out.lines() {
            if let Some(p) = line.strip_prefix("Hardware Port:") {
                port = p.trim().to_string();
            }
            if let Some(dev) = line.strip_prefix("Device:") {
                let pl = port.to_lowercase();
                let kind = if pl.contains("wi-fi") || pl.contains("airport") {
                    "Wi-Fi"
                } else if pl.contains("ethernet") || pl.contains("lan") || pl.contains("thunderbolt") {
                    "Ethernet"
                } else {
                    "Other"
                };
                m.insert(dev.trim().to_string(), IfaceMeta { kind: kind.into(), description: port.clone() });
            }
        }
    }
    m
}

pub async fn dns_servers() -> Result<(Vec<DnsServer>, Vec<String>), String> {
    let mut out = run("scutil", &["--dns"]).await?;
    // Only the first block describes what the system actually uses.
    if let Some(i) = out.find("DNS configuration (for scoped queries)") {
        out.truncate(i);
    }
    let mut res: Vec<DnsServer> = vec![];
    for block in out.split("resolver #").skip(1) {
        let (mut domain, mut iface, mut servers, mut mdns) = (String::new(), String::new(), vec![], false);
        for line in block.lines() {
            let Some((k, v)) = line.split_once(':') else { continue };
            let (k, v) = (k.trim(), v.trim());
            if k == "domain" {
                domain = v.to_string();
            } else if k.starts_with("nameserver[") {
                servers.push(v.to_string());
            } else if k == "if_index" {
                if let Some((_, b)) = v.split_once('(') {
                    iface = b.trim_end_matches(')').trim().to_string();
                }
            } else if k == "options" && v.contains("mdns") {
                mdns = true;
            }
        }
        if mdns {
            continue;
        }
        for s in servers {
            if !res.iter().any(|r| r.addr == s && r.domain == domain) {
                res.push(DnsServer { addr: s, iface: iface.clone(), domain: domain.clone() });
            }
        }
    }
    Ok((res, vec![]))
}

pub async fn proxy_settings() -> Result<Vec<ProxySetting>, String> {
    let out = run("scutil", &["--proxy"]).await?;
    let kv: HashMap<String, String> = out
        .lines()
        .filter_map(|l| l.split_once(" : ").map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .collect();
    let g = |k: &str| kv.get(k).cloned().unwrap_or_default();
    let mut ps = vec![];
    for (en, host, port, kind) in [
        ("HTTPEnable", "HTTPProxy", "HTTPPort", "HTTP proxy"),
        ("HTTPSEnable", "HTTPSProxy", "HTTPSPort", "HTTPS proxy"),
        ("SOCKSEnable", "SOCKSProxy", "SOCKSPort", "SOCKS proxy"),
    ] {
        if g(en) == "1" {
            ps.push(ProxySetting { source: "System (macOS)".into(), kind: kind.into(), value: format!("{}:{}", g(host), g(port)) });
        }
    }
    if g("ProxyAutoConfigEnable") == "1" {
        ps.push(ProxySetting { source: "System (macOS)".into(), kind: "Auto-config (PAC) file".into(), value: g("ProxyAutoConfigURLString") });
    }
    if g("ProxyAutoDiscoveryEnable") == "1" {
        ps.push(ProxySetting { source: "System (macOS)".into(), kind: "Auto proxy discovery (WPAD)".into(), value: "on".into() });
    }
    Ok(ps)
}

pub async fn vpn_services() -> Result<Vec<String>, String> {
    let out = run("scutil", &["--nc", "list"]).await?;
    Ok(out
        .lines()
        .filter(|l| l.contains("(Connected)"))
        .filter_map(|l| {
            let a = l.find('"')?;
            let b = l[a + 1..].find('"')?;
            Some(l[a + 1..a + 1 + b].to_string())
        })
        .collect())
}

fn split_dot_port(s: &str) -> (String, u16) {
    match s.rfind(['.', ':']) {
        Some(i) => (s[..i].to_string(), s[i + 1..].parse().unwrap_or(0)),
        None => (s.to_string(), 0),
    }
}

pub async fn listeners() -> Result<(Vec<Listener>, Vec<String>), String> {
    let mut ls = vec![];
    for proto in ["tcp", "udp"] {
        let out = run("netstat", &["-an", "-p", proto]).await?;
        for line in out.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 5 || !f[0].starts_with(proto) {
                continue;
            }
            if proto == "tcp" && (f.len() < 6 || f[5] != "LISTEN") {
                continue;
            }
            if proto == "udp" && f[4] != "*.*" {
                continue;
            }
            let (mut addr, port) = split_dot_port(f[3]);
            if addr == "*" {
                addr = if f[0].ends_with('6') && !f[0].ends_with("46") { "::".into() } else { "0.0.0.0".into() };
            }
            ls.push(Listener { proto: proto.into(), addr, port, pid: 0, process: String::new() });
        }
    }
    // lsof adds names for this user's own processes.
    let mut names: HashMap<String, (u32, String)> = HashMap::new();
    for (proto, args) in [("tcp", vec!["-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"]), ("udp", vec!["-nP", "-iUDP", "-F", "pcn"])] {
        let out = run("lsof", &args).await.unwrap_or_default();
        let (mut pid, mut cmd) = (0u32, String::new());
        for line in out.lines() {
            match line.chars().next() {
                Some('p') => pid = line[1..].parse().unwrap_or(0),
                Some('c') => cmd = line[1..].to_string(),
                Some('n') if !line.contains("->") => {
                    let (_, port) = split_dot_port(&line[1..]);
                    names.insert(format!("{proto}{port}"), (pid, cmd.clone()));
                }
                _ => {}
            }
        }
    }
    let mut missing = false;
    for l in &mut ls {
        if let Some((pid, cmd)) = names.get(&format!("{}{}", l.proto, l.port)) {
            l.pid = *pid;
            l.process = cmd.clone();
        } else {
            missing = true;
        }
    }
    let limits = if missing { vec!["macOS only shows process names for your own apps without admin rights, so system services appear without a name.".to_string()] } else { vec![] };
    Ok((ls, limits))
}

pub async fn neighbor_table() -> Result<Neighbors, String> {
    let out = run("arp", &["-an"]).await?;
    let mut m = Neighbors::new();
    for line in out.lines() {
        // ? (192.168.1.1) at a4:2b:b0:1:2:3 on en0 ifscope [ethernet]
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[2] != "at" {
            continue;
        }
        if let Some(mac) = norm_mac(f[3]) {
            m.insert(f[1].trim_matches(|c| c == '(' || c == ')').to_string(), mac);
        }
    }
    Ok(m)
}
