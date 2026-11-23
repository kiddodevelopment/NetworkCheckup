//! Linux support exists for development and testing; Windows and macOS are the targets.
use super::*;
use std::net::Ipv6Addr;

pub async fn iface_meta() -> HashMap<String, IfaceMeta> {
    HashMap::new()
}

pub async fn dns_servers() -> Result<(Vec<DnsServer>, Vec<String>), String> {
    let s = std::fs::read_to_string("/etc/resolv.conf").map_err(|e| e.to_string())?;
    let mut res = vec![];
    let mut notes = vec![];
    for line in s.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 2 && f[0] == "nameserver" {
            res.push(DnsServer { addr: f[1].into(), iface: String::new(), domain: String::new() });
            if f[1] == "127.0.0.53" {
                notes.push("systemd-resolved stub (127.0.0.53) forwards to the real upstream servers.".to_string());
            }
        }
    }
    Ok((res, notes))
}

pub async fn proxy_settings() -> Result<Vec<ProxySetting>, String> {
    Ok(vec![])
}

pub async fn vpn_services() -> Result<Vec<String>, String> {
    Ok(vec![])
}

fn hex_ip(h: &str) -> String {
    let raw: Vec<u8> = (0..h.len() / 2).filter_map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()).collect();
    let mut ip = raw.clone();
    for (i, w) in raw.chunks(4).enumerate() {
        for j in 0..w.len() {
            ip[i * 4 + j] = w[w.len() - 1 - j];
        }
    }
    if ip.len() == 4 {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    } else if ip.len() == 16 {
        let a: [u8; 16] = ip.try_into().unwrap_or([0; 16]);
        Ipv6Addr::from(a).to_string()
    } else {
        h.to_string()
    }
}

pub async fn listeners() -> Result<(Vec<Listener>, Vec<String>), String> {
    let mut ls = vec![];
    for (file, proto, state) in [("/proc/net/tcp", "tcp", "0A"), ("/proc/net/tcp6", "tcp", "0A"), ("/proc/net/udp", "udp", "07"), ("/proc/net/udp6", "udp", "07")] {
        let Ok(s) = std::fs::read_to_string(file) else { continue };
        for line in s.lines().skip(1) {
            let x: Vec<&str> = line.split_whitespace().collect();
            if x.len() < 4 || x[3] != state {
                continue;
            }
            if proto == "udp" && x[2] != "00000000:0000" && !x[2].starts_with("0000000000000000") {
                continue;
            }
            let Some((h, p)) = x[1].split_once(':') else { continue };
            ls.push(Listener { proto: proto.into(), addr: hex_ip(h), port: u16::from_str_radix(p, 16).unwrap_or(0), pid: 0, process: String::new() });
        }
    }
    Ok((ls, vec!["Process names are not collected on Linux in this build.".to_string()]))
}

pub async fn neighbor_table() -> Result<Neighbors, String> {
    let s = std::fs::read_to_string("/proc/net/arp").map_err(|e| e.to_string())?;
    let mut m = Neighbors::new();
    for line in s.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 4 && f[2] == "0x2" {
            if let Some(mac) = norm_mac(f[3]) {
                m.insert(f[0].to_string(), mac);
            }
        }
    }
    Ok(m)
}
