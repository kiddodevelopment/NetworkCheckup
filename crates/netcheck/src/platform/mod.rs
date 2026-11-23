//! Operating-system specific readers. Everything here works without admin rights.

use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct IfaceMeta {
    pub kind: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct DnsServer {
    pub addr: String,
    pub iface: String,
    /// Non-empty when this server only answers for certain domains (split DNS).
    pub domain: String,
}

#[derive(Debug, Clone)]
pub struct ProxySetting {
    pub source: String,
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Listener {
    pub proto: String,
    pub addr: String,
    pub port: u16,
    pub pid: u32,
    pub process: String,
}

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::*;

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod linux;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub use self::linux::*;

const TUNNEL_PREFIXES: &[&str] = &["utun", "tun", "tap", "wg", "ppp", "ipsec", "gpd", "zt", "tailscale", "nordlynx", "proton", "vpn", "cscotun", "ham"];
const TUNNEL_WORDS: &[&str] = &["vpn", "wireguard", "tap-windows", "tunnel", "openvpn", "anyconnect", "globalprotect", "fortinet", "zscaler", "tailscale", "zerotier", "wintun"];

pub fn looks_like_tunnel(name: &str, desc: &str) -> bool {
    let n = name.to_lowercase();
    if TUNNEL_PREFIXES.iter().any(|p| n.starts_with(p)) {
        return true;
    }
    let d = format!("{} {}", desc.to_lowercase(), n);
    TUNNEL_WORDS.iter().any(|w| d.contains(w))
}

/// Normalises a MAC to lowercase aa:bb:cc:dd:ee:ff, dropping multicast/broadcast/empty ones.
pub fn norm_mac(s: &str) -> Option<String> {
    let s = s.trim().to_lowercase().replace('-', ":");
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = vec![];
    for p in parts {
        match p.len() {
            1 => out.push(format!("0{p}")),
            2 => out.push(p.to_string()),
            _ => return None,
        }
    }
    let mac = out.join(":");
    if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" || mac.starts_with("01:00:5e") || mac.starts_with("33:33") {
        return None;
    }
    Some(mac)
}

pub type Neighbors = HashMap<String, String>;
