//! Discovery building blocks for the opt-in LAN scan. Every probe is unauthenticated,
//! read-only and rate-limited.

use super::*;
use crate::dnsmsg::{self, RData, TYPE_PTR};
use futures::StreamExt;
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};

// ---- MAC addresses and vendors ----

/// Vendor prefixes derived from the IEEE OUI registry (via nmap-mac-prefixes).
static OUI_GZ: &[u8] = include_bytes!("oui.txt.gz");

pub fn mac_vendor(mac: &str) -> String {
    static MAP: OnceLock<HashMap<String, String>> = OnceLock::new();
    let m = MAP.get_or_init(|| {
        let mut s = String::new();
        let _ = flate2::read::GzDecoder::new(OUI_GZ).read_to_string(&mut s);
        s.lines().filter_map(|l| l.split_once(' ')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
    });
    if mac.len() < 8 {
        return String::new();
    }
    m.get(&mac[..8].replace(':', "").to_uppercase()).cloned().unwrap_or_default()
}

/// A locally administered address: phones, tablets and laptops use these for
/// Wi-Fi privacy, so the vendor cannot be known.
pub fn random_mac(mac: &str) -> bool {
    mac.get(..2).and_then(|b| u8::from_str_radix(b, 16).ok()).is_some_and(|b| b & 0x02 != 0)
}

// ---- Rate limiting shared by every probe in a scan ----

pub struct Limiter {
    period: Duration,
    next: Mutex<Instant>,
}

impl Limiter {
    pub fn new(per_second: u32) -> Self {
        Limiter { period: Duration::from_secs(1) / per_second, next: Mutex::new(Instant::now()) }
    }
    pub async fn wait(&self) {
        let slot = {
            let mut n = self.next.lock().unwrap();
            let now = Instant::now();
            let slot = if *n > now { *n } else { now };
            *n = slot + self.period;
            slot
        };
        tokio::time::sleep_until(slot.into()).await;
    }
}

/// One echo (or one TCP connect when ICMP isn't allowed) per address. Replies matter
/// less than the side effect: the OS learns each device's MAC address.
pub async fn sweep(hosts: Vec<Ipv4Addr>, lim: &Limiter) -> HashSet<String> {
    futures::stream::iter(hosts)
        .map(|ip| async move {
            lim.wait().await;
            let ip = IpAddr::V4(ip);
            let ok = match crate::icmp::ping(ip, 1, Duration::ZERO).await {
                Ok(st) => st.received > 0,
                Err(_) => tcp_connect(SocketAddr::new(ip, 80), Duration::from_millis(700)).await.is_ok(),
            };
            ok.then(|| ip.to_string())
        })
        .buffer_unordered(32)
        .filter_map(|x| async { x })
        .collect()
        .await
}

// ---- mDNS / Bonjour ----

#[derive(Default, Debug)]
pub struct MdnsInfo {
    pub hosts: BTreeSet<String>,
    pub services: BTreeSet<String>,
    pub instances: BTreeSet<String>,
    pub txt: HashMap<String, String>,
}

const MDNS_TYPES: &[&str] = &[
    "_services._dns-sd._udp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_ipp._tcp", "_ipps._tcp",
    "_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp", "_uscan._tcp", "_smb._tcp", "_afpovertcp._tcp",
    "_hap._tcp", "_companion-link._tcp", "_device-info._tcp", "_sonos._tcp", "_spotify-connect._tcp",
    "_http._tcp", "_ssh._tcp", "_rfb._tcp", "_amzn-wplay._tcp", "_matter._tcp", "_workstation._tcp",
    "_rtsp._tcp", "_androidtvremote2._tcp", "_roku._tcp", "_nvstream._tcp", "_home-assistant._tcp",
];

/// "Name._airplay._tcp.local" or "_airplay._tcp.local" -> "_airplay._tcp".
pub fn svc_type(name: &str) -> String {
    let name = name.trim_end_matches(".local");
    let parts: Vec<&str> = name.split('.').collect();
    for i in 0..parts.len().saturating_sub(1) {
        if parts[i].starts_with('_') && (parts[i + 1] == "_tcp" || parts[i + 1] == "_udp") {
            return format!("{}.{}", parts[i], parts[i + 1]);
        }
    }
    name.to_string()
}

pub fn instance_name(full: &str) -> String {
    match full.find("._") {
        Some(i) if i > 0 => full[..i].replace("\\032", " "),
        _ => String::new(),
    }
}

async fn recv_all(sock: &UdpSocket, wait: Duration, mut on: impl FnMut(&[u8], IpAddr)) {
    let deadline = Instant::now() + wait;
    let mut buf = vec![0u8; 9000];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => on(&buf[..n], from.ip()),
            _ => break,
        }
    }
}

pub async fn mdns_discover(wait: Duration) -> HashMap<String, MdnsInfo> {
    let mut res: HashMap<String, MdnsInfo> = HashMap::new();
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else { return res };
    let names: Vec<String> = MDNS_TYPES.iter().map(|t| format!("{t}.local")).collect();
    // Class with the top bit set asks responders to reply directly to us (QU).
    let qs: Vec<(&str, u16, u16)> = names.iter().map(|n| (n.as_str(), TYPE_PTR, 0x8001)).collect();
    let pkt = dnsmsg::build_query(0, &qs, false);
    let dst: SocketAddr = "224.0.0.251:5353".parse().unwrap();
    let _ = sock.send_to(&pkt, dst).await;
    let resend = async {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let _ = sock.send_to(&pkt, dst).await;
    };
    let collect = recv_all(&sock, wait, |b, from| {
        let Some(m) = dnsmsg::parse(b) else { return };
        let ip = from.to_string();
        let info = res.entry(ip.clone()).or_default();
        for rr in m.records {
            let name = rr.name.trim_end_matches('.').to_string();
            match rr.data {
                RData::A(a) if a.to_string() == ip => {
                    info.hosts.insert(name.trim_end_matches(".local").to_string());
                }
                RData::Ptr(target) => {
                    let target = target.trim_end_matches('.').to_string();
                    if name.starts_with("_services._dns-sd") {
                        info.services.insert(svc_type(&target));
                    } else {
                        info.services.insert(svc_type(&name));
                        let inst = instance_name(&target);
                        if !inst.is_empty() {
                            info.instances.insert(inst);
                        }
                    }
                }
                RData::Srv { target, .. } => {
                    info.services.insert(svc_type(&name));
                    let inst = instance_name(&name);
                    if !inst.is_empty() {
                        info.instances.insert(inst);
                    }
                    info.hosts.insert(target.trim_end_matches('.').trim_end_matches(".local").to_string());
                }
                RData::Txt(kvs) => {
                    for kv in kvs {
                        if let Some((k, v)) = kv.split_once('=') {
                            let k = k.to_lowercase();
                            if !v.is_empty() && matches!(k.as_str(), "model" | "md" | "fn" | "ty" | "usb_mdl" | "am" | "manufacturer" | "product") {
                                info.txt.insert(k, v.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });
    tokio::join!(resend, collect);
    res
}

// ---- SSDP / UPnP ----

#[derive(Default, Debug, Clone)]
pub struct SsdpInfo {
    pub server: String,
    pub location: String,
    /// Router offers UPnP port mapping.
    pub igd: bool,
    pub friendly_name: String,
    pub manufacturer: String,
    pub model: String,
    pub device_type: String,
}

fn xml_tag(b: &str, tag: &str) -> String {
    let re = Regex::new(&format!(r"(?s)<{tag}>([^<]{{1,120}})</{tag}>")).unwrap();
    re.captures(b).map(|c| c[1].trim().to_string()).unwrap_or_default()
}

pub async fn ssdp_discover(wait: Duration) -> HashMap<String, SsdpInfo> {
    let mut res: HashMap<String, SsdpInfo> = HashMap::new();
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else { return res };
    let req = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
    let _ = sock.send_to(req.as_bytes(), "239.255.255.250:1900").await;
    recv_all(&sock, wait, |b, from| {
        let info = res.entry(from.to_string()).or_default();
        for line in String::from_utf8_lossy(b).split("\r\n") {
            let Some((k, v)) = line.split_once(':') else { continue };
            let v = v.trim();
            match k.trim().to_uppercase().as_str() {
                "SERVER" => info.server = v.into(),
                "LOCATION" if info.location.is_empty() => info.location = v.into(),
                "ST" | "NT" if v.contains("InternetGatewayDevice") || v.contains("WANIPConnection") => info.igd = true,
                _ => {}
            }
        }
    })
    .await;
    // One GET of each device's own description file, only on the device that announced it.
    let jobs = res.iter().filter_map(|(ip, info)| {
        let u = info.location.clone();
        (u.starts_with("http://") && (u.contains(&format!("//{ip}:")) || u.contains(&format!("//{ip}/")))).then(|| {
            let ip = ip.clone();
            async move { (ip, http::get(&u, Duration::from_millis(2500)).await) }
        })
    });
    for (ip, resp) in futures::future::join_all(jobs.collect::<Vec<_>>()).await {
        let (Ok(resp), Some(info)) = (resp, res.get_mut(&ip)) else { continue };
        let b = resp.text();
        info.friendly_name = xml_tag(&b, "friendlyName");
        info.manufacturer = xml_tag(&b, "manufacturer");
        info.model = format!("{} {}", xml_tag(&b, "modelName"), xml_tag(&b, "modelNumber")).trim().to_string();
        info.device_type = xml_tag(&b, "deviceType");
        info.igd |= b.contains("InternetGatewayDevice");
    }
    res
}

// ---- NetBIOS name (Windows PCs, NAS boxes) ----

pub async fn netbios_name(ip: &str) -> String {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else { return String::new() };
    if sock.connect(format!("{ip}:137")).await.is_err() {
        return String::new();
    }
    let mut q = vec![0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, b'C', b'K'];
    q.extend(std::iter::repeat_n(b'A', 30));
    q.extend([0, 0, 0x21, 0, 1]);
    if sock.send(&q).await.is_err() {
        return String::new();
    }
    let mut buf = [0u8; 1024];
    let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(800), sock.recv(&mut buf)).await else { return String::new() };
    if n < 57 {
        return String::new();
    }
    let mut off = 56; // header 12 + name 34 + type/class/ttl/len 10
    let count = buf[off] as usize;
    off += 1;
    for _ in 0..count {
        if off + 18 > n {
            break;
        }
        let name = String::from_utf8_lossy(&buf[off..off + 15]).trim().to_string();
        let suffix = buf[off + 15];
        let flags = u16::from_be_bytes([buf[off + 16], buf[off + 17]]);
        off += 18;
        if suffix == 0 && flags & 0x8000 == 0 && !name.is_empty() {
            return name;
        }
    }
    String::new()
}

/// Reverse DNS through a resolver on the local network (usually the router, which knows DHCP names).
pub async fn reverse_name(ip: Ipv4Addr, via: &str) -> Option<String> {
    let o = ip.octets();
    let q = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
    let a = super::dns::dns_query(via, &q, TYPE_PTR, Duration::from_millis(1500)).await.ok()?;
    a.names.into_iter().find(|n| !n.is_empty() && !n.ends_with(".in-addr.arpa"))
}

// ---- Service probes ----

pub enum Kind {
    Web,
    Tls,
    Banner,
    Plain,
}

pub const LAN_PORTS: &[(u16, &str, Kind)] = &[
    (21, "FTP", Kind::Banner), (22, "SSH", Kind::Banner), (23, "Telnet", Kind::Plain), (53, "DNS", Kind::Plain),
    (80, "Web (HTTP)", Kind::Web), (139, "NetBIOS file sharing", Kind::Plain), (443, "Web (HTTPS)", Kind::Tls),
    (445, "SMB file sharing", Kind::Plain), (548, "AFP file sharing", Kind::Plain), (554, "RTSP video stream", Kind::Plain),
    (631, "IPP printing", Kind::Plain), (1883, "MQTT (smart home, unencrypted)", Kind::Plain), (3389, "Remote Desktop", Kind::Plain),
    (5000, "Web / AirPlay", Kind::Plain), (5900, "VNC screen sharing", Kind::Plain), (7000, "AirPlay", Kind::Plain),
    (8008, "Chromecast", Kind::Plain), (8080, "Web (HTTP alt)", Kind::Web), (8443, "Web (HTTPS alt)", Kind::Tls),
    (9100, "Raw printing (JetDirect)", Kind::Plain), (32400, "Plex media server", Kind::Plain), (62078, "Apple iPhone/iPad sync", Kind::Plain),
];

#[derive(Debug, Clone, Default)]
pub struct PortResult {
    pub port: u16,
    pub name: String,
    pub detail: String,
}

pub async fn probe_host(ip: Ipv4Addr, lim: &Limiter) -> Vec<PortResult> {
    let mut out: Vec<PortResult> = futures::stream::iter(0..LAN_PORTS.len())
        .map(|i| async move {
            let (port, name, kind) = &LAN_PORTS[i];
            lim.wait().await;
            let addr = SocketAddr::new(IpAddr::V4(ip), *port);
            let mut c = tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(addr)).await.ok()?.ok()?;
            let mut r = PortResult { port: *port, name: name.to_string(), detail: String::new() };
            match kind {
                Kind::Banner => {
                    let mut b = [0u8; 200];
                    if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(1500), c.read(&mut b)).await {
                        r.detail = String::from_utf8_lossy(&b[..n]).lines().next().unwrap_or("").trim().to_string();
                    }
                }
                Kind::Web => {
                    drop(c);
                    r.detail = http_summary(&format!("http://{addr}/")).await;
                }
                Kind::Tls => {
                    drop(c);
                    r.detail = http_summary(&format!("https://{addr}/")).await;
                }
                Kind::Plain => {}
            }
            Some(r)
        })
        .buffer_unordered(4) // at most 4 connections per device
        .filter_map(|x| async { x })
        .collect()
        .await;
    out.sort_by_key(|p| p.port);
    out
}

pub async fn http_summary(u: &str) -> String {
    static TITLE: OnceLock<Regex> = OnceLock::new();
    let Ok(resp) = http::get(u, Duration::from_secs(3)).await else { return String::new() };
    let mut parts = vec![];
    let body = resp.text();
    if let Some(c) = TITLE.get_or_init(|| Regex::new(r"(?is)<title[^>]*>\s*([^<]{1,100}?)\s*</title>").unwrap()).captures(&body) {
        parts.push(format!("{:?}", c[1].split_whitespace().collect::<Vec<_>>().join(" ")));
    }
    let server = resp.header("server");
    if !server.is_empty() {
        parts.push(format!("server {server}"));
    }
    if (300..400).contains(&resp.status) {
        parts.push(format!("redirects to {}", resp.header("location")));
    }
    if resp.status == 401 {
        parts.push("asks for a password".into());
    }
    if let Some(cert) = &resp.cert {
        let mut s = format!("certificate {}", cert.subject_cn);
        if cert.self_signed {
            s += " (self-signed)";
        }
        if cert.expired {
            s += " (expired)";
        }
        parts.push(s);
    }
    parts.join(", ")
}
