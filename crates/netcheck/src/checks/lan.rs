//! Opt-in scan of the local network: devices and the services they expose.

use super::lan_discovery::*;
use super::*;
use crate::facts::usable_addrs;
use futures::StreamExt;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use tokio::sync::OnceCell;

pub const SEC_LAN: &str = "Local Network Devices & Services";
const MAX_HOST_BITS: u8 = 10; // a /22; bigger subnets only use the neighbor table
const PROBES_PER_SEC: u32 = 50;

pub type Progress = Arc<dyn Fn(String) + Send + Sync>;

#[derive(Debug, Clone, Default)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub random: bool,
    pub gateway: bool,
    pub this: bool,
    /// Best first.
    pub names: Vec<String>,
    /// mDNS service types.
    pub services: Vec<String>,
    pub model: String,
    pub upnp: Option<SsdpInfo>,
    pub ports: Vec<PortResult>,
    pub kind: String,
    pub label: String,
    pub unidentified: bool,
}

#[derive(Default)]
struct Scan {
    devices: Vec<Device>,
    limits: Vec<String>,
    scanned: usize,
    subnet: String,
    err: String,
}

struct Lan {
    facts: Arc<Facts>,
    progress: Option<Progress>,
    scan: OnceCell<Arc<Scan>>,
}

/// The opt-in network scan checks.
pub fn checks(progress: Progress) -> Vec<Check> {
    let s = Arc::new(Lan { facts: Facts::new(), progress: Some(progress), scan: OnceCell::new() });
    let (a, b) = (s.clone(), s);
    vec![
        Check { id: "lan-devices", section: SEC_LAN, title: "Devices on your network", timeout: Duration::from_secs(150), run: Box::new(move |r| Box::pin(devices_check(a, r))) },
        Check { id: "lan-services", section: SEC_LAN, title: "Services other devices expose", timeout: Duration::from_secs(150), run: Box::new(move |r| Box::pin(services_check(b, r))) },
    ]
}

impl Lan {
    fn say(&self, m: String) {
        if let Some(p) = &self.progress {
            p(m);
        }
    }
    async fn get(&self) -> Arc<Scan> {
        self.scan.get_or_init(|| async { Arc::new(self.run().await) }).await.clone()
    }

    async fn run(&self) -> Scan {
        let mut s = Scan::default();
        let l = self.facts.load().await;
        let Some(p) = l.primary.clone() else {
            s.err = "This computer is not connected to a network.".into();
            return s;
        };
        if l.kind(&p).kind == "VPN/tunnel" {
            s.err = "All traffic is going through a VPN, so your local network can't be seen. Disconnect the VPN and scan again.".into();
            return s;
        }
        let Some((self_ip, prefix, _)) = usable_addrs(&p).v4.into_iter().rfind(|(ip, _, _)| !ip.is_link_local()) else {
            s.err = "This computer has no usable IPv4 address on the local network.".into();
            return s;
        };
        if !self_ip.is_private() {
            s.err = "The scan only runs on private home or office networks (addresses like 192.168.x.x or 10.x.x.x).".into();
            return s;
        }
        let net = ipnet::Ipv4Net::new(self_ip, prefix).map(|n| n.trunc()).unwrap();
        s.subnet = net.to_string();
        let lim = Limiter::new(PROBES_PER_SEC);

        // 1. Gentle sweep so the neighbor table fills in.
        let mut hosts = hosts_in(&net);
        if 32 - prefix > MAX_HOST_BITS {
            s.limits.push(format!("Your network ({}) is larger than {} addresses, so only devices this computer has recently talked to were checked.", s.subnet, 1 << MAX_HOST_BITS));
            hosts.clear();
        }
        if !hosts.is_empty() {
            self.say(format!("Saying hello to {} addresses on {}…", hosts.len(), s.subnet));
        }
        s.scanned = hosts.len();
        let (alive, md, ss) = tokio::join!(sweep(hosts, &lim), mdns_discover(Duration::from_secs(4)), ssdp_discover(Duration::from_secs(4)));
        let neigh = match crate::platform::neighbor_table().await {
            Ok(n) => n,
            Err(e) => {
                s.limits.push(format!("Could not read the neighbor (ARP) table: {e}"));
                Default::default()
            }
        };

        // 2. Merge everything we heard about into devices.
        let mut by_ip: BTreeMap<u32, Device> = BTreeMap::new();
        let mut add = |ip: &str| -> Option<u32> {
            let a: Ipv4Addr = ip.parse().ok()?;
            if !net.contains(&a) {
                return None;
            }
            let k = u32::from(a);
            by_ip.entry(k).or_insert_with(|| Device { ip: ip.into(), ..Default::default() });
            Some(k)
        };
        let mut macs = vec![];
        for (ip, mac) in &neigh {
            if let Some(k) = add(ip) {
                macs.push((k, mac.clone()));
            }
        }
        for ip in alive.iter().chain(md.keys()).chain(ss.keys()) {
            add(ip);
        }
        let me = add(&self_ip.to_string());
        let gw = add(&l.gateway4);
        for (k, mac) in macs {
            by_ip.get_mut(&k).unwrap().mac = mac;
        }
        if let Some(d) = me.and_then(|k| by_ip.get_mut(&k)) {
            d.this = true;
            d.mac = p.mac_addr.map(|m| m.to_string()).unwrap_or_default();
        }
        if let Some(d) = gw.and_then(|k| by_ip.get_mut(&k)) {
            d.gateway = true;
        }

        // 3. Names, vendors and services.
        self.say(format!("Found {} devices. Looking up names and checking common services…", by_ip.len()));
        let resolver = crate::platform::dns_servers()
            .await
            .ok()
            .and_then(|(v, _)| v.into_iter().find(|d| d.domain.is_empty() && d.addr.parse::<Ipv4Addr>().is_ok_and(|a| a.is_private())).map(|d| d.addr))
            .unwrap_or_else(|| l.gateway4.clone());
        for d in by_ip.values_mut() {
            if !d.mac.is_empty() {
                d.vendor = mac_vendor(&d.mac);
                d.random = random_mac(&d.mac);
            }
            if let Some(m) = md.get(&d.ip) {
                d.names.extend(m.instances.iter().cloned());
                d.names.extend(m.hosts.iter().cloned());
                d.services = m.services.iter().cloned().collect();
                for k in ["model", "md", "usb_mdl", "ty", "am", "product"] {
                    if let Some(v) = m.txt.get(k) {
                        d.model = v.clone();
                        break;
                    }
                }
            }
            d.upnp = ss.get(&d.ip).cloned();
        }
        let lim = &lim;
        let resolver = &resolver;
        let extra: Vec<(u32, Option<String>, String, Vec<PortResult>)> = futures::stream::iter(by_ip.iter().map(|(k, d)| (*k, d.ip.clone(), d.this)).collect::<Vec<_>>())
            .map(|(k, ip, this)| async move {
                let a: Ipv4Addr = ip.parse().unwrap();
                let rev = if resolver.is_empty() { None } else { reverse_name(a, resolver).await };
                let (nb, ports) = if this { (String::new(), vec![]) } else { tokio::join!(netbios_name(&ip), probe_host(a, lim)) };
                (k, rev, nb, ports)
            })
            .buffer_unordered(8)
            .collect()
            .await;
        for (k, rev, nb, ports) in extra {
            let d = by_ip.get_mut(&k).unwrap();
            d.names.extend(rev);
            if !nb.is_empty() {
                d.names.push(nb);
            }
            d.ports = ports;
        }
        for (_, mut d) in by_ip {
            d.names = uniq(d.names);
            classify(&mut d);
            s.devices.push(d);
        }
        s
    }
}

pub fn hosts_in(n: &ipnet::Ipv4Net) -> Vec<Ipv4Addr> {
    if 32 - n.prefix_len() > MAX_HOST_BITS {
        return vec![];
    }
    n.hosts().filter(|h| *h != n.network() && *h != n.broadcast()).collect()
}

impl Device {
    fn has(&self, svc: &[&str]) -> bool {
        self.services.iter().any(|s| svc.contains(&s.as_str()))
    }
    fn open(&self, ports: &[u16]) -> bool {
        self.ports.iter().any(|p| ports.contains(&p.port))
    }
}

fn contains_any(s: &str, words: &[&str]) -> bool {
    let s = s.to_lowercase();
    words.iter().any(|w| s.contains(w))
}

/// Turns everything known about a device into a plain-English type.
pub fn classify(d: &mut Device) {
    let up = d.upnp.as_ref().map(|u| [u.friendly_name.as_str(), &u.manufacturer, &u.model, &u.device_type, &u.server].join(" ")).unwrap_or_default();
    let mut parts = vec![d.vendor.clone(), d.model.clone(), up.clone()];
    parts.extend(d.names.iter().cloned());
    let all = parts.join(" ");
    let k = if d.this {
        "This computer"
    } else if d.gateway {
        "Router / gateway"
    } else if d.has(&["_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp"]) || d.open(&[9100]) || contains_any(&up, &["printer"]) {
        "Printer"
    } else if d.has(&["_googlecast._tcp"]) || (d.open(&[8008]) && contains_any(&all, &["google"])) {
        "Chromecast / Google TV or speaker"
    } else if d.has(&["_sonos._tcp"]) || contains_any(&all, &["sonos"]) {
        "Sonos speaker"
    } else if d.has(&["_roku._tcp"]) || contains_any(&all, &["roku"]) {
        "Roku streaming device"
    } else if d.has(&["_amzn-wplay._tcp"]) || contains_any(&all, &["amazon technologies", "echo", "fire tv"]) {
        "Amazon Echo / Fire TV"
    } else if d.has(&["_airplay._tcp"]) && contains_any(&all, &["appletv", "apple tv"]) {
        "Apple TV"
    } else if d.has(&["_airplay._tcp", "_raop._tcp"]) && !d.has(&["_companion-link._tcp", "_smb._tcp"]) {
        "AirPlay TV or speaker"
    } else if contains_any(&all, &["mediarenderer", "smart tv", "smarttv", "lg electronics", "samsung electronics", "vizio", "tcl", "hisense"]) && (d.upnp.is_some() || d.has(&["_airplay._tcp"])) {
        "Smart TV"
    } else if d.has(&["_rtsp._tcp"]) || d.open(&[554]) || contains_any(&all, &["hikvision", "dahua", "reolink", "wyze", "ring", "arlo", "amcrest", "camera", "ipcam"]) {
        "Camera or doorbell"
    } else if d.has(&["_hap._tcp", "_matter._tcp", "_home-assistant._tcp"]) || contains_any(&all, &["philips lighting", "signify", "ecobee", "nest", "tuya", "espressif", "shelly", "lifx", "tp-link smart", "wemo"]) {
        "Smart home device"
    } else if d.open(&[62078]) || contains_any(&all, &["iphone", "ipad"]) {
        "iPhone or iPad"
    } else if contains_any(&all, &["synology", "qnap", "western digital", "nas", "truenas", "unraid"]) || (d.open(&[5000]) && d.open(&[445]) && !d.has(&["_companion-link._tcp"])) {
        "Network storage (NAS)"
    } else if d.open(&[32400]) {
        "Media server (Plex)"
    } else if contains_any(&all, &["raspberry pi"]) {
        "Raspberry Pi"
    } else if d.has(&["_companion-link._tcp"]) || (d.has(&["_smb._tcp", "_afpovertcp._tcp"]) && contains_any(&all, &["apple", "mac"])) {
        "Mac or Apple device"
    } else if d.open(&[3389]) || (d.open(&[445]) && d.open(&[139])) || contains_any(&all, &["desktop-", "laptop-"]) {
        "Windows PC"
    } else if contains_any(&all, &["android", "galaxy", "pixel"]) {
        "Phone or tablet"
    } else if contains_any(&all, &["netgear", "ubiquiti", "eero", "tp-link", "linksys", "asus", "aruba", "mikrotik", "google fiber"]) && d.open(&[80, 443]) {
        "Wi-Fi access point or mesh node"
    } else if d.open(&[22]) {
        "Computer or server"
    } else if d.random {
        "Phone, tablet or laptop (private address)"
    } else {
        "Unknown device"
    };
    d.kind = k.into();
    let name = d.names.first().cloned().or_else(|| d.upnp.as_ref().map(|u| u.friendly_name.clone()).filter(|n| !n.is_empty())).unwrap_or_default();
    d.label = if name.is_empty() { d.kind.clone() } else { name.clone() };
    d.unidentified = name.is_empty() && d.vendor.is_empty() && !d.random && d.kind == "Unknown device";
}

async fn devices_check(lan: Arc<Lan>, mut r: CheckResult) -> CheckResult {
    let s = lan.get().await;
    if !s.err.is_empty() {
        r.summary = "Network scan skipped.".into();
        r.limit(s.err.clone());
        return r;
    }
    r.set(Status::Good);
    for l in &s.limits {
        r.limit(l.clone());
    }
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut t = Table::new("Devices", &["IP", "Name", "Type", "Maker (from MAC)", "MAC", "Announces"]);
    let (mut unknown, mut private) = (vec![], vec![]);
    for d in &s.devices {
        *counts.entry(d.kind.clone()).or_default() += 1;
        let vendor = if d.random { "private address (hidden)".to_string() } else { d.vendor.clone() };
        let mut ann = d.services.join(" ");
        if let Some(u) = &d.upnp {
            let mut x = format!("{} {}", u.manufacturer, u.model).trim().to_string();
            if x.is_empty() {
                x = u.server.clone();
            }
            ann = format!("{ann} UPnP: {x}").trim().to_string();
        }
        if !d.model.is_empty() {
            ann = format!("model {} {ann}", d.model).trim().to_string();
        }
        t.row(vec![d.ip.clone(), or_dash(&d.names.join(", ")), d.kind.clone(), or_dash(&vendor), or_dash(&d.mac), ann]);
        if d.unidentified {
            unknown.push(d.ip.clone());
        }
        if d.kind == "Phone, tablet or laptop (private address)" && d.names.is_empty() {
            private.push(d.ip.clone());
        }
        if d.ip.starts_with("169.254.") {
            r.add(Status::Warn, format!("Device without a proper address: {}", d.ip), "This device gave itself a 169.254 address because the router did not hand it one. It probably can't reach the internet.");
        }
    }
    r.tables.push(t);
    let mut macs: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for d in s.devices.iter().filter(|d| !d.mac.is_empty() && !d.this) {
        macs.entry(&d.mac).or_default().push(&d.ip);
    }
    for (mac, ips) in macs {
        if ips.len() > 1 {
            r.add(Status::Info, "One device on several addresses", format!("MAC {mac} answers for {}. Usually a device with more than one address (or a Wi-Fi extender); rarely, a sign of address spoofing.", ips.join(", ")));
        }
    }
    if !unknown.is_empty() {
        r.add(Status::Warn, format!("{} unidentified device(s)", unknown.len()), format!("No name, maker or announcement for: {}. Often a smart plug or a device that keeps quiet, but if you don't recognise it, check your router's device list.", unknown.join(", ")));
    }
    if !private.is_empty() {
        r.add(Status::Info, format!("{} device(s) using private Wi-Fi addresses", private.len()), format!("Phones, tablets and laptops hide their real hardware address for privacy, so their maker can't be shown: {}.", private.join(", ")));
    }
    let kinds: Vec<String> = counts.iter().map(|(k, v)| format!("{v} {}", k.to_lowercase())).collect();
    r.summary = format!("{} devices found on {}.", s.devices.len(), s.subnet);
    r.detail("Subnet", s.subnet.clone());
    r.detail("Addresses checked", s.scanned.to_string());
    r.detail("By type", kinds.join("; "));
    r.detail("Method", "neighbor table, one ping per address, mDNS/Bonjour, SSDP/UPnP, reverse DNS, NetBIOS names. No logins.");
    r
}

async fn services_check(lan: Arc<Lan>, mut r: CheckResult) -> CheckResult {
    let s = lan.get().await;
    if !s.err.is_empty() {
        r.summary = "Network scan skipped.".into();
        r.limit(s.err.clone());
        return r;
    }
    r.set(Status::Good);
    let mut t = Table::new("Open services", &["Device", "IP", "Port", "Service", "What it showed"]);
    let mut group: HashMap<&str, Vec<String>> = HashMap::new();
    let mut total = 0;
    for d in s.devices.iter().filter(|d| !d.this) {
        let has_tls = d.open(&[443, 8443]);
        for p in &d.ports {
            total += 1;
            t.row(vec![d.label.clone(), d.ip.clone(), p.port.to_string(), p.name.clone(), p.detail.clone()]);
            let who = format!("{} ({})", d.label, d.ip);
            match p.port {
                23 => group.entry("telnet").or_default().push(who),
                21 => group.entry("ftp").or_default().push(who),
                80 | 8080 if !has_tls && !p.detail.contains("redirects to https") => group.entry("http").or_default().push(who),
                3389 | 5900 => group.entry("remote").or_default().push(format!("{who} port {}", p.port)),
                1883 => group.entry("mqtt").or_default().push(who),
                554 => group.entry("rtsp").or_default().push(who),
                _ => {}
            }
        }
        if d.gateway && d.upnp.as_ref().is_some_and(|u| u.igd) {
            r.add(Status::Info, "Router allows automatic port opening (UPnP)", "Your router lets devices on the network open ports to the internet by themselves. Games and video calls like this, but a compromised device could use it too. Turn UPnP off in the router if you don't need it.");
        }
    }
    r.tables.push(t);
    let g = |k: &str| group.get(k).map(|v| v.join("; ")).unwrap_or_default();
    if !g("telnet").is_empty() {
        r.add(Status::Bad, "Telnet login open", format!("These accept Telnet, which sends passwords in plain text and is a favourite target of malware: {}. Disable Telnet in the device's settings or update its firmware.", g("telnet")));
    }
    if !g("ftp").is_empty() {
        r.add(Status::Warn, "Unencrypted file transfer (FTP)", format!("FTP sends passwords and files unencrypted: {}.", g("ftp")));
    }
    if !g("http").is_empty() {
        r.add(Status::Warn, "Admin pages without encryption", format!("These offer a web page over plain HTTP with no HTTPS option. A password typed there can be read by anyone else on the network: {}.", g("http")));
    }
    if !g("remote").is_empty() {
        r.add(Status::Warn, "Remote control open on the network", format!("Remote Desktop or VNC is reachable from other devices: {}. Turn it off where you don't use it, and make sure strong passwords are set where you do.", g("remote")));
    }
    if !g("mqtt").is_empty() {
        r.add(Status::Info, "Smart home messaging (MQTT) without encryption", format!("An MQTT broker is running on {}. Fine inside a home if it requires a password.", g("mqtt")));
    }
    if !g("rtsp").is_empty() {
        r.add(Status::Info, "Video streams available", format!("These offer RTSP video streams, typical of cameras: {}. Make sure each camera's default password was changed.", g("rtsp")));
    }
    r.summary = format!("{total} open service(s) across {} device(s).", s.devices.len().saturating_sub(1));
    r.detail("Ports checked per device", LAN_PORTS.iter().map(|p| p.0.to_string()).collect::<Vec<_>>().join(", "));
    r.detail("Limits", format!("at most {PROBES_PER_SEC} new connections per second overall and 4 per device; one banner read or one page request per service; no logins."));
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::norm_mac;

    #[test]
    fn mac_helpers() {
        assert_eq!(norm_mac("a4:2b:b0:1:2:3").as_deref(), Some("a4:2b:b0:01:02:03"));
        assert_eq!(norm_mac("A4-2B-B0-01-02-03").as_deref(), Some("a4:2b:b0:01:02:03"));
        assert!(norm_mac("ff:ff:ff:ff:ff:ff").is_none() && norm_mac("01:00:5e:00:00:fb").is_none());
        assert!(random_mac("da:a1:19:00:00:01") && !random_mac("f0:d1:a9:00:00:01"));
        assert_eq!(mac_vendor("b8:27:eb:12:34:56"), "Raspberry Pi Foundation");
    }

    #[test]
    fn hosts() {
        let h = hosts_in(&"192.168.1.0/24".parse().unwrap());
        assert_eq!(h.len(), 254);
        assert_eq!(h[0].to_string(), "192.168.1.1");
        assert_eq!(h[253].to_string(), "192.168.1.254");
        assert!(hosts_in(&"10.0.0.0/16".parse().unwrap()).is_empty());
    }

    #[test]
    fn mdns_names() {
        assert_eq!(svc_type("Living Room._airplay._tcp.local"), "_airplay._tcp");
        assert_eq!(instance_name(r"Living\032Room._airplay._tcp.local"), "Living Room");
    }

    fn port(p: u16) -> PortResult {
        PortResult { port: p, ..Default::default() }
    }

    #[test]
    fn classify_cases() {
        let cases = vec![
            (Device { services: vec!["_ipp._tcp".into()], ..Default::default() }, "Printer"),
            (Device { services: vec!["_googlecast._tcp".into()], ..Default::default() }, "Chromecast / Google TV or speaker"),
            (Device { ports: vec![port(62078)], ..Default::default() }, "iPhone or iPad"),
            (Device { ports: vec![port(554)], ..Default::default() }, "Camera or doorbell"),
            (Device { gateway: true, ..Default::default() }, "Router / gateway"),
            (Device { random: true, ..Default::default() }, "Phone, tablet or laptop (private address)"),
            (Device { vendor: "Raspberry Pi Foundation".into(), ..Default::default() }, "Raspberry Pi"),
            (Device { ports: vec![port(445), port(139)], ..Default::default() }, "Windows PC"),
        ];
        for (mut d, want) in cases {
            classify(&mut d);
            assert_eq!(d.kind, want);
        }
        let mut u = Device::default();
        classify(&mut u);
        assert!(u.unidentified);
    }
}
