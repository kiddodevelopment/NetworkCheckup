//! Facts gathered once per run and shared by the checks.

use crate::platform::{self, IfaceMeta};
use crate::util::{probe, Stats};
use netdev::interface::types::InterfaceType;
use netdev::Interface;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;

#[derive(Default)]
pub struct Loaded {
    pub ifaces: Vec<Interface>,
    pub meta: HashMap<String, IfaceMeta>,
    /// Interface carrying the IPv4 default route.
    pub primary: Option<Interface>,
    pub local4: Option<IpAddr>,
    pub local6: Option<IpAddr>,
    pub gateway4: String,
    pub gateway6: String,
}

#[derive(Default)]
pub struct Facts {
    loaded: OnceCell<Arc<Loaded>>,
    gw: OnceCell<Stats>,
}

/// Asks the OS which source address it would use; a UDP "connect" sends no packets.
fn source_addr(dst: &str, bind: &str) -> Option<IpAddr> {
    let s = UdpSocket::bind(bind).ok()?;
    s.connect(dst).ok()?;
    Some(s.local_addr().ok()?.ip())
}

pub fn display_name(i: &Interface) -> String {
    i.friendly_name.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| i.name.clone())
}

pub struct Addrs {
    pub v4: Vec<(Ipv4Addr, u8, Ipv4Addr)>,
    pub v6: Vec<(Ipv6Addr, u8)>,
    pub link_local4: bool,
}

/// IPv4 addresses plus non link-local IPv6 addresses.
pub fn usable_addrs(i: &Interface) -> Addrs {
    let mut a = Addrs { v4: vec![], v6: vec![], link_local4: false };
    for n in &i.ipv4 {
        a.link_local4 |= n.addr().is_link_local();
        a.v4.push((n.addr(), n.prefix_len(), n.netmask()));
    }
    for n in &i.ipv6 {
        if (n.addr().segments()[0] & 0xffc0) != 0xfe80 {
            a.v6.push((n.addr(), n.prefix_len()));
        }
    }
    a
}

pub fn fmt_speed(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{} Gbps", (bps as f64 / 1e9 * 10.0).round() / 10.0)
    } else {
        format!("{} Mbps", bps / 1_000_000)
    }
}

impl Facts {
    pub fn new() -> Arc<Facts> {
        Arc::new(Facts::default())
    }

    pub async fn load(&self) -> Arc<Loaded> {
        self.loaded
            .get_or_init(|| async {
                let meta = platform::iface_meta().await;
                let ifaces = netdev::get_interfaces();
                let local4 = source_addr("1.1.1.1:53", "0.0.0.0:0");
                let local6 = source_addr("[2606:4700:4700::1111]:53", "[::]:0");
                let mut primary = ifaces
                    .iter()
                    .find(|i| local4.is_some_and(|l| i.ipv4.iter().any(|n| IpAddr::V4(n.addr()) == l)))
                    .cloned();
                if primary.is_none() {
                    primary = netdev::get_default_interface().ok();
                }
                let (mut gateway4, mut gateway6) = (String::new(), String::new());
                if let Some(gw) = primary.as_ref().and_then(|p| p.gateway.as_ref()) {
                    gateway4 = gw.ipv4.first().map(|a| a.to_string()).unwrap_or_default();
                    gateway6 = gw.ipv6.first().map(|a| a.to_string()).unwrap_or_default();
                }
                if gateway4.is_empty() {
                    if let Some(gw) = ifaces.iter().filter_map(|i| i.gateway.as_ref()).find(|g| !g.ipv4.is_empty()) {
                        gateway4 = gw.ipv4[0].to_string();
                    }
                }
                Arc::new(Loaded { ifaces, meta, primary, local4, local6, gateway4, gateway6 })
            })
            .await
            .clone()
    }

    /// Pings the IPv4 gateway once and caches the result for other checks.
    pub async fn gateway(&self) -> Stats {
        let l = self.load().await;
        self.gw
            .get_or_init(|| async move {
                match l.gateway4.parse::<IpAddr>() {
                    Ok(ip) => probe(ip, 20, Duration::from_millis(150), &[80, 443, 53]).await,
                    Err(_) => Stats::default(),
                }
            })
            .await
            .clone()
    }
}

impl Loaded {
    pub fn kind(&self, i: &Interface) -> IfaceMeta {
        let name = display_name(i);
        let desc = i.description.clone().unwrap_or_default();
        let mut m = self.meta.get(&i.name).cloned().unwrap_or_else(|| {
            let kind = match i.if_type {
                InterfaceType::Wireless80211 => "Wi-Fi",
                InterfaceType::Tunnel | InterfaceType::Ppp => "VPN/tunnel",
                InterfaceType::Ethernet | InterfaceType::GigabitEthernet | InterfaceType::FastEthernetT | InterfaceType::FastEthernetFx => "Ethernet",
                InterfaceType::Wwan | InterfaceType::Wwanpp | InterfaceType::Wwanpp2 => "Cellular",
                _ => "Other",
            };
            IfaceMeta { kind: kind.into(), description: desc.clone() }
        });
        if m.kind != "Wi-Fi" && m.kind != "VPN/tunnel" && (platform::looks_like_tunnel(&name, &desc) || platform::looks_like_tunnel(&i.name, "")) {
            m.kind = "VPN/tunnel".into();
        }
        m
    }

    pub fn primary_kind(&self) -> String {
        self.primary.as_ref().map(|p| self.kind(p).kind).unwrap_or_default()
    }
}
