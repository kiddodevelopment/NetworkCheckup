//! Every Network Checkup diagnostic.

pub mod connection;
pub mod dns;
pub mod listeners;
pub mod lan;
pub mod lan_discovery;
pub mod path;

pub(crate) use crate::engine::{Check, CheckResult, Status, Table};
pub(crate) use crate::facts::Facts;
pub(crate) use crate::http;
pub(crate) use crate::util::*;
pub(crate) use std::sync::Arc;
pub(crate) use std::time::{Duration, Instant};

pub const SEC_CONNECTION: &str = "Connection & Interface Health";
pub const SEC_PATH: &str = "Gateway, Internet & Path Quality";
pub const SEC_DNS: &str = "DNS Health & Resolution";
pub const SEC_EXPOSURE: &str = "Local Machine Exposure";

fn mk<F, Fut>(id: &'static str, section: &'static str, title: &'static str, secs: u64, facts: &Arc<Facts>, func: F) -> Check
where
    F: FnOnce(Arc<Facts>, CheckResult) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = CheckResult> + Send + 'static,
{
    let f = facts.clone();
    Check { id, section, title, timeout: Duration::from_secs(secs), run: Box::new(move |r| Box::pin(func(f, r))) }
}

/// A fresh set of checks sharing one facts cache.
pub fn all() -> Vec<Check> {
    let f = Facts::new();
    vec![
        mk("link", SEC_CONNECTION, "Active connection", 15, &f, connection::link),
        mk("vpn", SEC_CONNECTION, "VPN, proxy and tunnels", 15, &f, connection::vpn),
        mk("ipv6", SEC_CONNECTION, "IPv6 vs IPv4", 20, &f, connection::ipv6),
        mk("gateway", SEC_PATH, "Router (default gateway)", 20, &f, path::gateway),
        mk("internet", SEC_PATH, "Internet quality", 25, &f, path::internet),
        mk("captive", SEC_PATH, "Captive portal and real internet", 15, &f, path::captive),
        mk("dns-config", SEC_DNS, "DNS servers in use", 15, &f, dns::config),
        mk("dns-speed", SEC_DNS, "DNS lookup speed", 25, &f, dns::speed),
        mk("dns-integrity", SEC_DNS, "DNS interference and filtering", 20, &f, dns::integrity),
        mk("listeners", SEC_EXPOSURE, "Listening services on this computer", 20, &f, listeners::listeners),
    ]
}
