//! Shared helpers: commands, timing statistics and probes.

use serde::de::DeserializeOwned;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::process::Command;

/// Runs a command (never needs admin rights) and returns stdout.
pub async fn run(name: &str, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(name);
    cmd.args(args).kill_on_drop(true).stdin(std::process::Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let out = tokio::time::timeout(Duration::from_secs(15), cmd.output())
        .await
        .map_err(|_| format!("{name} took too long"))?
        .map_err(|e| format!("{name}: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() && stdout.trim().is_empty() {
        return Err(format!("{name}: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(stdout)
}

/// Runs a PowerShell snippet ending in ConvertTo-Json and decodes it into a Vec.
/// A single object is wrapped into a one-element array.
#[allow(dead_code)]
pub async fn ps_json<T: DeserializeOwned>(script: &str) -> Result<Vec<T>, String> {
    let full = format!("$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; {script}");
    let out = run("powershell.exe", &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &full]).await?;
    let t = out.trim();
    if t.is_empty() {
        return Ok(vec![]);
    }
    let t = if t.starts_with('{') { format!("[{t}]") } else { t.to_string() };
    serde_json::from_str(&t).map_err(|e| format!("could not read PowerShell output: {e}"))
}

/// A cheap random number (DNS ids, random labels); not for cryptography.
pub fn rand_u64() -> u64 {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let mut h = RandomState::new().build_hasher();
    h.write_u64(CTR.fetch_add(1, Ordering::Relaxed));
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
    h.finish()
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub sent: u32,
    pub received: u32,
    pub rtts: Vec<Duration>,
    pub method: String,
}

pub fn ms(d: Duration) -> f64 {
    d.as_micros() as f64 / 1000.0
}

impl Stats {
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 { 0.0 } else { 100.0 * (self.sent - self.received) as f64 / self.sent as f64 }
    }
    pub fn min(&self) -> f64 {
        self.rtts.iter().min().map(|d| ms(*d)).unwrap_or(0.0)
    }
    pub fn max(&self) -> f64 {
        self.rtts.iter().max().map(|d| ms(*d)).unwrap_or(0.0)
    }
    pub fn avg(&self) -> f64 {
        if self.rtts.is_empty() { 0.0 } else { self.rtts.iter().map(|d| ms(*d)).sum::<f64>() / self.rtts.len() as f64 }
    }
    /// Mean absolute difference between consecutive samples.
    pub fn jitter(&self) -> f64 {
        if self.rtts.len() < 2 {
            return 0.0;
        }
        let s: f64 = self.rtts.windows(2).map(|w| (ms(w[1]) - ms(w[0])).abs()).sum();
        s / (self.rtts.len() - 1) as f64
    }
}

pub fn median(ds: &[Duration]) -> f64 {
    if ds.is_empty() {
        return 0.0;
    }
    let mut c = ds.to_vec();
    c.sort();
    ms(c[c.len() / 2])
}

pub fn max_d(ds: &[Duration]) -> f64 {
    ds.iter().max().map(|d| ms(*d)).unwrap_or(0.0)
}

pub fn f1(v: f64) -> String {
    format!("{v:.1}")
}

pub fn or_dash(s: &str) -> String {
    if s.is_empty() { "none".into() } else { s.into() }
}

pub fn is_refused(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::ConnectionRefused
}

pub fn short_err(e: &str) -> String {
    let l = e.to_lowercase();
    if l.contains("timed out") || l.contains("timeout") || l.contains("deadline") {
        return "timed out".into();
    }
    if l.contains("refused") {
        return "refused".into();
    }
    if l.contains("no such host") || l.contains("failed to lookup") || l.contains("not known") || l.contains("no address") || l.contains("name or service") || l.contains("nodename") {
        return "name not found".into();
    }
    if l.contains("unreachable") {
        return "unreachable".into();
    }
    let s: String = e.chars().take(60).collect();
    s
}

/// One TCP connect with a timeout. Ok(true) = connected, Ok(false) = refused (host answered).
pub async fn tcp_connect(addr: SocketAddr, timeout: Duration) -> Result<bool, String> {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Err(_) => Err("timed out".into()),
        Ok(Ok(_)) => Ok(true),
        Ok(Err(e)) if is_refused(&e) => Ok(false),
        Ok(Err(e)) => Err(e.to_string()),
    }
}

/// Measures TCP connect time; a refused connection still proves the host answered.
pub async fn tcp_probe(ip: IpAddr, ports: &[u16], count: u32, gap: Duration) -> Stats {
    let mut st = Stats { method: "TCP connect".into(), ..Default::default() };
    let mut port = None;
    for p in ports {
        if tcp_connect(SocketAddr::new(ip, *p), Duration::from_millis(800)).await.is_ok() {
            port = Some(*p);
            break;
        }
    }
    let Some(port) = port else {
        st.sent = count;
        return st;
    };
    st.method = format!("TCP connect to port {port}");
    for _ in 0..count {
        st.sent += 1;
        let t0 = Instant::now();
        if tcp_connect(SocketAddr::new(ip, port), Duration::from_millis(1500)).await.is_ok() {
            st.received += 1;
            st.rtts.push(t0.elapsed());
        }
        tokio::time::sleep(gap).await;
    }
    st
}

/// Pings with ICMP when the OS allows it without admin, else falls back to TCP.
pub async fn probe(ip: IpAddr, count: u32, gap: Duration, tcp_ports: &[u16]) -> Stats {
    match crate::icmp::ping(ip, count, gap).await {
        Ok(st) if st.received > 0 => st,
        Ok(st) => {
            let t = tcp_probe(ip, tcp_ports, count, gap).await;
            if t.received > 0 { t } else { st }
        }
        Err(_) => tcp_probe(ip, tcp_ports, count, gap).await,
    }
}

pub fn uniq(v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    v.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => a.is_loopback() || (a.segments()[0] & 0xffc0) == 0xfe80 || (a.segments()[0] & 0xfe00) == 0xfc00,
    }
}
