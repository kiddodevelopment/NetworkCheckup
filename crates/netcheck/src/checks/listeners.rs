use super::*;
use crate::platform;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

const CLEARTEXT: &str = "sends logins and data unencrypted; anyone on the same network can read them.";
const DB: &str = "databases and caches usually have weak or no passwords by default and should listen on 127.0.0.1 only.";
const DEV: &str = "looks like a development or app web server. Other devices on this network can open it; bind it to 127.0.0.1 unless you mean to share it.";

/// (name, status when exposed beyond loopback, why)
pub fn known_port(p: u16) -> Option<(&'static str, Status, &'static str)> {
    use Status::*;
    Some(match p {
        21 => ("FTP file transfer", Warn, CLEARTEXT),
        22 => ("SSH remote login", Info, "secure remote login. Fine if you turned it on; otherwise switch off Remote Login."),
        23 => ("Telnet", Bad, CLEARTEXT),
        53 => ("DNS server", Info, "this computer answers DNS queries for others."),
        80 => ("Web server (HTTP)", Warn, "an unencrypted web page other devices can open. If it is an admin page, its password travels in clear text."),
        135 => ("Windows RPC", Info, "standard Windows system service."),
        139 => ("NetBIOS file sharing", Info, "legacy Windows file sharing. Fine at home, best off on public Wi-Fi."),
        445 => ("SMB file sharing", Info, "Windows/Mac file sharing. Normal at home and work; make sure the network is set to Public when on hotel or cafe Wi-Fi."),
        548 => ("AFP file sharing", Info, "older Mac file sharing."),
        631 => ("Printer sharing (IPP)", Info, "shares a printer with the network."),
        3000 | 4200 | 8000 => ("Dev web server", Warn, DEV),
        3283 => ("Apple Remote Desktop", Warn, "remote control of this Mac. Turn it off if you do not use it."),
        3306 => ("MySQL database", Warn, DB),
        3389 => ("Remote Desktop (RDP)", Warn, "remote control of this PC. A frequent attack target; keep it off unless you need it."),
        5000 => ("AirPlay receiver / app server", Info, "on a Mac this is usually AirPlay Receiver; elsewhere often a development server."),
        5040 => ("Windows Connected Devices", Info, "standard Windows service."),
        5173 => ("Dev web server (Vite)", Warn, DEV),
        5355 => ("LLMNR name lookup", Info, "Windows local name lookup."),
        5357 => ("Windows network discovery", Info, "standard Windows service."),
        5432 => ("PostgreSQL database", Warn, DB),
        5900 => ("VNC / Screen Sharing", Warn, "remote screen control. Classic VNC is weakly protected; turn it off if you do not use it."),
        6379 => ("Redis", Warn, DB),
        7000 => ("AirPlay receiver", Info, "lets nearby devices stream to this Mac."),
        7680 => ("Windows Update sharing", Info, "Delivery Optimization shares updates with nearby PCs."),
        8080 => ("Web server (alt HTTP)", Warn, DEV),
        8888 => ("Dev web server / Jupyter", Warn, DEV),
        9200 => ("Elasticsearch", Warn, DB),
        11211 => ("Memcached", Warn, DB),
        27017 => ("MongoDB", Warn, DB),
        _ => return None,
    })
}

fn reach_class(addr: &str) -> (String, bool) {
    let a = addr.split('%').next().unwrap_or("");
    if matches!(a, "0.0.0.0" | "::" | "*" | "") {
        return ("all interfaces (other devices can connect)".into(), true);
    }
    match a.parse::<IpAddr>() {
        Err(_) => (addr.into(), true),
        Ok(ip) if ip.is_loopback() => ("this computer only".into(), false),
        Ok(_) => (format!("network address {a} (devices on that network can connect)"), true),
    }
}

pub async fn listeners(_f: Arc<Facts>, mut r: CheckResult) -> CheckResult {
    let (mut ls, limits) = match platform::listeners().await {
        Ok(x) => x,
        Err(e) => {
            r.limit(format!("Could not list listening sockets: {e}"));
            r.summary = "Listening services could not be read.".into();
            return r;
        }
    };
    for l in limits {
        r.note(l);
    }
    ls.sort_by(|a, b| (a.proto.as_str(), a.port).cmp(&(b.proto.as_str(), b.port)));
    let mut seen = HashSet::new();
    let mut flagged = HashMap::new();
    let mut t = Table::new("Listening sockets", &["Proto", "Port", "Bound to", "Who can reach it", "Process", "Likely service"]);
    let (mut exposed_tcp, mut local_tcp, mut exposed_udp) = (0, 0, 0);
    r.set(Status::Good);
    for l in &ls {
        let (mut label, exposed) = reach_class(&l.addr);
        if !seen.insert((l.proto.clone(), l.port, exposed)) {
            continue;
        }
        if l.proto == "udp" && (l.port >= 49152 || !exposed) {
            continue; // ephemeral or local-only UDP is noise
        }
        if cfg!(windows) && l.proto == "tcp" && (49664..=49700).contains(&l.port) && exposed {
            label += "; Windows system RPC";
        }
        let known = known_port(l.port);
        let proc = if l.pid > 0 { format!("{} (pid {})", or_dash(&l.process), l.pid) } else { l.process.clone() };
        t.row(vec![l.proto.to_uppercase(), l.port.to_string(), l.addr.clone(), label, or_dash(&proc), known.map(|k| k.0).unwrap_or("").to_string()]);
        if l.proto == "tcp" && exposed {
            exposed_tcp += 1;
            if let Some((name, risk, why)) = known {
                if risk != Status::Info && flagged.insert(l.port, true).is_none() {
                    let who = if l.process.is_empty() { String::new() } else { format!(" ({})", l.process) };
                    r.add(risk, format!("{name} open to the network on port {}{who}", l.port), format!("This {why}"));
                }
            }
        } else if l.proto == "tcp" {
            local_tcp += 1;
        } else {
            exposed_udp += 1;
        }
    }
    r.tables.push(t);
    r.summary = format!("{exposed_tcp} TCP service(s) reachable from other devices, {local_tcp} local-only. {exposed_udp} UDP port(s) open to the network.");
    r.detail("Note", "\"Reachable\" means the program accepts outside connections. The OS firewall may still block them; firewall status is planned for a later version.");
    r
}
