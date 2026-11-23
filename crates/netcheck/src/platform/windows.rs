use super::*;
use crate::util::ps_json;
use serde::Deserialize;

pub async fn iface_meta() -> HashMap<String, IfaceMeta> {
    // netdev already knows Windows adapter types; nothing extra to read.
    HashMap::new()
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DnsRow {
    interface_alias: Option<String>,
    server_addresses: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NrptRow {
    namespace: Option<serde_json::Value>,
    name_servers: Option<serde_json::Value>,
}

fn strings(v: &Option<serde_json::Value>) -> Vec<String> {
    match v {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => vec![],
    }
}

pub async fn dns_servers() -> Result<(Vec<DnsServer>, Vec<String>), String> {
    let rows: Vec<DnsRow> = ps_json("Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress -Depth 3").await?;
    let mut res = vec![];
    for r in rows {
        let alias = r.interface_alias.unwrap_or_default();
        if alias.to_lowercase().starts_with("loopback") {
            continue;
        }
        for s in r.server_addresses.unwrap_or_default() {
            res.push(DnsServer { addr: s, iface: alias.clone(), domain: String::new() });
        }
    }
    if let Ok(nrpt) = ps_json::<NrptRow>("Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | Select-Object Namespace,NameServers | ConvertTo-Json -Compress -Depth 3").await {
        for n in nrpt {
            let ns = strings(&n.namespace).join(",");
            for s in strings(&n.name_servers) {
                res.push(DnsServer { addr: s, iface: "NRPT policy".into(), domain: ns.clone() });
            }
        }
    }
    Ok((res, vec![]))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProxyRow {
    proxy_enable: Option<i64>,
    proxy_server: Option<String>,
    #[serde(rename = "AutoConfigURL")]
    auto_config_url: Option<String>,
}

pub async fn proxy_settings() -> Result<Vec<ProxySetting>, String> {
    let rows: Vec<ProxyRow> = ps_json(r"Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL | ConvertTo-Json -Compress").await?;
    let mut ps = vec![];
    for r in rows {
        let server = r.proxy_server.unwrap_or_default();
        if r.proxy_enable == Some(1) && !server.is_empty() {
            ps.push(ProxySetting { source: "Windows (user)".into(), kind: "Manual proxy".into(), value: server });
        }
        if let Some(u) = r.auto_config_url.filter(|u| !u.is_empty()) {
            ps.push(ProxySetting { source: "Windows (user)".into(), kind: "Auto-config (PAC) script".into(), value: u });
        }
    }
    Ok(ps)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NameRow {
    name: Option<String>,
}

pub async fn vpn_services() -> Result<Vec<String>, String> {
    let rows: Vec<NameRow> = ps_json("Get-VpnConnection -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionStatus -eq 'Connected' } | Select-Object Name | ConvertTo-Json -Compress").await?;
    Ok(rows.into_iter().filter_map(|r| r.name).collect())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SockRow {
    proto: String,
    addr: String,
    port: u16,
    #[serde(rename = "PID")]
    pid: Option<u32>,
    process: Option<String>,
}

pub async fn listeners() -> Result<(Vec<Listener>, Vec<String>), String> {
    let script = r#"$p=@{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $p[[int]$_.Id]=$_.ProcessName };
$t=Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{Proto='tcp';Addr=$_.LocalAddress;Port=[int]$_.LocalPort;PID=[int]$_.OwningProcess;Process=$p[[int]$_.OwningProcess]} };
$u=Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{Proto='udp';Addr=$_.LocalAddress;Port=[int]$_.LocalPort;PID=[int]$_.OwningProcess;Process=$p[[int]$_.OwningProcess]} };
@($t)+@($u) | ConvertTo-Json -Compress"#;
    let rows: Vec<SockRow> = ps_json(script).await.map_err(|e| format!("listing sockets: {e}"))?;
    let mut missing = false;
    let ls = rows
        .into_iter()
        .map(|r| {
            let process = r.process.unwrap_or_default();
            missing |= process.is_empty();
            Listener { proto: r.proto, addr: r.addr, port: r.port, pid: r.pid.unwrap_or(0), process }
        })
        .collect();
    let limits = if missing { vec!["Some process names are hidden from standard (non-admin) accounts.".to_string()] } else { vec![] };
    Ok((ls, limits))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NeighRow {
    #[serde(rename = "IPAddress")]
    ip_address: String,
    link_layer_address: Option<String>,
    state: i64,
}

pub async fn neighbor_table() -> Result<Neighbors, String> {
    // State: 0 Unreachable, 1 Incomplete, 2 Probe, 3 Delay, 4 Stale, 5 Reachable, 6 Permanent
    let rows: Vec<NeighRow> = ps_json("Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress,LinkLayerAddress,@{n='State';e={[int]$_.State}} | ConvertTo-Json -Compress").await?;
    let mut m = Neighbors::new();
    for r in rows {
        if r.state <= 1 {
            continue;
        }
        if let Some(mac) = r.link_layer_address.as_deref().and_then(norm_mac) {
            m.insert(r.ip_address, mac);
        }
    }
    Ok(m)
}
