//! A tiny HTTP/1.1 GET client: no redirects, no proxy, size-limited, with an
//! optional TLS mode that accepts any certificate so it can describe it.

use std::net::SocketAddr;
#[cfg(feature = "tls")]
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Default, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub cert: Option<CertInfo>,
}

#[derive(Debug, Default, Clone)]
pub struct CertInfo {
    pub subject_cn: String,
    pub self_signed: bool,
    pub expired: bool,
}

impl Response {
    pub fn header(&self, name: &str) -> String {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()).unwrap_or_default()
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

#[cfg(feature = "tls")]
#[derive(Debug)]
struct AcceptAll(Arc<rustls::crypto::CryptoProvider>);

#[cfg(feature = "tls")]
impl rustls::client::danger::ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(feature = "tls")]
fn tls_config() -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll(provider)))
        .with_no_client_auth();
    Arc::new(cfg)
}

#[cfg(feature = "tls")]
fn cert_info(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert.subject().iter_common_name().next().and_then(|c| c.as_str().ok()).unwrap_or("").to_string();
    Some(CertInfo {
        subject_cn: cn,
        self_signed: cert.subject().as_raw() == cert.issuer().as_raw(),
        expired: !cert.validity().is_valid(),
    })
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, host: &str, path: &str) -> Result<Response, String> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetworkCheckup/0.4 (read-only check)\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(_) if !buf.is_empty() => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or("malformed response")?;
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let mut lines = head.lines();
    let status = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|c| c.parse().ok()).ok_or("bad status line")?;
    let headers = lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect();
    Ok(Response { status, headers, body: buf[split + 4..].to_vec(), cert: None })
}

/// GET http(s)://host[:port]/path. `connect_to` overrides DNS (used for LAN IPs).
pub async fn get(url: &str, timeout: Duration) -> Result<Response, String> {
    tokio::time::timeout(timeout, get_inner(url)).await.map_err(|_| "timed out".to_string())?
}

async fn get_inner(url: &str) -> Result<Response, String> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("unsupported url".into());
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || h.ends_with(']') => (h.trim_matches(|c| c == '[' || c == ']'), p.parse::<u16>().map_err(|_| "bad port")?),
        _ => (hostport.trim_matches(|c| c == '[' || c == ']'), if tls { 443 } else { 80 }),
    };
    let addr: SocketAddr = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => tokio::net::lookup_host((host, port)).await.map_err(|e| e.to_string())?.next().ok_or("name not found")?,
    };
    let mut tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    if !tls {
        return exchange(&mut tcp, hostport, path).await;
    }
    #[cfg(not(feature = "tls"))]
    {
        let _ = tcp;
        return Err("HTTPS support not built in".into());
    }
    #[cfg(feature = "tls")]
    {
    let connector = tokio_rustls::TlsConnector::from(tls_config());
    let sni = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let mut s = connector.connect(sni, tcp).await.map_err(|e| e.to_string())?;
    let cert = s.get_ref().1.peer_certificates().and_then(|c| c.first()).and_then(|c| cert_info(c.as_ref()));
    let mut r = exchange(&mut s, hostport, path).await.unwrap_or_default();
    r.cert = cert;
    Ok(r)
    }
}
