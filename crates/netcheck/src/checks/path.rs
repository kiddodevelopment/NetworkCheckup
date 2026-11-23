use super::*;
use std::net::IpAddr;

fn stats_details(r: &mut CheckResult, label: &str, s: &Stats) {
    r.detail(format!("{label} method"), s.method.clone());
    r.detail(format!("{label} sent / received"), format!("{} / {} ({:.0}% loss)", s.sent, s.received, s.loss_pct()));
    if s.received > 0 {
        r.detail(format!("{label} min / avg / max"), format!("{} / {} / {} ms", f1(s.min()), f1(s.avg()), f1(s.max())));
        r.detail(format!("{label} jitter"), format!("{} ms", f1(s.jitter())));
    }
}

pub async fn gateway(f: Arc<Facts>, mut r: CheckResult) -> CheckResult {
    let l = f.load().await;
    if l.gateway4.is_empty() {
        r.summary = "No IPv4 router found to test.".into();
        r.add(Status::Bad, "No gateway", "Without a default gateway nothing outside this computer is reachable.");
        return r;
    }
    let s = f.gateway().await;
    r.detail("Gateway", l.gateway4.clone());
    stats_details(&mut r, "Probe", &s);
    let wifi = l.primary_kind() == "Wi-Fi";
    let place = if wifi { "the Wi-Fi link (distance, walls, interference, or a busy channel)" } else { "the link between this computer and the router" };
    if s.received == 0 {
        r.summary = "The router did not answer.".into();
        if s.method == "ICMP echo" {
            r.add(Status::Warn, "Router ignores probes", "The router did not answer ping or common ports. Some routers do this by design, so check the internet card: if that is fine, this is harmless.");
        } else {
            r.add(Status::Bad, "Router unreachable", format!("Nothing came back from the router. If the internet card also fails, the problem is {place} or the router itself."));
        }
        return r;
    }
    r.set(Status::Good);
    r.summary = format!("Router answers in {} ms on average, {} ms jitter, {:.0}% loss.", f1(s.avg()), f1(s.jitter()), s.loss_pct());
    let loss = s.loss_pct();
    if loss >= 5.0 {
        r.add(Status::Bad, "Packet loss to the router", format!("{loss:.0}% of probes to your own router were lost. Loss this close to home points at {place}, not your internet provider."));
    } else if loss > 0.0 {
        r.add(Status::Warn, "Some packet loss to the router", format!("{loss:.0}% of probes were lost before even leaving your home network. Worth watching if calls stutter."));
    }
    if s.avg() > 100.0 {
        r.add(Status::Bad, "Very slow response from the router", "A healthy router answers in a few milliseconds. Over 100 ms usually means a weak Wi-Fi signal or an overloaded router.");
    } else if s.avg() > 20.0 {
        r.add(Status::Warn, "Slow response from the router", "Answers from the router should take under about 10 ms. A slow local link adds delay to everything you do online.");
    }
    if s.jitter() > 15.0 {
        r.add(Status::Warn, "Unsteady link to the router", "Response times swing a lot, which makes video calls choppy. Common on congested or weak Wi-Fi.");
    }
    r
}

const INTERNET_TARGETS: &[(&str, &str)] = &[("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google"), ("9.9.9.9", "Quad9")];

pub async fn internet(f: Arc<Facts>, mut r: CheckResult) -> CheckResult {
    let jobs = INTERNET_TARGETS.iter().map(|(ip, _)| probe(ip.parse::<IpAddr>().unwrap(), 15, Duration::from_millis(200), &[443, 53]));
    let (results, gw) = tokio::join!(futures::future::join_all(jobs), f.gateway());
    let mut t = Table::new("Probe results", &["Target", "Method", "Sent", "Lost %", "Min ms", "Avg ms", "Max ms", "Jitter ms"]);
    let (mut sent, mut recv) = (0u32, 0u32);
    let mut best = Stats::default();
    for (i, s) in results.iter().enumerate() {
        let (ip, name) = INTERNET_TARGETS[i];
        t.row(vec![format!("{name} {ip}"), s.method.clone(), s.sent.to_string(), format!("{:.0}", s.loss_pct()), f1(s.min()), f1(s.avg()), f1(s.max()), f1(s.jitter())]);
        sent += s.sent;
        recv += s.received;
        if s.received > best.received || (s.received == best.received && s.received > 0 && s.avg() < best.avg()) {
            best = s.clone();
        }
    }
    r.tables.push(t);
    if recv == 0 {
        r.summary = "No reply from any internet test server.".into();
        r.add(Status::Bad, "Internet unreachable", "None of three major public servers answered. If the router card is green, the problem is past your router: the modem, the provider, or a VPN/firewall blocking traffic.");
        return r;
    }
    let loss = 100.0 * (sent - recv) as f64 / sent as f64;
    r.set(Status::Good);
    r.summary = format!("Internet round trip {} ms, {} ms jitter, {loss:.1}% loss.", f1(best.avg()), f1(best.jitter()));
    let blame = if gw.received > 0 && gw.loss_pct() > 0.0 {
        "Your router link also loses packets, so fix the local network (Wi-Fi) first."
    } else {
        "Your router link looks fine, so this is most likely your internet provider or beyond."
    };
    if loss >= 5.0 {
        r.add(Status::Bad, "Heavy packet loss", format!("{loss:.1}% of packets to the internet were lost. Expect frozen video calls and stalled downloads. {blame}"));
    } else if loss > 1.0 {
        r.add(Status::Warn, "Some packet loss", format!("{loss:.1}% loss is enough to make calls choppy. {blame}"));
    }
    if best.avg() > 250.0 {
        r.add(Status::Bad, "Very high latency", "Over 250 ms round trip makes calls and remote desktops laggy. Satellite links, distant VPN servers, or a saturated connection cause this.");
    } else if best.avg() > 100.0 {
        r.add(Status::Warn, "High latency", "Over 100 ms to major servers is higher than a typical wired home connection (10 to 40 ms).");
    }
    if best.jitter() > 30.0 {
        r.add(Status::Warn, "High jitter", "Delay swings a lot from moment to moment. That makes voice and video choppy even when speed tests look fine; often caused by someone else using the full bandwidth.");
    }
    if best.avg() < 1.0 {
        r.add(Status::Warn, "Answers came back impossibly fast", "Public internet servers replied in under 1 ms, faster than a real round trip allows. Something nearby (a firewall, proxy, VPN client, or security software) is answering on their behalf, so these numbers do not reflect your real internet path.");
    }
    if gw.received > 0 {
        r.detail("Router share of delay", format!("{} of {} ms", f1(gw.avg()), f1(best.avg())));
        if best.avg() > 60.0 && gw.avg() > 0.5 * best.avg() {
            r.add(Status::Warn, "Most delay is inside your home", "More than half the round trip is spent reaching your own router, which points at Wi-Fi rather than the provider.");
        }
    }
    r
}

const CAPTIVE: &[(&str, &str, u16, &str)] = &[
    ("Apple", "http://captive.apple.com/hotspot-detect.html", 200, "Success"),
    ("Microsoft", "http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test"),
    ("Google", "http://connectivitycheck.gstatic.com/generate_204", 204, ""),
];

pub async fn captive(_f: Arc<Facts>, mut r: CheckResult) -> CheckResult {
    let jobs = CAPTIVE.iter().map(|(_, url, _, _)| http::get(url, Duration::from_secs(6)));
    let res = futures::future::join_all(jobs).await;
    let mut t = Table::new("Connectivity probes (plain HTTP, no proxy)", &["Probe", "URL", "Status", "Verdict"]);
    let (mut ok, mut redir, mut failed, mut odd) = (0, 0, 0, 0);
    let mut loc = String::new();
    for (i, o) in res.iter().enumerate() {
        let (name, url, code, body) = CAPTIVE[i];
        let (status, verdict) = match o {
            Err(e) => {
                failed += 1;
                ("-".to_string(), short_err(e))
            }
            Ok(resp) if (300..400).contains(&resp.status) => {
                redir += 1;
                loc = resp.header("location");
                (resp.status.to_string(), format!("redirected to {loc}"))
            }
            Ok(resp) if resp.status != code || (!body.is_empty() && !resp.text().contains(body)) => {
                odd += 1;
                (resp.status.to_string(), "unexpected content".into())
            }
            Ok(resp) => {
                ok += 1;
                (resp.status.to_string(), "expected answer".into())
            }
        };
        t.row(vec![name.to_string(), url.to_string(), status, verdict]);
    }
    r.tables.push(t);
    if ok == res.len() {
        r.set(Status::Good);
        r.summary = "Real, open internet: test pages came back untouched.".into();
    } else if redir > 0 {
        r.summary = "A login or terms page is intercepting traffic.".into();
        r.add(Status::Bad, "Captive portal detected", format!("This network redirects web requests to {loc}. Open a browser and visit any http:// site to finish the hotel/guest Wi-Fi sign-in. A VPN that starts before sign-in can hide this page."));
    } else if odd > 0 {
        r.summary = "Web responses are being altered.".into();
        r.add(Status::Warn, "Unexpected responses", "Test pages came back with different content. A portal, content filter, or security appliance may be rewriting traffic.");
    } else if failed == res.len() {
        r.summary = "Plain web requests fail.".into();
        r.add(Status::Bad, "No direct web access", "None of the connectivity test pages loaded. Either the internet is down, or this network only allows traffic through a proxy.");
    } else {
        r.summary = "Some test pages failed to load.".into();
        r.add(Status::Warn, "Partial web access", "Some connectivity checks failed. A firewall or filter may be blocking certain sites.");
    }
    r
}
