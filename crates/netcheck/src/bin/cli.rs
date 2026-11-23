//! netcheck-cli runs Network Checkup in a terminal (handy for techs and scripts).

use netcheck::{checks, engine, report, VERSION};

fn usage() -> ! {
    eprintln!("usage: netcheck-cli [--md FILE] [--json FILE] [--lan]\n  --md FILE    write the Markdown report to FILE instead of printing it\n  --json FILE  also write raw JSON results to FILE\n  --lan        also scan the local network (only on networks you own or manage)");
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    let (mut md_path, mut json_path, mut lan) = (None, None, false);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.trim_start_matches('-') {
            "md" => md_path = Some(args.next().unwrap_or_else(|| usage())),
            "json" => json_path = Some(args.next().unwrap_or_else(|| usage())),
            "lan" => lan = true,
            _ => usage(),
        }
    }
    eprintln!("Running Network Checkup (about 20 seconds)...");
    let mut list = checks::all();
    if lan {
        list.extend(checks::lan::checks(std::sync::Arc::new(|m: String| eprintln!("{m}"))));
    }
    let snap = engine::run_all(list, VERSION).await;
    let md = report::markdown(&snap);
    if let Some(p) = json_path {
        std::fs::write(&p, serde_json::to_string_pretty(&snap).unwrap()).unwrap_or_else(|e| panic!("writing {p}: {e}"));
    }
    match md_path {
        Some(p) => {
            std::fs::write(&p, md).unwrap_or_else(|e| panic!("writing {p}: {e}"));
            eprintln!("Wrote {p}");
        }
        None => print!("{md}"),
    }
}
