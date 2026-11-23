//! Check model and the parallel runner.

use serde::Serialize;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    #[default]
    Good,
    Warn,
    Bad,
    Info,
    Limited,
}

impl Status {
    /// Lower is worse.
    pub fn rank(self) -> u8 {
        match self {
            Status::Bad => 0,
            Status::Warn => 1,
            Status::Limited => 2,
            Status::Info => 3,
            Status::Good => 4,
        }
    }
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Table {
    pub title: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(title: &str, cols: &[&str]) -> Self {
        Table { title: title.into(), columns: cols.iter().map(|s| s.to_string()).collect(), rows: vec![] }
    }
    pub fn row<S: Into<String>>(&mut self, cells: Vec<S>) {
        self.rows.push(cells.into_iter().map(Into::into).collect());
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Kv {
    pub key: String,
    pub value: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Finding {
    pub status: Status,
    pub title: String,
    pub explain: String,
}

#[derive(Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub id: String,
    pub section: String,
    pub title: String,
    pub status: Status,
    #[serde(skip)]
    pub status_set: bool,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub details: Vec<Kv>,
    pub tables: Vec<Table>,
    pub limits: Vec<String>,
    pub duration_ms: u64,
}

impl CheckResult {
    /// Lowers the card to `s` if it is worse than the current status.
    pub fn raise(&mut self, s: Status) {
        if !self.status_set || s.rank() < self.status.rank() {
            self.status = s;
            self.status_set = true;
        }
    }
    pub fn set(&mut self, s: Status) {
        self.status = s;
        self.status_set = true;
    }
    pub fn add(&mut self, s: Status, title: impl Into<String>, explain: impl Into<String>) {
        self.findings.push(Finding { status: s, title: title.into(), explain: explain.into() });
        self.raise(s);
    }
    pub fn detail(&mut self, k: impl Into<String>, v: impl Into<String>) {
        self.details.push(Kv { key: k.into(), value: v.into() });
    }
    /// Records a permission/platform limit and marks the card Limited if it was fine.
    pub fn limit(&mut self, msg: impl Into<String>) {
        self.limits.push(msg.into());
        if !self.status_set || matches!(self.status, Status::Good | Status::Info) {
            self.set(Status::Limited);
        }
    }
    /// A limit note that does not change the status.
    pub fn note(&mut self, msg: impl Into<String>) {
        self.limits.push(msg.into());
    }
}

pub type CheckFuture = Pin<Box<dyn Future<Output = CheckResult> + Send>>;

pub struct Check {
    pub id: &'static str,
    pub section: &'static str,
    pub title: &'static str,
    pub timeout: Duration,
    pub run: Box<dyn FnOnce(CheckResult) -> CheckFuture + Send>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Snapshot {
    pub started: String,
    pub finished: String,
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub version: String,
    pub overall: Status,
    pub results: Vec<CheckResult>,
}

/// Worst red/amber status across results (green otherwise).
pub fn overall_of(results: &[CheckResult]) -> Status {
    let mut o = Status::Good;
    for r in results {
        if matches!(r.status, Status::Bad | Status::Warn) && r.status.rank() < o.rank() {
            o = r.status;
        }
    }
    o
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
        .or_else(|| {
            std::process::Command::new("hostname").output().ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|| "this computer".into())
}

pub fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        o => o,
    }
}

/// Runs every check concurrently, each with its own timeout, keeping declaration order.
pub async fn run_all(checks: Vec<Check>, version: &str) -> Snapshot {
    let started = chrono::Local::now();
    let mut handles = vec![];
    for c in checks {
        let base = CheckResult { id: c.id.into(), section: c.section.into(), title: c.title.into(), ..Default::default() };
        let timeout = c.timeout;
        let fut = (c.run)(base.clone());
        handles.push(tokio::spawn(async move {
            let t0 = Instant::now();
            let mut r = match tokio::time::timeout(timeout, fut).await {
                Ok(r) => r,
                Err(_) => {
                    let mut r = base;
                    r.summary = "This check took too long and was stopped.".into();
                    r.limit(format!("Timed out after {} seconds.", timeout.as_secs()));
                    r
                }
            };
            if !r.status_set {
                r.set(Status::Good);
            }
            r.duration_ms = t0.elapsed().as_millis() as u64;
            r
        }));
    }
    let mut results = vec![];
    for h in handles {
        match h.await {
            Ok(r) => results.push(r),
            Err(_) => {
                let mut r = CheckResult { title: "Check".into(), ..Default::default() };
                r.add(Status::Limited, "Check crashed", "This check hit an internal error and was skipped.");
                results.push(r);
            }
        }
    }
    Snapshot {
        started: started.to_rfc3339(),
        finished: chrono::Local::now().to_rfc3339(),
        os: os_name().into(),
        arch: std::env::consts::ARCH.into(),
        hostname: hostname(),
        version: version.into(),
        overall: overall_of(&results),
        results,
    }
}

/// Helper to box a check body.
#[macro_export]
macro_rules! check {
    ($id:expr, $sec:expr, $title:expr, $secs:expr, $f:expr) => {
        $crate::engine::Check {
            id: $id,
            section: $sec,
            title: $title,
            timeout: std::time::Duration::from_secs($secs),
            run: Box::new(move |r| Box::pin($f(r))),
        }
    };
}
