//! Network Checkup engine: plain-English network diagnostics for Windows and macOS.

pub mod engine;
pub mod util;
pub mod icmp;
pub mod dnsmsg;
pub mod http;
pub mod platform;
pub mod facts;
pub mod checks;
pub mod report;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
