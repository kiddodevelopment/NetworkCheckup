//! Tauri shell: the window calls these commands; all checks live in the netcheck crate.

use netcheck::checks::{self, lan::SEC_LAN};
use netcheck::engine::{self, Snapshot};
use netcheck::{report, VERSION};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_dialog::DialogExt;

#[derive(Default)]
struct AppState {
    last: Mutex<Option<Snapshot>>,
}

/// One run plus its Markdown report.
#[derive(Serialize)]
struct Payload {
    #[serde(flatten)]
    snapshot: Snapshot,
    markdown: String,
}

impl From<Snapshot> for Payload {
    fn from(s: Snapshot) -> Self {
        let markdown = report::markdown(&s);
        Payload { snapshot: s, markdown }
    }
}

#[tauri::command]
fn version() -> String {
    VERSION.to_string()
}

/// A full checkup (about 20 seconds). LAN results from an earlier scan are dropped
/// because they describe an older moment.
#[tauri::command]
async fn run_checkup(state: State<'_, AppState>) -> Result<Payload, String> {
    let s = engine::run_all(checks::all(), VERSION).await;
    *state.last.lock().unwrap() = Some(s.clone());
    Ok(s.into())
}

/// The opt-in local network scan, merged into the current results.
#[tauri::command]
async fn scan_lan(app: AppHandle, state: State<'_, AppState>) -> Result<Payload, String> {
    let base = state.last.lock().unwrap().clone().ok_or("Run a checkup first.")?;
    let progress = Arc::new(move |m: String| {
        let _ = app.emit("lan-progress", m);
    });
    let lan = engine::run_all(checks::lan::checks(progress), VERSION).await;
    let mut merged = base;
    merged.results.retain(|r| r.section != SEC_LAN);
    merged.results.extend(lan.results);
    merged.overall = engine::overall_of(&merged.results);
    merged.finished = chrono::Local::now().to_rfc3339();
    *state.last.lock().unwrap() = Some(merged.clone());
    Ok(merged.into())
}

/// Asks where to save the Markdown report and writes it. Returns the path, or "" if cancelled.
#[tauri::command]
async fn save_report(app: AppHandle, markdown: String) -> Result<String, String> {
    if markdown.is_empty() {
        return Err("Run a checkup first.".into());
    }
    let name = format!("network-checkup-{}.md", chrono::Local::now().format("%Y-%m-%d-%H%M"));
    let Some(path) = app.dialog().file().set_file_name(name).add_filter("Markdown", &["md"]).blocking_save_file() else {
        return Ok(String::new());
    };
    let path = path.into_path().map_err(|e| e.to_string())?;
    std::fs::write(&path, markdown).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![version, run_checkup, scan_lan, save_report])
        .run(tauri::generate_context!())
        .expect("error while running Network Checkup");
}
