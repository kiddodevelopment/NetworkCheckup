# Network Checkup

A desktop app for Windows and macOS that explains, in plain English, what is wrong (or right) with the network you are on. Built with [Tauri v2](https://tauri.app); every check is written in Rust and runs without admin rights.

## What it checks

- **Connection:** active interface, addresses, gateway, MAC/MTU, VPNs (full or split tunnel), proxies, IPv6 vs IPv4.
- **Path quality:** router and internet latency, loss and jitter, captive portal detection.
- **DNS:** configured servers, split DNS, lookup speed, made-up-name rewriting, filtering, interception, agreement with public DNS.
- **This computer:** listening services and whether other devices can reach them.
- **Local network (opt-in):** devices found through the neighbor table, a gentle ping sweep, mDNS/Bonjour, SSDP/UPnP, reverse DNS and NetBIOS; maker from the MAC address; a short list of common services per device. At most 50 new connections per second, 4 per device, no logins, no password guessing.

Results can be copied or saved as a Markdown report.

## Layout

| Path | What it is |
| --- | --- |
| `crates/netcheck` | All checks, the report and a `netcheck-cli` terminal tool |
| `src-tauri` | The desktop shell: window, commands, icons, bundle settings |
| `ui/index.html` | The window's page (plain HTML/JS, no bundler) |
| `icon-source` | Original icon artwork |

## Build

Needs Rust, Node.js and, on Windows, the Visual Studio C++ build tools.

```powershell
# Windows
./build-windows.ps1
```

```sh
# macOS or Windows
npm ci
npx tauri build
```

The terminal version: `cargo run -p netcheck --bin netcheck-cli -- --md report.md` (add `--lan` to include the network scan).

GitHub Actions builds the Windows exe and installers and a universal macOS app on every push; download them from the run's **Artifacts**.

The macOS app is ad-hoc signed, not notarized: the first time, right-click it and choose **Open**.
