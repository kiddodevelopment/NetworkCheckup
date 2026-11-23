# Network Checkup

Plain-English network diagnostics for Windows and macOS, as a native desktop app. No admin rights needed.

The app is built with [Wails](https://wails.io): the Go check engine runs inside the app, and the window uses the system web view (WebView2 on Windows, WebKit on macOS). Nothing opens in your browser and nothing listens on the network.

## Build on Windows

One-time setup:

1. Install **Go 1.23 or newer** from https://go.dev/dl/ (the Windows `.msi`). Accept the defaults.
2. Open a **new** PowerShell window so it picks up Go.

Every build:

```powershell
cd path\to\network-checkup
powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
```

The first run downloads the Go libraries (a few minutes). The app lands at `build\bin\NetworkCheckup.exe`, with the icon, version info and high-DPI manifest built in (from the `rsrc_windows_*.syso` files). A terminal version, `build\bin\netcheckup-cli.exe`, is built next to it.

Only Go is needed: no Node.js, no Visual Studio, no Wails command-line tool. The user interface is a single HTML file in `frontend/dist/`.

To change the icon, replace `build/windows/icon.ico`, then run `go run ./tools/winres 0.3.0` (with the new version number) and build again.

The app needs Microsoft Edge WebView2, which is already on Windows 10 (21H2+) and Windows 11.

## Build for macOS

Mac apps can only be compiled on a Mac. Two options:

- **GitHub Actions (no Mac needed):** push this folder to a GitHub repository. `.github/workflows/build.yml` builds a universal Mac app (Intel + Apple silicon) and a Windows app on every push to `main`. Download them from the run's *Artifacts* section.
- **On a Mac:** install Xcode command line tools (`xcode-select --install`) and Go, then:

  ```sh
  go install github.com/wailsapp/wails/v2/cmd/wails@v2.10.1
  ~/go/bin/wails build -skipbindings -platform darwin/universal
  ```

The Mac build is not notarized yet. The first time you open it, right-click the app and choose **Open**. On macOS 15, go to *System Settings > Privacy & Security* and click **Open Anyway** instead.

## Terminal version

```
netcheckup-cli                 # print the Markdown report
netcheckup-cli -md report.md   # save the report
netcheckup-cli -json raw.json  # also save raw results
netcheckup-cli -lan            # include the local network scan
```

## What it checks (v0.3)

| Section | Cards |
| --- | --- |
| Connection and interface | Active interface, addresses, gateway, MTU, link speed. VPN, tunnel and proxy detection, with a reachability test for the proxy. IPv6 vs IPv4 connection times. |
| Gateway, internet and path | Router latency, loss and jitter (20 probes). Internet latency, loss and jitter to Cloudflare, Google and Quad9. Captive portal and "real internet" check. |
| DNS | Configured and split DNS servers, plus which upstream resolver is actually used. Lookup speed for each server compared with a reference. Made-up-name rewriting, ad filtering, DNS interception and answer agreement. |
| Local exposure | Listening TCP and UDP sockets, split into "this computer only" and "other devices can connect". Plain-English warnings for remote-control, database, dev-server and cleartext services. |

| Local network (opt-in) | Click **Scan my network**. Lists devices from the neighbor (ARP) table, one ping per address, mDNS/Bonjour, SSDP/UPnP, reverse DNS and NetBIOS names, with the maker from the MAC address and a plain-English type (router, printer, TV, camera, phone...). Flags unidentified devices, then checks about 20 common ports on each device and warns about Telnet, FTP, admin pages without HTTPS, open Remote Desktop/VNC and router UPnP. |

Safety: the network scan only runs when you click it, only on private networks up to 1,024 addresses, at most 50 new connections per second and 4 per device. It reads at most one banner or one web page per service and never tries a login or password. Nothing is uploaded.

MAC vendor names come from the IEEE OUI registry (via the nmap-mac-prefixes list) in `checks/oui.txt.gz`.

## Project layout

| Path | What it is |
| --- | --- |
| `main.go`, `app.go` | Desktop app window and the functions the UI calls |
| `frontend/dist/index.html` | The whole user interface |
| `engine/` | Runs checks in parallel and scores them |
| `checks/` | Every check, plus the Windows, macOS and Linux code that reads system settings |
| `report/` | Markdown report |
| `cmd/netcheckup-cli/` | Terminal version |
| `build/appicon.png`, `build/windows/icon.ico`, `build/icon-source/` | App icon (Mac uses the PNG, Windows the ICO; SVG sources kept) |
| `rsrc_windows_*.syso` | Windows icon, version and manifest, picked up by `go build` |
| `tools/winres/` | Regenerates the `.syso` files |
