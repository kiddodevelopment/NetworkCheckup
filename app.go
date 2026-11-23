package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"netcheckup/checks"
	"netcheckup/engine"
	"netcheckup/report"
)

// App is bound to the window; its exported methods are callable from the UI.
type App struct {
	ctx  context.Context
	mu   sync.Mutex
	last *engine.Snapshot
}

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

// Payload is one run plus its Markdown report.
type Payload struct {
	engine.Snapshot
	Markdown string `json:"markdown"`
}

// Version reports the app version for the UI footer.
func (a *App) Version() string { return version }

// Run performs a full checkup (about 20 seconds). LAN results from an earlier
// scan are dropped because they describe an older moment.
func (a *App) Run() Payload {
	host, _ := os.Hostname()
	s := engine.RunAll(a.ctx, checks.All(), host, version)
	a.mu.Lock()
	a.last = &s
	a.mu.Unlock()
	return Payload{s, report.Markdown(s)}
}

// ScanLAN runs the opt-in local network scan and adds it to the current results.
func (a *App) ScanLAN() (Payload, error) {
	a.mu.Lock()
	base := a.last
	a.mu.Unlock()
	if base == nil {
		return Payload{}, fmt.Errorf("run a checkup first")
	}
	host, _ := os.Hostname()
	lan := engine.RunAll(a.ctx, checks.LAN(func(msg string) {
		runtime.EventsEmit(a.ctx, "lan-progress", msg)
	}), host, version)

	merged := *base
	merged.Results = nil
	for _, r := range base.Results {
		if r.Section != checks.SecLAN {
			merged.Results = append(merged.Results, r)
		}
	}
	merged.Results = append(merged.Results, lan.Results...)
	merged.Overall = engine.OverallOf(merged.Results)
	merged.Finished = time.Now()
	a.mu.Lock()
	a.last = &merged
	a.mu.Unlock()
	return Payload{merged, report.Markdown(merged)}, nil
}

// SaveReport asks where to save the Markdown report and writes it.
// Returns the chosen path, or "" if the user cancelled.
func (a *App) SaveReport(md string) (string, error) {
	if md == "" {
		return "", fmt.Errorf("run a checkup first")
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Network Checkup report",
		DefaultFilename: "network-checkup-" + time.Now().Format("2006-01-02-1504") + ".md",
		Filters:         []runtime.FileFilter{{DisplayName: "Markdown (*.md)", Pattern: "*.md"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	return path, os.WriteFile(path, []byte(md), 0o644)
}
