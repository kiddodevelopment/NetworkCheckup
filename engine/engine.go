// Package engine defines the check model and runs checks in parallel.
package engine

import (
	"context"
	"runtime"
	"sort"
	"sync"
	"time"
)

// Status is a card's stoplight colour.
type Status string

const (
	Good    Status = "good"    // green: nothing to worry about
	Warn    Status = "warn"    // amber: worth a look
	Bad     Status = "bad"     // red: likely cause of problems
	Info    Status = "info"    // neutral fact, no judgement
	Limited Status = "limited" // OS or permissions prevented a full check
)

// Rank orders statuses from worst to best for summaries.
func (s Status) Rank() int {
	switch s {
	case Bad:
		return 0
	case Warn:
		return 1
	case Limited:
		return 2
	case Info:
		return 3
	default:
		return 4
	}
}

// Table is a block of tabular technical detail.
type Table struct {
	Title   string     `json:"title"`
	Columns []string   `json:"columns"`
	Rows    [][]string `json:"rows"`
}

// KV is one labelled technical detail.
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Finding is one flagged issue inside a card.
type Finding struct {
	Status  Status `json:"status"`
	Title   string `json:"title"`
	Explain string `json:"explain"`
}

// Result is what a check returns: one card in the UI and report.
type Result struct {
	ID         string    `json:"id"`
	Section    string    `json:"section"`
	Title      string    `json:"title"`
	Status     Status    `json:"status"`
	Summary    string    `json:"summary"`
	Findings   []Finding `json:"findings,omitempty"`
	Details    []KV      `json:"details,omitempty"`
	Tables     []Table   `json:"tables,omitempty"`
	Limits     []string  `json:"limits,omitempty"` // permission / sandbox notes
	DurationMS int64     `json:"durationMs"`
	order      int
}

// Add appends a finding and raises the card status if the finding is worse.
func (r *Result) Add(s Status, title, explain string) {
	r.Findings = append(r.Findings, Finding{s, title, explain})
	r.Raise(s)
}

// Raise lowers the card to s if s is worse than the current status.
func (r *Result) Raise(s Status) {
	if r.Status == "" || s.Rank() < r.Status.Rank() {
		r.Status = s
	}
}

// Detail appends a key/value technical detail.
func (r *Result) Detail(k, v string) { r.Details = append(r.Details, KV{k, v}) }

// Limit records a permission or platform limitation.
func (r *Result) Limit(msg string) {
	r.Limits = append(r.Limits, msg)
	if r.Status == "" || r.Status == Good || r.Status == Info {
		r.Raise(Limited)
	}
}

// Check is one diagnostic.
type Check struct {
	ID      string
	Section string
	Title   string
	Timeout time.Duration
	Run     func(ctx context.Context, env *Env, r *Result)
}

// Env carries facts shared between checks (filled by an early pass).
type Env struct {
	OS string
}

// Snapshot is a full run.
type Snapshot struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	OS       string    `json:"os"`
	Arch     string    `json:"arch"`
	Hostname string    `json:"hostname"`
	Version  string    `json:"version"`
	Overall  Status    `json:"overall"`
	Results  []Result  `json:"results"`
}

// RunAll runs every check concurrently, each with its own timeout,
// and returns results in declaration order.
func RunAll(ctx context.Context, checks []Check, hostname, version string) Snapshot {
	snap := Snapshot{Started: time.Now(), OS: runtime.GOOS, Arch: runtime.GOARCH, Hostname: hostname, Version: version}
	env := &Env{OS: runtime.GOOS}
	results := make([]Result, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		wg.Add(1)
		go func(i int, c Check) {
			defer wg.Done()
			r := Result{ID: c.ID, Section: c.Section, Title: c.Title, order: i}
			t := c.Timeout
			if t == 0 {
				t = 20 * time.Second
			}
			cctx, cancel := context.WithTimeout(ctx, t)
			defer cancel()
			start := time.Now()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if p := recover(); p != nil {
						r.Add(Limited, "Check crashed", "This check hit an internal error and was skipped.")
					}
				}()
				c.Run(cctx, env, &r)
			}()
			select {
			case <-done:
			case <-cctx.Done():
				<-done
			}
			if r.Status == "" {
				r.Status = Good
			}
			r.DurationMS = time.Since(start).Milliseconds()
			results[i] = r
		}(i, c)
	}
	wg.Wait()
	sort.SliceStable(results, func(a, b int) bool { return results[a].order < results[b].order })
	snap.Results = results
	snap.Overall = OverallOf(results)
	snap.Finished = time.Now()
	return snap
}

// OverallOf is the worst red/amber status across results (green otherwise).
func OverallOf(results []Result) Status {
	o := Good
	for _, r := range results {
		if (r.Status == Bad || r.Status == Warn) && r.Status.Rank() < o.Rank() {
			o = r.Status
		}
	}
	return o
}
