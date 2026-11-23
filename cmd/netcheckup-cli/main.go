// Command netcheckup-cli runs Network Checkup in a terminal (handy for techs and scripts).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"netcheckup/checks"
	"netcheckup/engine"
	"netcheckup/report"
)

var version = "0.3.0"

func main() {
	mdPath := flag.String("md", "", "write the Markdown report to this file instead of printing it")
	jsonPath := flag.String("json", "", "also write raw JSON results to this file")
	lan := flag.Bool("lan", false, "also scan the local network for devices and services (only on networks you own or manage)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	host, _ := os.Hostname()
	fmt.Fprintln(os.Stderr, "Running Network Checkup (about 20 seconds)...")
	list := checks.All()
	if *lan {
		list = append(list, checks.LAN(func(m string) { fmt.Fprintln(os.Stderr, m) })...)
	}
	snap := engine.RunAll(ctx, list, host, version)
	md := report.Markdown(snap)
	if *jsonPath != "" {
		b, _ := json.MarshalIndent(snap, "", "  ")
		must(os.WriteFile(*jsonPath, b, 0o644))
	}
	if *mdPath != "" {
		must(os.WriteFile(*mdPath, []byte(md), 0o644))
		fmt.Fprintln(os.Stderr, "Wrote", *mdPath)
		return
	}
	fmt.Print(md)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
