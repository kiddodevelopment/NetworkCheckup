// Network Checkup: plain-English network diagnostics for Windows and macOS.
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

var version = "0.3.0"

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := &App{}
	err := wails.Run(&options.App{
		Title:            "Network Checkup",
		Width:            1180,
		Height:           860,
		MinWidth:         420,
		MinHeight:        500,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 246, G: 247, B: 249, A: 255},
		OnStartup:        app.startup,
		Bind:             []interface{}{app},
		Windows:          &windows.Options{Theme: windows.SystemDefault},
		Mac: &mac.Options{
			About: &mac.AboutInfo{Title: "Network Checkup", Message: "Version " + version + "\nPlain-English network diagnostics."},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
