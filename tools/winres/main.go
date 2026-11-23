// Regenerates the Windows icon/manifest/version resources (rsrc_windows_*.syso)
// so a plain `go build` produces a proper Windows app. Run after changing
// build/windows/icon.ico or the version:
//
//	go run ./tools/winres 0.2.0
package main

import (
	"bytes"
	"log"
	"os"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

const manifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
    <assemblyIdentity type="win32" name="NetworkCheckup" version="1.0.0.0" processorArchitecture="*"/>
    <dependency><dependentAssembly>
        <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly></dependency>
    <asmv3:application><asmv3:windowsSettings>
        <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
        <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">permonitorv2,permonitor</dpiAwareness>
    </asmv3:windowsSettings></asmv3:application>
</assembly>`

func main() {
	ver := "0.2.0"
	if len(os.Args) > 1 {
		ver = os.Args[1]
	}
	b, err := os.ReadFile("build/windows/icon.ico")
	if err != nil {
		log.Fatal(err)
	}
	ico, err := winres.LoadICO(bytes.NewReader(b))
	if err != nil {
		log.Fatal(err)
	}
	for _, arch := range []winres.Arch{winres.ArchAMD64, winres.ArchARM64} {
		rs := winres.ResourceSet{}
		if err := rs.SetIcon(winres.Name("APPICON"), ico); err != nil {
			log.Fatal(err)
		}
		rs.Set(winres.RT_MANIFEST, winres.ID(1), 0, []byte(manifest))
		vi := version.Info{}
		vi.SetFileVersion(ver)
		vi.SetProductVersion(ver)
		vi.Set(0, version.ProductName, "Network Checkup")
		vi.Set(0, version.FileDescription, "Network Checkup")
		vi.Set(0, version.OriginalFilename, "NetworkCheckup.exe")
		rs.SetVersionInfo(vi)
		f, err := os.Create("rsrc_windows_" + string(arch) + ".syso")
		if err != nil {
			log.Fatal(err)
		}
		if err := rs.WriteObject(f, arch); err != nil {
			log.Fatal(err)
		}
		f.Close()
	}
}
