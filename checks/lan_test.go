package checks

import (
	"net"
	"testing"
)

func TestMACHelpers(t *testing.T) {
	if got := normMAC("a4:2b:b0:1:2:3"); got != "a4:2b:b0:01:02:03" {
		t.Fatalf("normMAC = %q", got)
	}
	if normMAC("ff:ff:ff:ff:ff:ff") != "" || normMAC("01:00:5e:00:00:fb") != "" {
		t.Fatal("broadcast/multicast should be dropped")
	}
	if !randomMAC("da:a1:19:00:00:01") || randomMAC("f0:d1:a9:00:00:01") {
		t.Fatal("randomMAC wrong")
	}
	if v := macVendor("b8:27:eb:12:34:56"); v != "Raspberry Pi Foundation" {
		t.Fatalf("vendor = %q", v)
	}
}

func TestHostsIn(t *testing.T) {
	_, n, _ := net.ParseCIDR("192.168.1.0/24")
	if h := hostsIn(n); len(h) != 254 || h[0].String() != "192.168.1.1" || h[253].String() != "192.168.1.254" {
		t.Fatalf("hostsIn /24 wrong: %d", len(h))
	}
	_, big, _ := net.ParseCIDR("10.0.0.0/16")
	if hostsIn(big) != nil {
		t.Fatal("/16 must not be swept")
	}
}

func TestMDNSNames(t *testing.T) {
	if svcType("Living Room._airplay._tcp.local") != "_airplay._tcp" {
		t.Fatal("svcType")
	}
	if instanceName(`Living\032Room._airplay._tcp.local`) != "Living Room" {
		t.Fatal("instanceName")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		d    Device
		want string
	}{
		{Device{Services: []string{"_ipp._tcp"}}, "Printer"},
		{Device{Services: []string{"_googlecast._tcp"}}, "Chromecast / Google TV or speaker"},
		{Device{Ports: []portResult{{Port: 62078}}}, "iPhone or iPad"},
		{Device{Ports: []portResult{{Port: 554}}}, "Camera or doorbell"},
		{Device{Gateway: true}, "Router / gateway"},
		{Device{Random: true}, "Phone, tablet or laptop (private address)"},
		{Device{Vendor: "Raspberry Pi Foundation"}, "Raspberry Pi"},
		{Device{Ports: []portResult{{Port: 445}, {Port: 139}}}, "Windows PC"},
	}
	for _, c := range cases {
		d := c.d
		classify(&d)
		if d.Type != c.want {
			t.Errorf("got %q want %q", d.Type, c.want)
		}
	}
	u := Device{}
	classify(&u)
	if !u.Unidentified {
		t.Error("bare device should be unidentified")
	}
}
