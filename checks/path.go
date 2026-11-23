package checks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"netcheckup/engine"
)

func statsDetails(r *engine.Result, label string, s Stats) {
	r.Detail(label+" method", s.Method)
	r.Detail(label+" sent / received", fmt.Sprintf("%d / %d (%.0f%% loss)", s.Sent, s.Received, s.LossPct()))
	if s.Received > 0 {
		r.Detail(label+" min / avg / max", fmt.Sprintf("%s / %s / %s ms", f1(s.Min()), f1(s.Avg()), f1(s.Max())))
		r.Detail(label+" jitter", f1(s.Jitter())+" ms")
	}
}

func (f *facts) gatewayCheck(ctx context.Context, _ *engine.Env, r *engine.Result) {
	f.load(ctx)
	if f.gateway4 == "" {
		r.Summary = "No IPv4 router found to test."
		r.Add(engine.Bad, "No gateway", "Without a default gateway nothing outside this computer is reachable.")
		return
	}
	s := f.gateway(ctx)
	r.Detail("Gateway", f.gateway4)
	statsDetails(r, "Probe", s)
	wifi := f.primary != nil && f.kind(f.primary.Name).Kind == "Wi-Fi"
	where := "the link between this computer and the router"
	if wifi {
		where = "the Wi-Fi link (distance, walls, interference, or a busy channel)"
	}
	if s.Received == 0 {
		r.Summary = "The router did not answer."
		if s.Method == "ICMP echo" {
			r.Add(engine.Warn, "Router ignores probes", "The router did not answer ping or common ports. Some routers do this by design, so check the internet card: if that is fine, this is harmless.")
		} else {
			r.Add(engine.Bad, "Router unreachable", "Nothing came back from the router. If the internet card also fails, the problem is "+where+" or the router itself.")
		}
		return
	}
	r.Status = engine.Good
	r.Summary = fmt.Sprintf("Router answers in %s ms on average, %s ms jitter, %.0f%% loss.", f1(s.Avg()), f1(s.Jitter()), s.LossPct())
	loss := s.LossPct()
	switch {
	case loss >= 5:
		r.Add(engine.Bad, "Packet loss to the router", fmt.Sprintf("%.0f%% of probes to your own router were lost. Loss this close to home points at %s, not your internet provider.", loss, where))
	case loss > 0:
		r.Add(engine.Warn, "Some packet loss to the router", fmt.Sprintf("%.0f%% of probes were lost before even leaving your home network. Worth watching if calls stutter.", loss))
	}
	switch {
	case s.Avg() > 100:
		r.Add(engine.Bad, "Very slow response from the router", "A healthy router answers in a few milliseconds. Over 100 ms usually means a weak Wi-Fi signal or an overloaded router.")
	case s.Avg() > 20:
		r.Add(engine.Warn, "Slow response from the router", "Answers from the router should take under about 10 ms. A slow local link adds delay to everything you do online.")
	}
	if s.Jitter() > 15 {
		r.Add(engine.Warn, "Unsteady link to the router", "Response times swing a lot, which makes video calls choppy. Common on congested or weak Wi-Fi.")
	}
}

var internetTargets = []struct{ ip, name string }{
	{"1.1.1.1", "Cloudflare"}, {"8.8.8.8", "Google"}, {"9.9.9.9", "Quad9"},
}

func (f *facts) internetCheck(ctx context.Context, _ *engine.Env, r *engine.Result) {
	f.load(ctx)
	var wg sync.WaitGroup
	results := make([]Stats, len(internetTargets))
	for i, t := range internetTargets {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			results[i] = probe(ctx, ip, 15, 200*time.Millisecond, []string{"443", "53"})
		}(i, t.ip)
	}
	gw := f.gateway(ctx)
	wg.Wait()
	tbl := engine.Table{Title: "Probe results", Columns: []string{"Target", "Method", "Sent", "Lost %", "Min ms", "Avg ms", "Max ms", "Jitter ms"}}
	var sent, recv int
	var best Stats
	for i, s := range results {
		tbl.Rows = append(tbl.Rows, []string{internetTargets[i].name + " " + internetTargets[i].ip, s.Method, fmt.Sprint(s.Sent), fmt.Sprintf("%.0f", s.LossPct()), f1(s.Min()), f1(s.Avg()), f1(s.Max()), f1(s.Jitter())})
		sent += s.Sent
		recv += s.Received
		if s.Received > best.Received || (s.Received == best.Received && s.Received > 0 && s.Avg() < best.Avg()) {
			best = s
		}
	}
	r.Tables = append(r.Tables, tbl)
	if recv == 0 {
		r.Summary = "No reply from any internet test server."
		r.Add(engine.Bad, "Internet unreachable", "None of three major public servers answered. If the router card is green, the problem is past your router: the modem, the provider, or a VPN/firewall blocking traffic.")
		return
	}
	loss := 100 * float64(sent-recv) / float64(sent)
	r.Status = engine.Good
	r.Summary = fmt.Sprintf("Internet round trip %s ms, %s ms jitter, %.1f%% loss.", f1(best.Avg()), f1(best.Jitter()), loss)
	localLoss := gw.Received > 0 && gw.LossPct() > 0
	blame := "Your router link looks fine, so this is most likely your internet provider or beyond."
	if localLoss {
		blame = "Your router link also loses packets, so fix the local network (Wi-Fi) first."
	}
	switch {
	case loss >= 5:
		r.Add(engine.Bad, "Heavy packet loss", fmt.Sprintf("%.1f%% of packets to the internet were lost. Expect frozen video calls and stalled downloads. %s", loss, blame))
	case loss > 1:
		r.Add(engine.Warn, "Some packet loss", fmt.Sprintf("%.1f%% loss is enough to make calls choppy. %s", loss, blame))
	}
	switch {
	case best.Avg() > 250:
		r.Add(engine.Bad, "Very high latency", "Over 250 ms round trip makes calls and remote desktops laggy. Satellite links, distant VPN servers, or a saturated connection cause this.")
	case best.Avg() > 100:
		r.Add(engine.Warn, "High latency", "Over 100 ms to major servers is higher than a typical wired home connection (10 to 40 ms).")
	}
	if best.Jitter() > 30 {
		r.Add(engine.Warn, "High jitter", "Delay swings a lot from moment to moment. That makes voice and video choppy even when speed tests look fine; often caused by someone else using the full bandwidth.")
	}
	if best.Avg() < 1 {
		r.Add(engine.Warn, "Answers came back impossibly fast", "Public internet servers replied in under 1 ms, faster than a real round trip allows. Something nearby (a firewall, proxy, VPN client, or security software) is answering on their behalf, so these numbers do not reflect your real internet path.")
	}
	if gw.Received > 0 {
		r.Detail("Router share of delay", fmt.Sprintf("%s of %s ms", f1(gw.Avg()), f1(best.Avg())))
		if best.Avg() > 60 && gw.Avg() > 0.5*best.Avg() {
			r.Add(engine.Warn, "Most delay is inside your home", "More than half the round trip is spent reaching your own router, which points at Wi-Fi rather than the provider.")
		}
	}
}

var captiveProbes = []struct {
	name, url string
	code      int
	body      string
}{
	{"Apple", "http://captive.apple.com/hotspot-detect.html", 200, "Success"},
	{"Microsoft", "http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test"},
	{"Google", "http://connectivitycheck.gstatic.com/generate_204", 204, ""},
}

func (f *facts) captiveCheck(ctx context.Context, _ *engine.Env, r *engine.Result) {
	client := &http.Client{
		Timeout:   6 * time.Second,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	type out struct {
		ok, redirected bool
		code           int
		loc, err       string
	}
	res := make([]out, len(captiveProbes))
	var wg sync.WaitGroup
	for i, p := range captiveProbes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(ctx, "GET", p.url, nil)
			req.Header.Set("User-Agent", "NetworkCheckup/0.1")
			resp, err := client.Do(req)
			if err != nil {
				res[i] = out{err: shortErr(err)}
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			o := out{code: resp.StatusCode, loc: resp.Header.Get("Location")}
			o.redirected = resp.StatusCode >= 300 && resp.StatusCode < 400
			o.ok = resp.StatusCode == p.code && (p.body == "" || strings.Contains(string(b), p.body))
			res[i] = o
		}(i)
	}
	wg.Wait()
	t := engine.Table{Title: "Connectivity probes (plain HTTP, no proxy)", Columns: []string{"Probe", "URL", "Status", "Verdict"}}
	var ok, redir, failed, odd int
	var loc string
	for i, o := range res {
		verdict := "expected answer"
		switch {
		case o.err != "":
			verdict, failed = o.err, failed+1
		case o.redirected:
			verdict, redir = "redirected to "+o.loc, redir+1
			loc = o.loc
		case !o.ok:
			verdict, odd = "unexpected content", odd+1
		default:
			ok++
		}
		code := "-"
		if o.code > 0 {
			code = fmt.Sprint(o.code)
		}
		t.Rows = append(t.Rows, []string{captiveProbes[i].name, captiveProbes[i].url, code, verdict})
	}
	r.Tables = append(r.Tables, t)
	switch {
	case ok == len(res):
		r.Status = engine.Good
		r.Summary = "Real, open internet: test pages came back untouched."
	case redir > 0:
		r.Summary = "A login or terms page is intercepting traffic."
		r.Add(engine.Bad, "Captive portal detected", "This network redirects web requests to "+loc+". Open a browser and visit any http:// site to finish the hotel/guest Wi-Fi sign-in. A VPN that starts before sign-in can hide this page.")
	case odd > 0:
		r.Summary = "Web responses are being altered."
		r.Add(engine.Warn, "Unexpected responses", "Test pages came back with different content. A portal, content filter, or security appliance may be rewriting traffic.")
	case failed == len(res):
		r.Summary = "Plain web requests fail."
		r.Add(engine.Bad, "No direct web access", "None of the connectivity test pages loaded. Either the internet is down, or this network only allows traffic through a proxy.")
	default:
		r.Summary = "Some test pages failed to load."
		r.Add(engine.Warn, "Partial web access", "Some connectivity checks failed. A firewall or filter may be blocking certain sites.")
	}
}
