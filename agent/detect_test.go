package main

import (
	"strings"
	"testing"
)

func feed(events []Event) map[string]Alert {
	en := NewEngine()
	for _, e := range events {
		en.Add(e)
	}
	out := map[string]Alert{}
	for _, a := range en.Alerts() {
		out[a.Rule] = a
	}
	return out
}

func hev(ts float64, client, method, path, query string, status int) Event {
	return Event{TS: ts, Source: "portal", Role: "vulnweb", Kind: "http", Client: client,
		Method: method, Path: path, Query: query, Status: status}
}

func TestSignatureRulesFireOnOneRequest(t *testing.T) {
	cases := map[string]Event{
		"http-sqli":      hev(1, "10.0.0.2", "GET", "/directory", "q=zz' UNION SELECT name,value FROM secrets", 200),
		"http-traversal": hev(1, "10.0.0.2", "GET", "/files", "name=../private/flag.txt", 200),
		"http-xss":       hev(1, "10.0.0.2", "GET", "/directory", "q=<script>alert(1)</script>", 200),
	}
	for rule, ev := range cases {
		a := feed([]Event{ev})
		if _, ok := a[rule]; !ok {
			t.Errorf("%s did not fire on %q", rule, ev.Query)
		}
	}
}

func TestSqliInlineCommentsDetected(t *testing.T) {
	a := feed([]Event{hev(1, "x", "GET", "/directory", "q=zz'/**/UNION/**/SELECT/**/name,value/**/FROM/**/secrets", 200)})
	if _, ok := a["http-sqli"]; !ok {
		t.Error("inline-comment UNION not detected")
	}
}

func TestDoubleEncodedTraversalDetected(t *testing.T) {
	a := feed([]Event{hev(1, "x", "GET", "/files", "name=%252e%252e%252fprivate%252fflag.txt", 200)})
	if _, ok := a["http-traversal"]; !ok {
		t.Error("double-encoded traversal not detected")
	}
}

func TestBenignTrafficRaisesNothing(t *testing.T) {
	var evs []Event
	for i := 0; i < 20; i++ {
		evs = append(evs, hev(float64(i), "10.0.0.2", "GET", "/", "", 200))
	}
	if a := feed(evs); len(a) != 0 {
		t.Errorf("benign traffic raised alerts: %v", a)
	}
}

func TestEnumNeedsABurst(t *testing.T) {
	// 7 x 404 in window -> below threshold (8); 8 -> fires.
	var evs []Event
	for i := 0; i < 7; i++ {
		evs = append(evs, hev(float64(i), "10.0.0.9", "GET", "/x", "", 404))
	}
	if _, ok := feed(evs)["http-enum"]; ok {
		t.Error("enum fired below threshold")
	}
	evs = append(evs, hev(7, "10.0.0.9", "GET", "/x", "", 404))
	if _, ok := feed(evs)["http-enum"]; !ok {
		t.Error("enum did not fire at threshold")
	}
}

func TestEnumWindowExpires(t *testing.T) {
	// 8 x 404 but spread over 100s (> 12s window): never 8 within one window.
	var evs []Event
	for i := 0; i < 8; i++ {
		evs = append(evs, hev(float64(i*15), "10.0.0.9", "GET", "/x", "", 404))
	}
	if _, ok := feed(evs)["http-enum"]; ok {
		t.Error("enum fired across an expired window")
	}
}

func TestEnumIsPerClient(t *testing.T) {
	// 8 total but split across two clients -> neither reaches 8.
	var evs []Event
	for i := 0; i < 8; i++ {
		client := "10.0.0.1"
		if i%2 == 0 {
			client = "10.0.0.2"
		}
		evs = append(evs, hev(float64(i), client, "GET", "/x", "", 404))
	}
	if _, ok := feed(evs)["http-enum"]; ok {
		t.Error("enum should be per-client")
	}
}

func TestSshBruteForce(t *testing.T) {
	var evs []Event
	for i := 0; i < 5; i++ {
		evs = append(evs, Event{TS: float64(i), Source: "bastion", Role: "ssh", Kind: "ssh",
			Event: "auth_fail", User: "root", Client: "10.0.0.2"})
	}
	a := feed(evs)
	if got, ok := a["ssh-bruteforce"]; !ok || got.Count != 5 || got.Severity != "high" {
		t.Errorf("ssh brute force not detected: %+v", a)
	}
}

func TestRootLoginFlagged(t *testing.T) {
	a := feed([]Event{{TS: 1, Source: "bastion", Role: "ssh", Kind: "ssh", Event: "auth_ok",
		User: "root", Client: "10.0.0.2"}})
	if _, ok := a["ssh-root-login"]; !ok {
		t.Error("root login not flagged")
	}
}

func TestFirewallDeniedFlowsCountPackets(t *testing.T) {
	// One fw event carrying a delta of 25 denied packets exceeds the threshold of 20.
	a := feed([]Event{{TS: 1, Source: "router", Role: "router", Kind: "fw", Verdict: "drop", Delta: 25}})
	got, ok := a["fw-denied-flows"]
	if !ok || got.Count != 25 || got.Technique != "T1046" {
		t.Errorf("fw denied-flows not detected: %+v", a)
	}
}

func TestAlertsSortedBySeverity(t *testing.T) {
	en := NewEngine()
	en.Add(hev(1, "x", "GET", "/directory", "q=<script>alert(1)</script>", 200)) // medium xss
	en.Add(hev(2, "x", "GET", "/files", "name=../private/flag.txt", 200))        // high traversal
	alerts := en.Alerts()
	if len(alerts) < 2 || alerts[0].Severity != "high" {
		t.Errorf("alerts not sorted by severity: %+v", alerts)
	}
}

func TestMonitorMinSeverityFilter(t *testing.T) {
	en := NewEngine()
	en.Add(hev(1, "x", "GET", "/directory", "q=<script>alert(1)</script>", 200)) // medium
	high := 0
	for _, a := range en.Alerts() {
		if severityRank[a.Severity] >= severityRank["high"] {
			high++
		}
	}
	if high != 0 {
		t.Error("expected no high alerts from a lone xss")
	}
}

func TestEvidenceCappedAtFive(t *testing.T) {
	var evs []Event
	for i := 0; i < 10; i++ {
		evs = append(evs, hev(float64(i), "10.0.0.9", "GET", "/x", "", 404))
	}
	a := feed(evs)["http-enum"]
	if len(a.Evidence) != 5 {
		t.Errorf("evidence should cap at 5, got %d", len(a.Evidence))
	}
	for _, e := range a.Evidence {
		if !strings.Contains(e, "404") {
			t.Errorf("bad evidence %q", e)
		}
	}
}
