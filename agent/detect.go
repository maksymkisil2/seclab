// detect: a small detection engine. Normalized events in (JSON lines on stdin), alerts out.
// Rules are signatures (regex, threshold 1) and correlation rules (threshold over a sliding window).
// This is the blue-team half of seclab: run an attack, then run detection and find it in the alerts.
//
//	seclab-agent monitor [-json] [-min-severity low]   reads events on stdin, writes alerts
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Event is one normalized observation from a log source. Only the fields a source has are set.
type Event struct {
	TS     float64 `json:"ts"`
	Source string  `json:"source"`           // node name (portal, bastion, router)
	Role   string  `json:"role"`             // vulnweb | ssh | router
	Kind   string  `json:"kind"`             // http | ssh | fw
	Client string  `json:"client,omitempty"` // observed source address
	// http
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Query  string `json:"query,omitempty"`
	Status int    `json:"status,omitempty"`
	// ssh
	Event string `json:"event,omitempty"` // auth_fail | auth_ok
	User  string `json:"user,omitempty"`
	// fw
	Verdict string `json:"verdict,omitempty"` // drop
	Delta   int    `json:"delta,omitempty"`   // new denied packets since last sample
}

// Severity ranks, high to low, for sorting and the -min-severity filter.
var severityRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

type Alert struct {
	Rule      string   `json:"rule"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity"`
	Technique string   `json:"technique"` // MITRE ATT&CK id
	Tactic    string   `json:"tactic"`
	Source    string   `json:"source"`        // node the signal was seen on
	Key       string   `json:"key,omitempty"` // correlation key (client/path) when relevant
	Count     int      `json:"count"`
	FirstTS   float64  `json:"first_ts"`
	LastTS    float64  `json:"last_ts"`
	Evidence  []string `json:"evidence"`
}

// match decides whether an event is relevant to a rule and returns the correlation key to group by.
type rule struct {
	name, title, severity, technique, tactic string
	window                                   float64 // seconds; 0 = no window (each match independent)
	threshold                                int     // matches within window needed to fire (1 = signature)
	match                                    func(e Event) (ok bool, key string)
}

func q(e Event) string { return e.Path + "?" + e.Query }

var (
	reSQLi      = regexp.MustCompile(`(?i)(union(\s|/\*)|/\*\*/|'\s*or\s*'|'\s*or\s*1|\bor\s+1=1|information_schema|sleep\s*\(|'\s*--|'\s*#|%27)`)
	reTraversal = regexp.MustCompile(`(?i)(\.\./|\.\.%2f|%2e%2e|\.\.\\|\.\.\.//|%252e)`)
	reXSS       = regexp.MustCompile(`(?i)(<script|onerror\s*=|onfocus\s*=|javascript:|<img[^>]+onerror|alert\s*\()`)
)

func httpSig(re *regexp.Regexp) func(Event) (bool, string) {
	return func(e Event) (bool, string) {
		if e.Kind != "http" {
			return false, ""
		}
		return re.MatchString(q(e)), e.Client
	}
}

// rules: order is irrelevant; each fires independently. Signatures (threshold 1) catch a single
// malicious request; correlation rules need a burst in the window (scans, brute force).
func rules() []rule {
	adminPaths := map[string]bool{"/admin": true, "/backup": true, "/backup/config.bak": true, "/robots.txt": true}
	return []rule{
		{"http-sqli", "SQL injection attempt", "high", "T1190", "Initial Access", 0, 1, httpSig(reSQLi)},
		{"http-traversal", "Path traversal attempt", "high", "T1083", "Discovery", 0, 1, httpSig(reTraversal)},
		{"http-xss", "Cross-site scripting attempt", "medium", "T1059", "Execution", 0, 1, httpSig(reXSS)},
		{"http-enum", "Resource enumeration / scanning", "medium", "T1595", "Reconnaissance", 12, 8,
			func(e Event) (bool, string) {
				if e.Kind != "http" {
					return false, ""
				}
				return e.Status == 401 || e.Status == 403 || e.Status == 404 || strings.HasPrefix(e.Path, "/notes"), e.Client
			}},
		{"http-admin-probe", "Admin / backup path probing", "medium", "T1595", "Reconnaissance", 30, 3,
			func(e Event) (bool, string) {
				if e.Kind != "http" {
					return false, ""
				}
				return adminPaths[e.Path], e.Client
			}},
		{"ssh-bruteforce", "SSH password brute force", "high", "T1110", "Credential Access", 60, 5,
			func(e Event) (bool, string) {
				return e.Kind == "ssh" && e.Event == "auth_fail", e.Client
			}},
		{"ssh-root-login", "Root login over SSH", "medium", "T1078", "Persistence", 0, 1,
			func(e Event) (bool, string) {
				return e.Kind == "ssh" && e.Event == "auth_ok" && e.User == "root", e.Client
			}},
		{"fw-denied-flows", "Blocked cross-segment traffic (lateral movement / scan)", "high", "T1046",
			"Discovery", 30, 10,
			func(e Event) (bool, string) {
				if e.Kind != "fw" || e.Verdict != "drop" {
					return false, ""
				}
				return true, e.Source // correlate denied packets on the router
			}},
	}
}

type window struct {
	times []float64
	ev    []string
}

// Engine applies the ruleset to a stream of events and accumulates alerts, one per (rule, key).
type Engine struct {
	rules   []rule
	windows map[string]*window // rule+"\x00"+key -> timestamps in window
	alerts  map[string]*Alert  // rule+"\x00"+key -> alert
	order   []string
}

func NewEngine() *Engine {
	return &Engine{rules: rules(), windows: map[string]*window{}, alerts: map[string]*Alert{}}
}

func evidence(e Event) string {
	switch e.Kind {
	case "http":
		return fmt.Sprintf("%s %s %d", e.Method, q(e), e.Status)
	case "ssh":
		return fmt.Sprintf("ssh %s user=%s from=%s", e.Event, e.User, e.Client)
	case "fw":
		return fmt.Sprintf("fw drop +%d", e.Delta)
	}
	return e.Kind
}

func (en *Engine) Add(e Event) {
	for _, r := range en.rules {
		ok, key := r.match(e)
		if !ok {
			continue
		}
		id := r.name + "\x00" + key
		w := en.windows[id]
		if w == nil {
			w = &window{}
			en.windows[id] = w
		}
		// fw deltas count packets, not events; everything else counts one per matching event.
		n := 1
		if e.Kind == "fw" && e.Delta > 0 {
			n = e.Delta
		}
		for i := 0; i < n; i++ {
			w.times = append(w.times, e.TS)
		}
		if len(w.ev) < 5 {
			w.ev = append(w.ev, evidence(e))
		}
		if r.window > 0 { // drop timestamps older than the window
			cut := e.TS - r.window
			i := 0
			for i < len(w.times) && w.times[i] < cut {
				i++
			}
			w.times = w.times[i:]
		}
		if len(w.times) < r.threshold {
			continue
		}
		a := en.alerts[id]
		if a == nil {
			a = &Alert{Rule: r.name, Title: r.title, Severity: r.severity, Technique: r.technique,
				Tactic: r.tactic, Source: e.Source, Key: key, FirstTS: w.times[0]}
			en.alerts[id] = a
			en.order = append(en.order, id)
		}
		a.Count = len(w.times)
		a.LastTS = e.TS
		a.Evidence = w.ev
	}
}

func (en *Engine) Alerts() []Alert {
	out := make([]Alert, 0, len(en.alerts))
	for _, id := range en.order {
		out = append(out, *en.alerts[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank[out[i].Severity] != severityRank[out[j].Severity] {
			return severityRank[out[i].Severity] > severityRank[out[j].Severity]
		}
		return out[i].LastTS > out[j].LastTS
	})
	return out
}

func runMonitor(args []string) int {
	fs := flag.NewFlagSet("monitor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	minSev := fs.String("min-severity", "info", "drop alerts below this severity")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	floor, ok := severityRank[*minSev]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown severity %q\n", *minSev)
		return 2
	}
	en := NewEngine()
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var e Event
		if json.Unmarshal([]byte(line), &e) == nil {
			en.Add(e)
		}
	}
	var alerts []Alert
	for _, a := range en.Alerts() {
		if severityRank[a.Severity] >= floor {
			alerts = append(alerts, a)
		}
	}
	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(alerts)
		return 0
	}
	if len(alerts) == 0 {
		fmt.Println("no alerts")
		return 0
	}
	for _, a := range alerts {
		fmt.Printf("%-8s %-18s %-7s %-6s %-10s x%-4d %s\n", strings.ToUpper(a.Severity), a.Rule,
			a.Technique, a.Source, a.Key, a.Count, a.Title)
	}
	return 0
}
