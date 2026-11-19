// vulnweb: deliberately vulnerable "corporate intranet" with difficulty levels.
//
//	vuln         easy                 medium                          hard                                secure
//	SQLi login   raw concat, errors   blocks "--", " or "             blocks \s(or|and|union|select..)\s,  bound params + PBKDF2
//	                                   (bypass: admin'#, 'OR'1'='1)    "--", "#" (bypass: /**/ comments)
//	SQLi search  UNION via LIKE        same filter                     same filter                          bound params
//	XSS          raw reflection        strips "<script" (case-sens.)   escapes <>& but not quotes in attr   escaped + CSP
//	IDOR notes   no auth               login, no owner check           login, base64 "note:N" refs          owner check
//	traversal    raw join              strips "../" once (....//)      blocks "..", then decodes twice      clean + base check
//	admin        admin:admin, role     leaked creds in /backup         only via SQLi                        random password
//	             cookie trusted
//
// Flags (FLAG{...}) prove exploitation: sqli (secrets table), idor (admin note), traversal (private file),
// admin (admin panel).
package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var Levels = []string{"easy", "medium", "hard", "secure"}

type session struct {
	id       int64
	username string
	role     string
}

type App struct {
	level    string
	site     string
	db       *DB
	flags    map[string]string
	filesDir string
	mu       sync.Mutex
	sessions map[string]session
}

var hardFilter = regexp.MustCompile(`\s(or|and|union|select|from|where)\s`)

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key, _ := pbkdf2.Key(sha256.New, pw, salt, 210000, 32)
	return "pbkdf2$" + base64.StdEncoding.EncodeToString(salt) + "$" + base64.StdEncoding.EncodeToString(key)
}

func checkPassword(stored, pw string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 3 {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(parts[1])
	want, err2 := base64.StdEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, 210000, 32)
	return err == nil && hmac.Equal(got, want)
}

func NewApp(level, site string, flags map[string]string, filesDir string) (*App, error) {
	valid := false
	for _, l := range Levels {
		valid = valid || l == level
	}
	if !valid {
		return nil, fmt.Errorf("level must be one of %v", Levels)
	}
	if flags == nil {
		flags = map[string]string{}
	}
	for _, k := range []string{"sqli", "idor", "traversal", "admin"} {
		if flags[k] == "" {
			flags[k] = fmt.Sprintf("FLAG{%s-%s}", k, randHex(6))
		}
	}
	adminPw := map[string]string{"easy": "admin", "medium": "Winter2026!"}[level]
	if adminPw == "" {
		adminPw = randHex(12)
	}
	store := func(pw string) Value {
		if level == "secure" {
			return hashPassword(pw)
		}
		return pw
	}
	db := &DB{Tables: map[string]*Table{
		"users": {Cols: []string{"id", "username", "password", "role", "email"}, Rows: [][]Value{
			{int64(1), "admin", store(adminPw), "admin", "admin@corp.local"},
			{int64(2), "j.doe", store("summer2024"), "user", "j.doe@corp.local"},
			{int64(3), "m.mueller", store("Passw0rd!"), "user", "m.mueller@corp.local"},
		}},
		"secrets": {Cols: []string{"id", "name", "value"}, Rows: [][]Value{
			{int64(1), "db_backup_key", flags["sqli"]},
		}},
		"notes": {Cols: []string{"id", "owner", "title", "body"}, Rows: [][]Value{
			{int64(1), "admin", "Board meeting Q4", "Budget cuts confidential. " + flags["idor"]},
			{int64(2), "j.doe", "Todo", "Renew VPN certificate"},
			{int64(3), "j.doe", "Lunch", "Pizza on Friday"},
		}},
	}}
	for dir, files := range map[string]map[string]string{
		"public":  {"handbook.txt": "Employee handbook v3\n", "menu.txt": "Canteen: soup, pasta\n"},
		"private": {"flag.txt": flags["traversal"] + "\n"},
	} {
		if err := os.MkdirAll(filepath.Join(filesDir, dir), 0o755); err != nil {
			return nil, err
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(filesDir, dir, name), []byte(body), 0o644); err != nil {
				return nil, err
			}
		}
	}
	return &App{level: level, site: site, db: db, flags: flags, filesDir: filesDir, sessions: map[string]session{}}, nil
}

// ---- helpers ------------------------------------------------------------------------------
func (a *App) headers(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	switch a.level {
	case "easy", "medium":
		h.Set("Server", "Apache/2.4.29 (Ubuntu)")
		h.Set("X-Powered-By", "PHP/7.2.24")
	case "hard":
		h.Set("Server", "nginx")
	case "secure":
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
	}
}

func (a *App) page(w http.ResponseWriter, r *http.Request, status int, title, body string) {
	a.headers(w)
	w.WriteHeader(status)
	who := "not logged in · <a href=\"/login\">login</a>"
	if s, ok := a.current(r); ok {
		who = "logged in as <b>" + html.EscapeString(s.username) + "</b> · <a href=\"/logout\">logout</a>"
	}
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>%s · %s</title></head><body>
<header><b>%s</b> intranet · <a href="/">home</a> · <a href="/directory">directory</a> · <a href="/notes">notes</a> · <a href="/files">files</a> · <a href="/admin">admin</a> · %s</header>
<h1>%s</h1>%s</body></html>`, html.EscapeString(title), html.EscapeString(a.site), html.EscapeString(a.site), who,
		html.EscapeString(title), body)
}

func (a *App) current(r *http.Request) (session, bool) {
	c, err := r.Cookie("sid")
	if err != nil {
		return session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[c.Value]
	return s, ok
}

func (a *App) login(w http.ResponseWriter, s session) {
	sid := randHex(16)
	a.mu.Lock()
	a.sessions[sid] = s
	a.mu.Unlock()
	c := &http.Cookie{Name: "sid", Value: sid, Path: "/"}
	if a.level == "secure" {
		c.HttpOnly = true
		c.SameSite = http.SameSiteStrictMode
	}
	http.SetCookie(w, c)
	if a.level == "easy" {
		http.SetCookie(w, &http.Cookie{Name: "role", Value: s.role, Path: "/"})
	}
}

// sqlFilter returns false when the input is rejected by the level's (bypassable) filter.
func (a *App) sqlFilter(in string) bool {
	switch a.level {
	case "medium":
		return !strings.Contains(in, "--") && !strings.Contains(in, " or ")
	case "hard":
		low := strings.ToLower(in)
		return !strings.Contains(low, "--") && !strings.Contains(low, "#") && !hardFilter.MatchString(low)
	}
	return true
}

func (a *App) sqlError(err error, q string) string {
	if a.level == "easy" {
		return "<pre>SQL error: " + html.EscapeString(err.Error()) + "\nquery: " + html.EscapeString(q) + "</pre>"
	}
	return "<p>Request failed.</p>"
}

func row(vals ...Value) string {
	var b strings.Builder
	b.WriteString("<tr>")
	for _, v := range vals {
		b.WriteString("<td>" + html.EscapeString(toStr(v)) + "</td>")
	}
	b.WriteString("</tr>")
	return b.String()
}

// ---- handlers -----------------------------------------------------------------------------
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.home)
	mux.HandleFunc("/login", a.loginPage)
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("/directory", a.directory)
	mux.HandleFunc("/notes", a.notes)
	mux.HandleFunc("/files", a.files)
	mux.HandleFunc("/admin", a.admin)
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		if a.level == "secure" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin\nDisallow: /backup/\n")
	})
	mux.HandleFunc("/backup/config.bak", func(w http.ResponseWriter, r *http.Request) {
		if a.level != "easy" && a.level != "medium" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		pw := map[string]string{"easy": "admin", "medium": "Winter2026!"}[a.level]
		fmt.Fprintf(w, "[db]\nhost=10.0.0.5\nuser=admin\npassword=%s\n", pw)
	})
	return mux
}

func (a *App) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		a.page(w, r, http.StatusNotFound, "Not found", "<p>Page not found.</p>")
		return
	}
	a.page(w, r, http.StatusOK, "Welcome", "<p>Internal portal. Demo account: <code>j.doe</code> / <code>summer2024</code>.</p>")
}

func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	form := `<form method="post"><input name="username" placeholder="username"> <input name="password" type="password" placeholder="password"> <button>Login</button></form>`
	if r.Method != http.MethodPost {
		a.page(w, r, http.StatusOK, "Login", form)
		return
	}
	u, p := r.FormValue("username"), r.FormValue("password")
	var s session
	found := false
	if a.level == "secure" {
		res, err := a.db.Query("SELECT id, username, role, password FROM users WHERE username = ?", u)
		if err == nil && len(res.Rows) == 1 && checkPassword(toStr(res.Rows[0][3]), p) {
			s, found = session{res.Rows[0][0].(int64), toStr(res.Rows[0][1]), toStr(res.Rows[0][2])}, true
		}
	} else {
		if !a.sqlFilter(u) || !a.sqlFilter(p) {
			a.page(w, r, http.StatusForbidden, "Login", "<p>Blocked by security filter.</p>"+form)
			return
		}
		q := fmt.Sprintf("SELECT id, username, role FROM users WHERE username = '%s' AND password = '%s'", u, p)
		res, err := a.db.Query(q)
		if err != nil {
			a.page(w, r, http.StatusInternalServerError, "Login", a.sqlError(err, q)+form)
			return
		}
		if len(res.Rows) > 0 {
			id, _ := res.Rows[0][0].(int64)
			s, found = session{id, toStr(res.Rows[0][1]), toStr(res.Rows[0][2])}, true
		}
	}
	if !found {
		a.page(w, r, http.StatusUnauthorized, "Login", "<p>Invalid credentials.</p>"+form)
		return
	}
	a.login(w, s)
	http.Redirect(w, r, "/", http.StatusFound)
}

func attrEscapeNoQuotes(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func (a *App) directory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	var text, attr string
	switch a.level {
	case "easy":
		text, attr = q, q
	case "medium":
		text, attr = strings.ReplaceAll(q, "<script", ""), html.EscapeString(q)
	case "hard":
		text, attr = html.EscapeString(q), attrEscapeNoQuotes(q)
	default:
		text, attr = html.EscapeString(q), html.EscapeString(q)
	}
	body := `<form><input name="q" value="` + attr + `"> <button>Search</button></form>`
	if q == "" {
		a.page(w, r, http.StatusOK, "Employee directory", body)
		return
	}
	body += "<p>Results for: " + text + "</p>"
	var res *Result
	var err error
	sql := ""
	if a.level == "secure" {
		res, err = a.db.Query("SELECT username, email FROM users WHERE username LIKE ?", "%"+q+"%")
	} else {
		if !a.sqlFilter(q) {
			a.page(w, r, http.StatusForbidden, "Employee directory", body+"<p>Blocked by security filter.</p>")
			return
		}
		sql = fmt.Sprintf("SELECT username, email FROM users WHERE username LIKE '%%%s%%'", q)
		res, err = a.db.Query(sql)
	}
	if err != nil {
		a.page(w, r, http.StatusInternalServerError, "Employee directory", body+a.sqlError(err, sql))
		return
	}
	body += "<table><tr><th>user</th><th>email</th></tr>"
	for _, rw := range res.Rows {
		body += row(rw...)
	}
	a.page(w, r, http.StatusOK, "Employee directory", body+"</table>")
}

func (a *App) noteByID(id int64) ([]Value, bool) {
	res, err := a.db.Query("SELECT id, owner, title, body FROM notes WHERE id = ?", id)
	if err != nil || len(res.Rows) == 0 {
		return nil, false
	}
	return res.Rows[0], true
}

func noteRef(id int64) string {
	return base64.URLEncoding.EncodeToString([]byte("note:" + strconv.FormatInt(id, 10)))
}

func (a *App) notes(w http.ResponseWriter, r *http.Request) {
	s, logged := a.current(r)
	if a.level != "easy" && !logged {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	var id int64 = -1
	if a.level == "hard" {
		if ref := r.URL.Query().Get("ref"); ref != "" {
			raw, err := base64.URLEncoding.DecodeString(ref)
			if err == nil && strings.HasPrefix(string(raw), "note:") {
				id, _ = strconv.ParseInt(strings.TrimPrefix(string(raw), "note:"), 10, 64)
			}
		}
	} else if v := r.URL.Query().Get("id"); v != "" {
		id, _ = strconv.ParseInt(v, 10, 64)
	}
	if id < 0 {
		owner := s.username
		if !logged {
			owner = "j.doe"
		}
		res, _ := a.db.Query("SELECT id, title FROM notes WHERE owner = ?", owner)
		body := "<ul>"
		for _, n := range res.Rows {
			link := "/notes?id=" + toStr(n[0])
			if a.level == "hard" {
				link = "/notes?ref=" + noteRef(n[0].(int64))
			}
			body += `<li><a href="` + link + `">` + html.EscapeString(toStr(n[1])) + "</a></li>"
		}
		a.page(w, r, http.StatusOK, "Notes of "+owner, body+"</ul>")
		return
	}
	n, ok := a.noteByID(id)
	if !ok || (a.level == "secure" && toStr(n[1]) != s.username) {
		a.page(w, r, http.StatusNotFound, "Note", "<p>No such note.</p>")
		return
	}
	a.page(w, r, http.StatusOK, toStr(n[2]), "<p>"+html.EscapeString(toStr(n[3]))+"</p><p>owner: "+html.EscapeString(toStr(n[1]))+"</p>")
}

func (a *App) files(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	base := filepath.Join(a.filesDir, "public")
	if name == "" {
		a.page(w, r, http.StatusOK, "Files", `<ul><li><a href="/files?name=handbook.txt">handbook.txt</a></li><li><a href="/files?name=menu.txt">menu.txt</a></li></ul>`)
		return
	}
	var path string
	switch a.level {
	case "easy":
		path = filepath.Join(base, name)
	case "medium":
		path = filepath.Join(base, strings.ReplaceAll(name, "../", ""))
	case "hard":
		if strings.Contains(name, "..") {
			a.page(w, r, http.StatusForbidden, "Files", "<p>Blocked by security filter.</p>")
			return
		}
		decoded, err := url.QueryUnescape(name) // bug: second decode after the check
		if err != nil {
			decoded = name
		}
		path = filepath.Join(base, decoded)
	default:
		path = filepath.Join(base, filepath.Clean("/"+name))
		if !strings.HasPrefix(path, base+string(filepath.Separator)) {
			a.page(w, r, http.StatusForbidden, "Files", "<p>Forbidden.</p>")
			return
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		a.page(w, r, http.StatusNotFound, "Files", "<p>No such file.</p>")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if a.level == "secure" {
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	w.Write(data)
}

func (a *App) admin(w http.ResponseWriter, r *http.Request) {
	s, ok := a.current(r)
	isAdmin := ok && s.role == "admin"
	if a.level == "easy" {
		if c, err := r.Cookie("role"); err == nil && c.Value == "admin" {
			isAdmin = true // trusts a client-side cookie
		}
	}
	if !isAdmin {
		a.page(w, r, http.StatusForbidden, "Admin", "<p>Administrators only.</p>")
		return
	}
	a.page(w, r, http.StatusOK, "Admin", "<p>Maintenance key: <code>"+html.EscapeString(a.flags["admin"])+"</code></p>")
}

// ---- entry --------------------------------------------------------------------------------
func runVulnweb(args []string) int {
	fs := flag.NewFlagSet("vulnweb", flag.ContinueOnError)
	listen := fs.String("listen", ":8080", "listen address")
	level := fs.String("level", "easy", "easy|medium|hard|secure")
	site := fs.String("site", "Corp", "site name")
	flagsFile := fs.String("flags", "", "JSON file with flag values")
	files := fs.String("files", "/tmp/vulnweb", "writable dir for served files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	flags := map[string]string{}
	if *flagsFile != "" {
		raw, err := os.ReadFile(*flagsFile)
		if err != nil {
			log.Print(err)
			return 1
		}
		if err := json.Unmarshal(raw, &flags); err != nil {
			log.Print(err)
			return 1
		}
	}
	app, err := NewApp(*level, *site, flags, *files)
	if err != nil {
		log.Print(err)
		return 1
	}
	log.Printf("vulnweb %s level=%s listen=%s", *site, *level, *listen)
	srv := &http.Server{Addr: *listen, Handler: app.Handler()}
	if err := srv.ListenAndServe(); err != nil {
		log.Print(err)
		return 1
	}
	return 0
}
