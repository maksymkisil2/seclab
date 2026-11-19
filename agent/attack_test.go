package main

import (
	"net/http/httptest"
	"testing"
)

func serve(t *testing.T, level string, vulns map[string]bool) *attacker {
	app, err := NewApp(level, "Test", map[string]string{}, t.TempDir(), vulns)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	return newAttacker(srv.URL)
}

func captured(c *attacker, cats ...string) map[string]bool {
	cat := catalogue()
	got := map[string]bool{}
	for _, name := range cats {
		got[name] = runCategory(c, cat[name]).Captured
	}
	return got
}

// At every non-secure level the attack catalogue captures sqli/idor/traversal/admin; creds only where
// the admin password is guessable (easy, medium). At secure, nothing is captured.
func TestAttackCatalogueByLevel(t *testing.T) {
	cases := map[string]map[string]bool{
		"easy":   {"sqli": true, "idor": true, "traversal": true, "admin": true, "creds": true},
		"medium": {"sqli": true, "idor": true, "traversal": true, "admin": true, "creds": true},
		"hard":   {"sqli": true, "idor": true, "traversal": true, "admin": true, "creds": false},
		"secure": {"sqli": false, "idor": false, "traversal": false, "admin": false, "creds": false},
	}
	for level, want := range cases {
		c := serve(t, level, nil)
		got := captured(c, "sqli", "idor", "traversal", "admin", "creds")
		for cat, exp := range want {
			if got[cat] != exp {
				t.Errorf("level=%s category=%s captured=%v want %v", level, cat, got[cat], exp)
			}
		}
	}
}

func TestDisablingAClassRemovesIt(t *testing.T) {
	// easy level, but SQLi turned off: the sqli category must now fail while the others still land.
	c := serve(t, "easy", map[string]bool{"idor": true, "traversal": true, "admin": true, "xss": true})
	got := captured(c, "sqli", "idor", "traversal")
	if got["sqli"] {
		t.Error("sqli disabled but still captured")
	}
	if !got["idor"] || !got["traversal"] {
		t.Errorf("other classes should still work: %v", got)
	}
}

func TestDisablingAllClassesIsLikeSecure(t *testing.T) {
	c := serve(t, "easy", map[string]bool{"none": true}) // a non-class name: every real class stays off
	for cat, hit := range captured(c, "sqli", "idor", "traversal", "admin") {
		if hit {
			t.Errorf("category %s captured with all classes off", cat)
		}
	}
}

func TestAttackRefusesNonLoopbackTarget(t *testing.T) {
	for _, bad := range []string{"http://example.com:80", "https://127.0.0.1:8080", "http://10.0.0.5:8080",
		"http://127.0.0.1", "ftp://127.0.0.1:21"} {
		if _, err := validTarget(bad); err == nil {
			t.Errorf("target %q should be refused", bad)
		}
	}
	for _, ok := range []string{"http://127.0.0.1:8080", "http://localhost:9000/"} {
		if _, err := validTarget(ok); err != nil {
			t.Errorf("target %q should be allowed: %v", ok, err)
		}
	}
}

func TestAttackFindingReportsTechniqueWhenNothingLands(t *testing.T) {
	c := serve(t, "secure", nil)
	f := runCategory(c, catalogue()["sqli"])
	if f.Captured || f.Technique == "" {
		t.Errorf("expected a reported-but-failed technique, got %+v", f)
	}
}
