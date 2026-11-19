package main

import "testing"

func testDB() *DB {
	return &DB{Tables: map[string]*Table{
		"users": {Cols: []string{"id", "name", "pw"}, Rows: [][]Value{
			{int64(1), "admin", "s3cret"}, {int64(2), "bob", "pw"}}},
		"secrets": {Cols: []string{"id", "v"}, Rows: [][]Value{{int64(1), "FLAG{x}"}}},
	}}
}

func TestQueries(t *testing.T) {
	db := testDB()
	cases := []struct {
		q    string
		rows int
	}{
		{"SELECT * FROM users", 2},
		{"select name from users where id = 2", 1},
		{"SELECT name FROM users WHERE name = 'admin' AND pw = 'x'", 0},
		{"SELECT name FROM users WHERE name = 'x' OR 1=1", 2},
		{"SELECT name FROM users WHERE name = 'x' OR '1'='1'", 2},
		{"SELECT name FROM users WHERE name = 'admin'-- ' AND pw = 'x'", 1},
		{"SELECT name FROM users WHERE name = 'admin'#' AND pw = 'x'", 1},
		{"SELECT name FROM users WHERE name = 'x'/**/OR/**/'a'='a'", 2},
		{"SELECT name FROM users WHERE name LIKE '%dm%'", 1},
		{"SELECT name, pw FROM users WHERE id = 99 UNION SELECT id, v FROM secrets", 1},
		{"SELECT name FROM users WHERE NOT (id = 1)", 1},
		{"SELECT 'it''s' || 'x'", 1},
		{"SELECT name FROM users WHERE id >= 1 AND id <> 2;", 1},
	}
	for _, c := range cases {
		res, err := db.Query(c.q)
		if err != nil {
			t.Fatalf("%q: %v", c.q, err)
		}
		if len(res.Rows) != c.rows {
			t.Errorf("%q: got %d rows, want %d", c.q, len(res.Rows), c.rows)
		}
	}
}

func TestErrors(t *testing.T) {
	db := testDB()
	for q, want := range map[string]string{
		"SELECT name FROM users WHERE name = 'x''":               "unrecognized token",
		"SELECT name FROM users UNION SELECT id, v FROM secrets": "same number of result columns",
		"SELECT name FROM nope":                                  "no such table",
		"SELECT nope FROM users":                                 "no such column",
		"SELECT name FROM users WHERE":                           "incomplete input",
		"SELECT name FROM users WHERE name = 'a' garbage":        "syntax error",
	} {
		_, err := db.Query(q)
		if err == nil || !contains(err.Error(), want) {
			t.Errorf("%q: err=%v want %q", q, err, want)
		}
	}
}

func TestPlaceholdersAreNotParsed(t *testing.T) {
	db := testDB()
	res, err := db.Query("SELECT name FROM users WHERE name = ?", "x' OR '1'='1")
	if err != nil || len(res.Rows) != 0 {
		t.Fatalf("bound param was interpreted: rows=%v err=%v", res, err)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
