// minisql: a tiny in-memory SQL engine so that SQL injection in the training app is real:
// user input concatenated into query text is tokenized and parsed like in a real DBMS.
//
// Supported: SELECT cols|*|literals [FROM t] [WHERE expr] (UNION [ALL] SELECT ...)*
// expr: OR / AND / NOT, = != <> < > <= >= LIKE, parentheses, 'strings' (” escape), numbers, NULL, ?
// Comments: -- and # to end of line, /* ... */ (acts as whitespace).
// Placeholders (?) are bound as values and never re-parsed: the safe path.
package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type Value any // string | int64 | nil

type Table struct {
	Cols []string
	Rows [][]Value
}

type DB struct{ Tables map[string]*Table }

type Result struct {
	Cols []string
	Rows [][]Value
}

// ---- lexer --------------------------------------------------------------------------
type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tKeyword
	tString
	tNumber
	tSymbol
	tParam
)

type token struct {
	kind tokKind
	text string
}

var keywords = map[string]bool{"SELECT": true, "FROM": true, "WHERE": true, "AND": true, "OR": true,
	"NOT": true, "UNION": true, "ALL": true, "LIKE": true, "NULL": true}

func lex(q string) ([]token, error) {
	var out []token
	r := []rune(q)
	for i := 0; i < len(r); {
		c := r[i]
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '-' && i+1 < len(r) && r[i+1] == '-', c == '#':
			for i < len(r) && r[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(r) && r[i+1] == '*':
			j := i + 2
			for j+1 < len(r) && !(r[j] == '*' && r[j+1] == '/') {
				j++
			}
			if j+1 >= len(r) {
				return nil, fmt.Errorf("unterminated comment")
			}
			i = j + 2
		case c == '\'':
			var sb strings.Builder
			i++
			closed := false
			for i < len(r) {
				if r[i] == '\'' {
					if i+1 < len(r) && r[i+1] == '\'' {
						sb.WriteRune('\'')
						i += 2
						continue
					}
					closed = true
					i++
					break
				}
				sb.WriteRune(r[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unrecognized token: \"'%s\"", sb.String())
			}
			out = append(out, token{tString, sb.String()})
		case unicode.IsDigit(c):
			j := i
			for j < len(r) && unicode.IsDigit(r[j]) {
				j++
			}
			out = append(out, token{tNumber, string(r[i:j])})
			i = j
		case unicode.IsLetter(c) || c == '_':
			j := i
			for j < len(r) && (unicode.IsLetter(r[j]) || unicode.IsDigit(r[j]) || r[j] == '_') {
				j++
			}
			w := string(r[i:j])
			if keywords[strings.ToUpper(w)] {
				out = append(out, token{tKeyword, strings.ToUpper(w)})
			} else {
				out = append(out, token{tIdent, strings.ToLower(w)})
			}
			i = j
		case c == '?':
			out = append(out, token{tParam, "?"})
			i++
		default:
			two := ""
			if i+1 < len(r) {
				two = string(r[i : i+2])
			}
			if two == "!=" || two == "<>" || two == "<=" || two == ">=" || two == "||" {
				out = append(out, token{tSymbol, two})
				i += 2
			} else if strings.ContainsRune("*,=()<>;", c) {
				out = append(out, token{tSymbol, string(c)})
				i++
			} else {
				return nil, fmt.Errorf("unrecognized token: \"%c\"", c)
			}
		}
	}
	return append(out, token{tEOF, ""}), nil
}

// ---- parser / evaluator ---------------------------------------------------------------
type parser struct {
	toks []token
	pos  int
	args []Value
	argi int
	db   *DB
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }

func (p *parser) accept(kind tokKind, text string) bool {
	t := p.peek()
	if t.kind == kind && t.text == text {
		p.pos++
		return true
	}
	return false
}

func (p *parser) syntaxErr() error {
	t := p.peek()
	if t.kind == tEOF {
		return fmt.Errorf("incomplete input")
	}
	return fmt.Errorf("near \"%s\": syntax error", t.text)
}

// expression tree
type expr interface {
	eval(row map[string]Value) (Value, error)
}

type lit struct{ v Value }
type col struct{ name string }
type unary struct{ e expr }
type binary struct {
	op   string
	l, r expr
}

func (e lit) eval(map[string]Value) (Value, error) { return e.v, nil }
func (e col) eval(row map[string]Value) (Value, error) {
	v, ok := row[e.name]
	if !ok {
		return nil, fmt.Errorf("no such column: %s", e.name)
	}
	return v, nil
}
func (e unary) eval(row map[string]Value) (Value, error) {
	v, err := e.e.eval(row)
	if err != nil {
		return nil, err
	}
	return boolVal(!truthy(v)), nil
}
func (e binary) eval(row map[string]Value) (Value, error) {
	l, err := e.l.eval(row)
	if err != nil {
		return nil, err
	}
	r, err := e.r.eval(row)
	if err != nil {
		return nil, err
	}
	switch e.op {
	case "OR":
		return boolVal(truthy(l) || truthy(r)), nil
	case "AND":
		return boolVal(truthy(l) && truthy(r)), nil
	case "||":
		return toStr(l) + toStr(r), nil
	case "LIKE":
		if l == nil || r == nil {
			return nil, nil
		}
		return boolVal(like(strings.ToLower(toStr(l)), strings.ToLower(toStr(r)))), nil
	}
	if l == nil || r == nil {
		return nil, nil
	}
	c := compare(l, r)
	switch e.op {
	case "=":
		return boolVal(c == 0), nil
	case "!=", "<>":
		return boolVal(c != 0), nil
	case "<":
		return boolVal(c < 0), nil
	case ">":
		return boolVal(c > 0), nil
	case "<=":
		return boolVal(c <= 0), nil
	case ">=":
		return boolVal(c >= 0), nil
	}
	return nil, fmt.Errorf("bad operator %s", e.op)
}

func boolVal(b bool) Value {
	if b {
		return int64(1)
	}
	return int64(0)
}

func truthy(v Value) bool {
	switch x := v.(type) {
	case nil:
		return false
	case int64:
		return x != 0
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return err == nil && n != 0
	}
	return false
}

func toStr(v Value) string {
	switch x := v.(type) {
	case nil:
		return ""
	case int64:
		return strconv.FormatInt(x, 10)
	case string:
		return x
	}
	return fmt.Sprint(v)
}

func compare(a, b Value) int {
	ai, aok := a.(int64)
	bi, bok := b.(int64)
	if aok && bok {
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		}
		return 0
	}
	if aok != bok { // sqlite: integer vs text compares by type unless text looks numeric
		var num int64
		var text string
		if aok {
			num, text = ai, b.(string)
		} else {
			num, text = bi, a.(string)
		}
		if n, err := strconv.ParseInt(text, 10, 64); err == nil {
			if aok {
				return compare(num, n)
			}
			return compare(n, num)
		}
		if aok {
			return -1
		}
		return 1
	}
	return strings.Compare(toStr(a), toStr(b))
}

func like(s, pattern string) bool {
	if pattern == "" {
		return s == ""
	}
	switch pattern[0] {
	case '%':
		for i := 0; i <= len(s); i++ {
			if like(s[i:], pattern[1:]) {
				return true
			}
		}
		return false
	case '_':
		return s != "" && like(s[1:], pattern[1:])
	}
	return s != "" && s[0] == pattern[0] && like(s[1:], pattern[1:])
}

func (p *parser) parseExpr() (expr, error) { return p.parseOr() }

func (p *parser) parseOr() (expr, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.accept(tKeyword, "OR") {
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = binary{"OR", l, r}
	}
	return l, nil
}

func (p *parser) parseAnd() (expr, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.accept(tKeyword, "AND") {
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l = binary{"AND", l, r}
	}
	return l, nil
}

func (p *parser) parseNot() (expr, error) {
	if p.accept(tKeyword, "NOT") {
		e, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return unary{e}, nil
	}
	return p.parseCmp()
}

func (p *parser) parseCmp() (expr, error) {
	l, err := p.parseConcat()
	if err != nil {
		return nil, err
	}
	t := p.peek()
	isOp := t.kind == tSymbol && (t.text == "=" || t.text == "!=" || t.text == "<>" || t.text == "<" ||
		t.text == ">" || t.text == "<=" || t.text == ">=")
	if isOp || (t.kind == tKeyword && t.text == "LIKE") {
		p.next()
		r, err := p.parseConcat()
		if err != nil {
			return nil, err
		}
		return binary{t.text, l, r}, nil
	}
	return l, nil
}

func (p *parser) parseConcat() (expr, error) {
	l, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for p.accept(tSymbol, "||") {
		r, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		l = binary{"||", l, r}
	}
	return l, nil
}

func (p *parser) parsePrimary() (expr, error) {
	t := p.next()
	switch t.kind {
	case tString:
		return lit{t.text}, nil
	case tNumber:
		n, _ := strconv.ParseInt(t.text, 10, 64)
		return lit{n}, nil
	case tIdent:
		return col{t.text}, nil
	case tParam:
		if p.argi >= len(p.args) {
			return nil, fmt.Errorf("not enough parameters")
		}
		v := p.args[p.argi]
		p.argi++
		return lit{v}, nil
	case tKeyword:
		if t.text == "NULL" {
			return lit{nil}, nil
		}
	case tSymbol:
		if t.text == "(" {
			e, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if !p.accept(tSymbol, ")") {
				return nil, p.syntaxErr()
			}
			return e, nil
		}
	}
	p.pos--
	return nil, p.syntaxErr()
}

type selectItem struct {
	star bool
	e    expr
	name string
}

func (p *parser) parseSelect() (*Result, error) {
	if !p.accept(tKeyword, "SELECT") {
		return nil, p.syntaxErr()
	}
	var items []selectItem
	for {
		if p.accept(tSymbol, "*") {
			items = append(items, selectItem{star: true})
		} else {
			start := p.peek()
			e, err := p.parseConcat()
			if err != nil {
				return nil, err
			}
			items = append(items, selectItem{e: e, name: start.text})
		}
		if !p.accept(tSymbol, ",") {
			break
		}
	}
	var table *Table
	if p.accept(tKeyword, "FROM") {
		t := p.next()
		if t.kind != tIdent {
			p.pos--
			return nil, p.syntaxErr()
		}
		var ok bool
		if table, ok = p.db.Tables[t.text]; !ok {
			return nil, fmt.Errorf("no such table: %s", t.text)
		}
	}
	var where expr
	if p.accept(tKeyword, "WHERE") {
		var err error
		if where, err = p.parseExpr(); err != nil {
			return nil, err
		}
	}
	res := &Result{}
	for _, it := range items {
		if it.star {
			if table == nil {
				return nil, fmt.Errorf("no tables specified")
			}
			res.Cols = append(res.Cols, table.Cols...)
		} else {
			res.Cols = append(res.Cols, it.name)
		}
	}
	rows := [][]Value{nil}
	var cols []string
	if table != nil {
		rows, cols = table.Rows, table.Cols
	}
	for _, raw := range rows {
		row := map[string]Value{}
		for i, c := range cols {
			row[c] = raw[i]
		}
		if where != nil {
			v, err := where.eval(row)
			if err != nil {
				return nil, err
			}
			if !truthy(v) {
				continue
			}
		}
		var out []Value
		for _, it := range items {
			if it.star {
				out = append(out, raw...)
				continue
			}
			v, err := it.e.eval(row)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		res.Rows = append(res.Rows, out)
	}
	return res, nil
}

// Query parses and runs q. Values in args bind to '?' placeholders.
func (db *DB) Query(q string, args ...Value) (*Result, error) {
	toks, err := lex(q)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, args: args, db: db}
	res, err := p.parseSelect()
	if err != nil {
		return nil, err
	}
	for p.accept(tKeyword, "UNION") {
		p.accept(tKeyword, "ALL")
		more, err := p.parseSelect()
		if err != nil {
			return nil, err
		}
		if len(more.Cols) != len(res.Cols) {
			return nil, fmt.Errorf("SELECTs to the left and right of UNION do not have the same number of result columns")
		}
		res.Rows = append(res.Rows, more.Rows...)
	}
	p.accept(tSymbol, ";")
	if p.peek().kind != tEOF {
		return nil, p.syntaxErr()
	}
	return res, nil
}
