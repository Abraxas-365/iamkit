package e2e_test

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// rowGate holds row locks in a transaction of its own until it opens:
// requests that need those rows queue behind it, so a test lines up
// concurrent requests in a known order instead of guessing timings.
type rowGate struct {
	e  *Env
	tx *sqlx.Tx
}

// holdRows locks the rows query selects (it must end in a locking clause)
// and fails the test when it selects none.
func (e *Env) holdRows(query string, args ...any) *rowGate {
	e.t.Helper()
	tx, err := e.DB.Beginx()
	if err != nil {
		e.t.Fatal(err)
	}
	var rows []int
	if err = tx.Select(&rows, query, args...); err != nil || len(rows) == 0 {
		tx.Rollback()
		e.t.Fatalf("gate %q: %d rows, %v", query, len(rows), err)
	}
	g := &rowGate{e: e, tx: tx}
	e.t.Cleanup(func() { tx.Rollback() })
	return g
}

func (g *rowGate) open() {
	g.e.t.Helper()
	if err := g.tx.Commit(); err != nil {
		g.e.t.Fatal(err)
	}
}

// waitLocked waits until at least n statements of the test's database wait
// for a lock: the requests started so far have reached the gate.
func (e *Env) waitLocked(n int) {
	e.t.Helper()
	e.waitFor("statements waiting for a lock", func() bool { return e.locked("") >= n })
}

// locked counts the statements of the test's database waiting for a lock
// whose text contains like (any when empty).
func (e *Env) locked(like string) int {
	e.t.Helper()
	var got int
	if err := e.DB.Get(&got, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%'||$1||'%'`, like); err != nil {
		e.t.Fatal(err)
	}
	return got
}

// waitFor polls ok until it holds (90 s at most).
func (e *Env) waitFor(what string, ok func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			e.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// tokenTry posts a token request from any goroutine (no t.Fatal) and waits
// as long as the request does.
func (e *Env) tokenTry(form url.Values) (int, map[string]any) {
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := e.App.Test(req, -1)
	if err != nil {
		return 0, map[string]any{"error": err.Error()}
	}
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}
