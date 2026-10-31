package architecture_test

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/event"
)

// The retention class of an event is fixed when it is inserted, by the
// trigger set_event_retention_class calling the SQL function
// event_retention_class(type). The Go catalog (event.SecurityFamilies,
// event.SecurityTypes) is the source of truth; the function in the latest
// migration that defines it must list exactly the same families and types
// (D39), so the two cannot drift apart.
var (
	retentionFunction = regexp.MustCompile(`(?is)create\s+(?:or\s+replace\s+)?function\s+event_retention_class\s*\(.*?\$\$(.*?)\$\$`)
	retentionFamilies = regexp.MustCompile(`(?is)split_part\s*\(\s*t\s*,\s*'\.'\s*,\s*1\s*\)\s+in\s*\(([^)]*)\)`)
	retentionTypes    = regexp.MustCompile(`(?is)\bt\s+in\s*\(([^)]*)\)`)
	quoted            = regexp.MustCompile(`'([^']*)'`)
)

func quotedList(s string) []string {
	var out []string
	for _, m := range quoted.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

// retentionClassViolations compares the migrations' definition of
// event_retention_class (files are name → SQL; the last name defining it
// wins) with the Go lists.
func retentionClassViolations(migrations map[string]string, families, types []string) []string {
	names := make([]string, 0, len(migrations))
	for name := range migrations {
		names = append(names, name)
	}
	sort.Strings(names)
	var body, from string
	for _, name := range names {
		if m := retentionFunction.FindStringSubmatch(migrations[name]); m != nil {
			body, from = m[1], name
		}
	}
	if from == "" {
		return []string{"no migration defines the SQL function event_retention_class"}
	}
	var out []string
	check := func(what string, re *regexp.Regexp, want []string) {
		m := re.FindStringSubmatch(body)
		if m == nil {
			out = append(out, fmt.Sprintf("%s: event_retention_class lists no %s", from, what))
			return
		}
		got, want := quotedList(m[1]), slices.Sorted(slices.Values(want))
		if !slices.Equal(got, want) {
			out = append(out, fmt.Sprintf("%s: event_retention_class %s %v differ from the Go catalog %v", from, what, got, want))
		}
	}
	check("security families", retentionFamilies, families)
	// The type list is the second `t IN (…)`: the first match is the one inside split_part( t …).
	typeLists := retentionTypes.FindAllStringSubmatch(retentionFamilies.ReplaceAllString(body, ""), -1)
	if len(typeLists) != 1 {
		out = append(out, fmt.Sprintf("%s: event_retention_class must list security types in one `t IN (…)`", from))
	} else if got, want := quotedList(typeLists[0][1]), slices.Sorted(slices.Values(types)); !slices.Equal(got, want) {
		out = append(out, fmt.Sprintf("%s: event_retention_class security types %v differ from the Go catalog %v", from, got, want))
	}
	return out
}

func readMigrations(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("../../migrations/*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations: %v (%d files)", err, len(files))
	}
	out := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(f)] = string(b)
	}
	return out
}

func TestEventRetentionClassMatchesCatalog(t *testing.T) {
	report(t, retentionClassViolations(readMigrations(t), event.SecurityFamilies, event.SecurityTypes))
	// The trigger that applies the function is part of the contract.
	all := ""
	for _, sql := range readMigrations(t) {
		all += sql
	}
	if !strings.Contains(all, "CREATE TRIGGER event_retention_class BEFORE INSERT ON events") {
		t.Error("no migration creates the BEFORE INSERT trigger event_retention_class on events")
	}
}

func TestRetentionClassOfFollowsTheLists(t *testing.T) {
	for _, family := range event.SecurityFamilies {
		if got := event.RetentionClassOf(family + ".anything"); got != event.ClassSecurity {
			t.Errorf("%s.anything = %s", family, got)
		}
	}
	for _, typ := range event.SecurityTypes {
		if got := event.RetentionClassOf(typ); got != event.ClassSecurity {
			t.Errorf("%s = %s", typ, got)
		}
	}
	for _, typ := range []string{event.UserCreated, event.UserUpdated, event.WebhookCreated, event.LimitsUpdated, "sessions.created", "user_session.x"} {
		if got := event.RetentionClassOf(typ); got != event.ClassDefault {
			t.Errorf("%s = %s", typ, got)
		}
	}
}

func TestRetentionLintCatchesDrift(t *testing.T) {
	define := func(families, types string) string {
		return "CREATE FUNCTION event_retention_class(t text) RETURNS text LANGUAGE sql IMMUTABLE AS $$\n" +
			"SELECT CASE WHEN split_part(t, '.', 1) IN (" + families + ") OR t IN (" + types + ") THEN 'security' ELSE 'default' END\n$$;"
	}
	families, types := []string{"session", "mfa"}, []string{"user.locked"}
	good := map[string]string{"001.up.sql": define(`'mfa', 'session'`, `'user.locked'`)}
	expectViolations(t, retentionClassViolations(good, families, types))

	expectViolations(t, retentionClassViolations(map[string]string{
		"001.up.sql": define(`'mfa'`, `'user.locked'`),
	}, families, types), "001.up.sql: event_retention_class security families [mfa] differ from the Go catalog [mfa session]")

	expectViolations(t, retentionClassViolations(map[string]string{
		"001.up.sql": define(`'mfa', 'session'`, `'user.locked'`),
		"002.up.sql": "CREATE OR REPLACE FUNCTION event_retention_class(t text) RETURNS text AS $$\n" +
			"SELECT CASE WHEN split_part(t, '.', 1) IN ('mfa', 'session', 'token') OR t IN ('user.locked', 'user.unlocked') THEN 'security' ELSE 'default' END\n$$ LANGUAGE sql;",
	}, families, types),
		"002.up.sql: event_retention_class security families [mfa session token] differ from the Go catalog [mfa session]",
		"002.up.sql: event_retention_class security types [user.locked user.unlocked] differ from the Go catalog [user.locked]")

	expectViolations(t, retentionClassViolations(map[string]string{"001.up.sql": "SELECT 1;"}, families, types),
		"no migration defines the SQL function event_retention_class")
}

// retention_class is set by the trigger from the catalog; no statement
// names it when inserting events, so a writer cannot file an event under
// another class (and the class is never derived by a pattern at delete time:
// pruning compares the stored column).
var insertsRetentionClass = regexp.MustCompile(`(?is)\binsert\s+into\s+events\s*\([^)]*\bretention_class\b`)

func eventClassWriteViolations(files []goFile) []string {
	var out []string
	for _, f := range files {
		for _, decl := range f.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if sql, err := strconv.Unquote(lit.Value); err == nil && insertsRetentionClass.MatchString(sql) {
					out = append(out, fmt.Sprintf("%s:%d: %s sets events.retention_class; the trigger event_retention_class does", f.rel, f.fset.Position(lit.Pos()).Line, funcKey(fn)))
				}
				return true
			})
		}
	}
	sort.Strings(out)
	return out
}

func TestEventsNeverSetTheirRetentionClass(t *testing.T) {
	report(t, eventClassWriteViolations(sources(t, false)))
}

func TestEventClassLintCatchesViolations(t *testing.T) {
	files := parseFixtures(t, map[string]string{
		"iam/x/adapters/xpg/x.go": "package xpg\n" +
			"func ok() { exec(`INSERT INTO events(environment_id,type) VALUES($1,$2)`) }\n" +
			"func bad() { exec(`INSERT INTO events (environment_id, type, retention_class) VALUES($1,$2,'default')`) }\n",
	})
	expectViolations(t, eventClassWriteViolations(files),
		"iam/x/adapters/xpg/x.go:3: bad sets events.retention_class; the trigger event_retention_class does")
}
