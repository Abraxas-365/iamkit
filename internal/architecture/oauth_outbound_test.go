package architecture_test

// Two rules of the external-client (CIMD) work, as lints:
//
//   - Everything the OAuth module fetches from a host a stranger named (a
//     client's metadata document, a jwks_uri, a back-channel logout URI)
//     goes through a guarded http.Client: no default client, no shortcut
//     like http.Get, no Transport that can use a proxy or dial anything.
//   - A row of oauth_clients that is not "registered" is written only by the
//     functions that own external clients (document save, admission,
//     templates); every other statement is scoped to source='registered' in
//     its own SQL, so an operator route (PATCH/DELETE /oauth-clients/:id,
//     the portal) can never rewrite or disable a client named by a URL.
//
// The third rule — no cachememory/cacheredis use outside bootstrap — is
// TestCacheAdapters.

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// outboundScope is where OAuth code reaches operator/stranger-named hosts.
func outboundScope(rel string) bool {
	return rel == "oauth" || strings.HasPrefix(rel, "oauth/")
}

// httpShortcuts use http.DefaultClient underneath.
var httpShortcuts = map[string]bool{"Get": true, "Head": true, "Post": true, "PostForm": true, "DefaultClient": true, "DefaultTransport": true}

// httpName returns the local name of net/http in the file ("" if unused).
func httpName(f goFile) string {
	for _, spec := range f.file.Imports {
		if p, _ := strconv.Unquote(spec.Path.Value); p == "net/http" {
			if spec.Name != nil {
				return spec.Name.Name
			}
			return "http"
		}
	}
	return ""
}

func fieldKeys(lit *ast.CompositeLit) map[string]ast.Expr {
	keys := map[string]ast.Expr{}
	for _, el := range lit.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok {
				keys[id.Name] = kv.Value
			}
		}
	}
	return keys
}

// guardedClientViolations flags, in the OAuth module's non-test code, an
// outbound HTTP client that is not the guarded one.
func guardedClientViolations(files []goFile) []string {
	var out []string
	for _, f := range files {
		if !outboundScope(f.rel) {
			continue
		}
		pkg := httpName(f)
		if pkg == "" {
			continue
		}
		isHTTP := func(e ast.Expr, name string) bool {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != name {
				return false
			}
			id, ok := sel.X.(*ast.Ident)
			return ok && id.Name == pkg
		}
		at := func(p token.Pos) string { return fmt.Sprintf("%s:%d", f.rel, f.fset.Position(p).Line) }
		ast.Inspect(f.file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == pkg && httpShortcuts[x.Sel.Name] {
					out = append(out, fmt.Sprintf("%s: http.%s is the default client; build one on the guarded transport (netx.Guarded)", at(x.Pos()), x.Sel.Name))
				}
			case *ast.CallExpr:
				if fn, ok := x.Fun.(*ast.Ident); ok && fn.Name == "new" && len(x.Args) == 1 && (isHTTP(x.Args[0], "Client") || isHTTP(x.Args[0], "Transport")) {
					out = append(out, fmt.Sprintf("%s: new(http.Client/Transport) is unguarded; build one on the guarded transport", at(x.Pos())))
				}
			case *ast.CompositeLit:
				keys := fieldKeys(x)
				switch {
				case isHTTP(x.Type, "Client"):
					if _, ok := keys["Transport"]; !ok {
						out = append(out, fmt.Sprintf("%s: http.Client without a Transport uses the default one; set the guarded transport", at(x.Pos())))
					}
				case isHTTP(x.Type, "Transport"):
					if _, ok := keys["Proxy"]; ok {
						out = append(out, fmt.Sprintf("%s: http.Transport with a Proxy would send the request to whatever HTTP(S)_PROXY says; remove it", at(x.Pos())))
					}
					dial, ok := keys["DialContext"]
					if !ok || !references(&ast.BlockStmt{List: []ast.Stmt{&ast.ExprStmt{X: dial}}}, "GuardedDialer") {
						out = append(out, fmt.Sprintf("%s: http.Transport must dial through netx.GuardedDialer", at(x.Pos())))
					}
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

// externalWriters are the functions allowed to write rows of oauth_clients
// that are not 'registered' (and the registered templates admission owns).
// Keys are "<dir without iam/> <func>".
var externalWriters = map[string]bool{
	"oauth/adapters/oauthpg insertExternal":                    true,
	"oauth/adapters/oauthpg (*Repository).SaveExternalClient":  true,
	"oauth/adapters/oauthpg (*Repository).TouchExternal":       true,
	"oauth/adapters/oauthpg (*Repository).PruneExternal":       true,
	"oauth/adapters/oauthpg approveRow":                        true,
	"oauth/adapters/oauthpg demote":                            true,
	"oauth/adapters/oauthpg reconcilePolicy":                   true,
	"oauth/adapters/oauthpg (*Admission).BlockClient":          true,
	"oauth/adapters/oauthpg (*Admission).UnblockClient":        true,
	"oauth/adapters/oauthpg (*Admission).ForgetClient":         true,
	"oauth/adapters/oauthpg (*Admission).ExpireApprovals":      true,
	"oauth/adapters/oauthpg (*Admission).CreateTemplateClient": true,
}

var (
	clientWrite    = regexp.MustCompile(`(?is)\b(insert\s+into|update|delete\s+from)\s+oauth_clients\b`)
	insertsSource  = regexp.MustCompile(`(?is)insert\s+into\s+oauth_clients\s*\([^)]*\bsource\b`)
	scopedToUsers  = regexp.MustCompile(`(?i)\bsource\s*=\s*'registered'`)
	insertStatment = regexp.MustCompile(`(?is)^\s*insert\s+into\s+oauth_clients\b`)
)

// clientWriteViolations scans every SQL string literal of internal/ for a
// write to oauth_clients.
func clientWriteViolations(files []goFile, writers map[string]bool) []string {
	var out []string
	for _, f := range files {
		dir := dirOf(f.rel)
		for _, decl := range f.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := dir + " " + funcKey(fn)
			owner := writers[key]
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				sql, err := strconv.Unquote(lit.Value)
				if err != nil || !clientWrite.MatchString(sql) {
					return true
				}
				where := fmt.Sprintf("%s:%d", f.rel, f.fset.Position(lit.Pos()).Line)
				switch {
				case owner:
					// the external-client writers own these statements
				case insertStatment.MatchString(sql):
					// A registered client's insert leaves source to its
					// default; naming it makes the row external.
					if insertsSource.MatchString(sql) {
						out = append(out, fmt.Sprintf("%s: %s inserts a non-registered client; only the external-client writers may (externalWriters)", where, funcKey(fn)))
					}
				case !scopedToUsers.MatchString(sql):
					out = append(out, fmt.Sprintf("%s: %s changes oauth_clients without source='registered'; clients named by a URL are written only by the external-client writers (externalWriters)", where, funcKey(fn)))
				}
				return true
			})
		}
	}
	for key := range writers {
		seen := false
		for _, f := range files {
			for _, decl := range f.file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && dirOf(f.rel)+" "+funcKey(fn) == key {
					seen = true
				}
			}
		}
		if !seen {
			out = append(out, fmt.Sprintf("%s: function not found (update externalWriters when it moves)", key))
		}
	}
	sort.Strings(out)
	return out
}

func TestOAuthOutboundUsesGuardedClient(t *testing.T) {
	report(t, guardedClientViolations(sources(t, false)))
}

// clientDeleters are the functions that may lock oauth_clients rows FOR
// UPDATE: they delete them. Every other lock of a client row is FOR NO KEY
// UPDATE (a change of admission) or FOR SHARE (an authorization or token
// request reading it): FOR UPDATE also conflicts with the key-share lock
// the foreign key of a token insert takes, so a token request that holds a
// token row and an operator's block holding the client would deadlock
// (W4-1). Keys are "<dir without iam/> <func>".
var clientDeleters = map[string]bool{
	"oauth/adapters/oauthpg lockClientForDelete":                           true,
	"oauth/adapters/oauthpg (*Repository).PruneExternal":                   true,
	"oauth/adapters/oauthpg (*ProtectedResources).DeleteProtectedResource": true,
}

var (
	forUpdate = regexp.MustCompile(`(?is)\bfor\s+update\b(\s+of\s+([a-z_]+(?:\s*,\s*[a-z_]+)*))?`)
	fromTable = regexp.MustCompile(`(?is)\b(?:from|join)\s+(?:[a-z_]+\.)?([a-z_]+)(?:\s+(?:as\s+)?([a-z_]+))?`)
	bareLock  = regexp.MustCompile(`(?is)^\s*for\s+update\b`)
)

// sqlKeywords are words fromTable may read as an alias.
var sqlKeywords = map[string]bool{"where": true, "join": true, "on": true, "left": true, "inner": true, "using": true, "for": true, "order": true, "group": true, "limit": true, "set": true, "returning": true, "cross": true}

// locksClients reports whether sql has a FOR UPDATE on oauth_clients: with
// OF, a listed alias or table that is oauth_clients; without, any FROM/JOIN
// table before it (W6-1: conservative — FOR UPDATE locks every table of its
// SELECT, and a subquery read as part of it is a false positive to reword,
// not a miss). A lock clause kept apart from its statement counts too.
// Tables may carry a schema (public.oauth_clients).
func locksClients(sql string) bool {
	if bareLock.MatchString(sql) {
		return true
	}
	for _, at := range forUpdate.FindAllStringSubmatchIndex(sql, -1) {
		var of []string
		if at[4] >= 0 {
			for _, name := range strings.Split(sql[at[4]:at[5]], ",") {
				of = append(of, strings.TrimSpace(name))
			}
		}
		for _, t := range fromTable.FindAllStringSubmatch(sql[:at[0]], -1) {
			if !strings.EqualFold(t[1], "oauth_clients") {
				continue
			}
			if of == nil {
				return true
			}
			alias := t[2]
			if sqlKeywords[strings.ToLower(alias)] {
				alias = ""
			}
			for _, name := range of {
				if strings.EqualFold(name, alias) || strings.EqualFold(name, t[1]) {
					return true
				}
			}
		}
	}
	return false
}

// clientLockViolations scans the SQL string literals of the adapters (in
// function bodies and package-level constants and variables) for FOR
// UPDATE on oauth_clients outside clientDeleters.
func clientLockViolations(files []goFile, deleters map[string]bool) []string {
	var out []string
	for _, f := range files {
		dir := dirOf(f.rel)
		if !strings.Contains(dir, "/adapters/") {
			continue
		}
		check := func(owner string, node ast.Node) {
			// A lock clause kept apart from its statement counts only where
			// the statement is about oauth_clients (W5-2): elsewhere it
			// locks invitations, users...
			names := false
			ast.Inspect(node, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.Contains(strings.ToLower(lit.Value), "oauth_clients") {
					names = true
				}
				return true
			})
			ast.Inspect(node, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				sql, err := strconv.Unquote(lit.Value)
				if err != nil || !locksClients(sql) || (bareLock.MatchString(sql) && !names && !strings.HasPrefix(dir, "oauth/")) {
					return true
				}
				out = append(out, fmt.Sprintf("%s:%d: %s locks oauth_clients FOR UPDATE; use FOR NO KEY UPDATE unless it deletes the row (clientDeleters)", f.rel, f.fset.Position(lit.Pos()).Line, owner))
				return true
			})
		}
		for _, decl := range f.file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body != nil && !deleters[dir+" "+funcKey(d)] {
					check(funcKey(d), d.Body)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if v, ok := spec.(*ast.ValueSpec); ok && len(v.Names) > 0 && !deleters[dir+" "+v.Names[0].Name] {
						check(v.Names[0].Name, v)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestClientRowLocksLetTokenInsertsThrough(t *testing.T) {
	report(t, clientLockViolations(sources(t, false), clientDeleters))
}

func TestClientLockLintCatchesViolations(t *testing.T) {
	files := parseFixtures(t, map[string]string{
		"oauth/adapters/oauthpg/admission.go": "package oauthpg\n" +
			"func block() { get(`SELECT id FROM oauth_clients WHERE id=$1 FOR NO KEY UPDATE`) }\n" +
			"func bad() { get(`SELECT id FROM oauth_clients WHERE id=$1 FOR UPDATE`) }\n" +
			"func clause(wait bool) string { if wait { return `FOR UPDATE OF c` }; return `FOR NO KEY UPDATE OF c SKIP LOCKED` }\n" +
			"func lockClientForDelete() { get(`SELECT id FROM oauth_clients WHERE id=$1 FOR UPDATE`) }\n" +
			"func ticket() { get(`SELECT 1 FROM oauth_authorizations WHERE secret_hash=$1 FOR UPDATE`) }\n" +
			"func claim() { get(`WITH due AS (SELECT id FROM logouts FOR UPDATE SKIP LOCKED) UPDATE logouts SET x=1 RETURNING (SELECT uri FROM oauth_clients)`) }\n" +
			"func joined() { get(`SELECT c.id FROM oauth_clients c JOIN x ON true FOR UPDATE OF c`) }\n" +
			"const lockQuery = `SELECT id FROM oauth_clients WHERE id=$1 FOR UPDATE`\n" +
			"func schema() { get(`SELECT id FROM public.oauth_clients WHERE id=$1 FOR UPDATE`) }\n" +
			"func server() { get(`SELECT pr.id FROM oauth_clients c JOIN protected_resources pr ON pr.id=c.protected_resource_id FOR UPDATE OF pr`) }\n" +
			"func subquery() { get(`SELECT c.id FROM oauth_clients c WHERE c.id IN (SELECT client_id FROM oauth_requests) FOR UPDATE OF c`) }\n" +
			"func notLast() { get(`SELECT c.id FROM oauth_clients c JOIN sessions s ON s.oauth_client_id=c.id FOR UPDATE`) }\n" +
			"func list() { get(`SELECT c.id FROM oauth_clients c JOIN protected_resources pr ON true FOR UPDATE OF pr, c`) }\n" +
			"func listOther() { get(`SELECT c.id FROM oauth_clients c JOIN protected_resources pr ON true JOIN sessions s ON true FOR UPDATE OF pr, s`) }\n",
		"billing/adapters/billingpg/x.go": "package billingpg\n" +
			"func other() { get(`SELECT id FROM oauth_clients FOR UPDATE`) }\n" +
			"func users(lock bool) { s := ``; if lock { s = ` FOR UPDATE` }; get(`SELECT id FROM users`+s) }\n" +
			"func portal(lock bool) { s := `SELECT id FROM oauth_clients WHERE system=$1`; if lock { s += ` FOR UPDATE` }; get(s) }\n",
		"billing/billingsvc/x.go": "package billingsvc\n" +
			"func notAdapter() { get(`SELECT id FROM oauth_clients FOR UPDATE`) }\n",
	})
	expectViolations(t, clientLockViolations(files, map[string]bool{"oauth/adapters/oauthpg lockClientForDelete": true}),
		"billing/adapters/billingpg/x.go:2: other locks oauth_clients FOR UPDATE",
		"billing/adapters/billingpg/x.go:4: portal locks oauth_clients FOR UPDATE",
		"oauth/adapters/oauthpg/admission.go:10: schema locks oauth_clients FOR UPDATE",
		"oauth/adapters/oauthpg/admission.go:12: subquery locks oauth_clients FOR UPDATE",
		"oauth/adapters/oauthpg/admission.go:3: bad locks oauth_clients FOR UPDATE",
		"oauth/adapters/oauthpg/admission.go:4: clause locks oauth_clients FOR UPDATE",
		"oauth/adapters/oauthpg/admission.go:8: joined locks oauth_clients FOR UPDATE",
		"oauth/adapters/oauthpg/admission.go:13: notLast locks oauth_clients FOR UPDATE",
		"oauth/adapters/oauthpg/admission.go:14: list locks oauth_clients FOR UPDATE",
		"oauth/adapters/oauthpg/admission.go:9: lockQuery locks oauth_clients FOR UPDATE",
	)
}

func TestExternalClientRowsHaveOneWriter(t *testing.T) {
	report(t, clientWriteViolations(sources(t, false), externalWriters))
}

func TestOutboundAndWriterLintsCatchViolations(t *testing.T) {
	files := parseFixtures(t, map[string]string{
		"oauth/adapters/oauthcimd/good.go": `package oauthcimd
import ("net/http"; "x/netx")
func ok(t http.RoundTripper) *http.Client { return &http.Client{Transport: t} }
func guarded() *http.Transport { return &http.Transport{DialContext: netx.GuardedDialer().DialContext} }
`,
		"oauth/adapters/oauthcimd/bad.go": `package oauthcimd
import "net/http"
func a() { http.Get("https://x") }
func b() *http.Client { return &http.Client{} }
func c() *http.Client { return http.DefaultClient }
func d() *http.Transport { return &http.Transport{Proxy: http.ProxyFromEnvironment} }
func e() *http.Transport { return &http.Transport{} }
func f() *http.Client { return new(http.Client) }
`,
		"billing/adapters/billinghttp/other.go": `package billinghttp
import "net/http"
func other() { http.Get("https://x") }
`,
	})
	expectViolations(t, guardedClientViolations(files),
		"oauth/adapters/oauthcimd/bad.go:3: http.Get is the default client",
		"oauth/adapters/oauthcimd/bad.go:4: http.Client without a Transport",
		"oauth/adapters/oauthcimd/bad.go:5: http.DefaultClient is the default client",
		"oauth/adapters/oauthcimd/bad.go:6: http.Transport with a Proxy",
		"oauth/adapters/oauthcimd/bad.go:6: http.Transport must dial through netx.GuardedDialer",
		"oauth/adapters/oauthcimd/bad.go:7: http.Transport must dial through netx.GuardedDialer",
		"oauth/adapters/oauthcimd/bad.go:8: new(http.Client/Transport) is unguarded",
	)

	sqlFiles := parseFixtures(t, map[string]string{
		"oauth/adapters/oauthpg/ext.go": "package oauthpg\n" +
			"func (r *Repository) SaveExternalClient() { exec(`INSERT INTO oauth_clients(id,source) VALUES($1,'cimd')`); exec(`UPDATE oauth_clients SET x=1 WHERE id=$1`) }\n",
		"oauth/adapters/oauthpg/control.go": "package oauthpg\n" +
			"func (r *Repository) Update() { exec(`UPDATE oauth_clients SET x=1 WHERE id=$1 AND source='registered'`) }\n" +
			"func (r *Repository) Create() { exec(`INSERT INTO oauth_clients(id,redirect_uris) VALUES($1,$2)`) }\n" +
			"func (r *Repository) Disable() { exec(`UPDATE oauth_clients SET active=false WHERE id=$1`) }\n" +
			"func (r *Repository) Purge() { exec(\"DELETE FROM oauth_clients WHERE id=$1\") }\n" +
			"func (r *Repository) Sneak() { exec(`INSERT INTO oauth_clients(id,source,external_id) VALUES($1,'cimd',$2)`) }\n",
	})
	expectViolations(t, clientWriteViolations(sqlFiles, map[string]bool{
		"oauth/adapters/oauthpg (*Repository).SaveExternalClient": true,
		"oauth/adapters/oauthpg (*Repository).Gone":               true,
	}),
		"oauth/adapters/oauthpg/control.go:4: (*Repository).Disable changes oauth_clients without source='registered'",
		"oauth/adapters/oauthpg/control.go:5: (*Repository).Purge changes oauth_clients without source='registered'",
		"oauth/adapters/oauthpg/control.go:6: (*Repository).Sneak inserts a non-registered client",
		"oauth/adapters/oauthpg (*Repository).Gone: function not found",
	)
}

// registrationWriters are the functions that may write oauth_registrations
// (D25/D26): a dynamic registration is inserted once, marked used when a
// client row is written from it, and pruned. Nothing else changes it — it
// is immutable (no RFC 7592), so an UPDATE may set last_used_at only. Keys
// are "<dir without iam/> <func>".
var registrationWriters = map[string]bool{
	"oauth/adapters/oauthpg (*Repository).SaveRegistration":   true,
	"oauth/adapters/oauthpg markRegistrationUsed":             true,
	"oauth/adapters/oauthpg (*Repository).PruneRegistrations": true,
}

var (
	registrationWrite  = regexp.MustCompile(`(?is)\b(insert\s+into|update|delete\s+from)\s+oauth_registrations\b`)
	registrationUpdate = regexp.MustCompile(`(?is)\bupdate\s+oauth_registrations\s+set\s+(.*?)(\bwhere\b|$)`)
	onlyLastUsed       = regexp.MustCompile(`(?is)^\s*last_used_at\s*=\s*[^,]+$`)
)

func registrationWriteViolations(files []goFile, writers map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range files {
		dir := dirOf(f.rel)
		for _, decl := range f.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := dir + " " + funcKey(fn)
			seen[key] = true
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				sql, err := strconv.Unquote(lit.Value)
				if err != nil || !registrationWrite.MatchString(sql) {
					return true
				}
				where := fmt.Sprintf("%s:%d", f.rel, f.fset.Position(lit.Pos()).Line)
				if !writers[key] {
					out = append(out, fmt.Sprintf("%s: %s writes oauth_registrations; only the registration writers may (registrationWriters)", where, funcKey(fn)))
					return true
				}
				if m := registrationUpdate.FindStringSubmatch(sql); m != nil && !onlyLastUsed.MatchString(m[1]) {
					out = append(out, fmt.Sprintf("%s: %s changes a registration beyond last_used_at; registrations are immutable", where, funcKey(fn)))
				}
				return true
			})
		}
	}
	for key := range writers {
		if !seen[key] {
			out = append(out, fmt.Sprintf("%s: function not found (update registrationWriters when it moves)", key))
		}
	}
	sort.Strings(out)
	return out
}

func TestDynamicRegistrationsHaveOneWriter(t *testing.T) {
	report(t, registrationWriteViolations(sources(t, false), registrationWriters))
}

func TestRegistrationLintCatchesViolations(t *testing.T) {
	files := parseFixtures(t, map[string]string{
		"oauth/adapters/oauthpg/registration.go": "package oauthpg\n" +
			"func (r *Repository) SaveRegistration() { exec(`INSERT INTO oauth_registrations(client_id) VALUES($1)`) }\n" +
			"func markRegistrationUsed() { exec(`UPDATE oauth_registrations SET last_used_at=now() WHERE client_id=$1`) }\n" +
			"func (r *Repository) PruneRegistrations() { exec(`UPDATE oauth_registrations SET client_name=$2 WHERE client_id=$1`) }\n" +
			"func (r *Repository) Rename() { exec(`UPDATE oauth_registrations SET client_name=$2 WHERE client_id=$1`) }\n" +
			"func (r *Repository) Find() { get(`SELECT client_id FROM oauth_registrations WHERE client_id=$1`) }\n",
		"billing/adapters/billingpg/x.go": "package billingpg\n" +
			"func purge() { exec(`DELETE FROM oauth_registrations`) }\n",
	})
	expectViolations(t, registrationWriteViolations(files, map[string]bool{
		"oauth/adapters/oauthpg (*Repository).SaveRegistration":   true,
		"oauth/adapters/oauthpg markRegistrationUsed":             true,
		"oauth/adapters/oauthpg (*Repository).PruneRegistrations": true,
		"oauth/adapters/oauthpg (*Repository).Gone":               true,
	}),
		"billing/adapters/billingpg/x.go:2: purge writes oauth_registrations",
		"oauth/adapters/oauthpg (*Repository).Gone: function not found",
		"oauth/adapters/oauthpg/registration.go:4: (*Repository).PruneRegistrations changes a registration beyond last_used_at",
		"oauth/adapters/oauthpg/registration.go:5: (*Repository).Rename writes oauth_registrations",
	)
}

// networkBeforeTx is M-5 as a lint: the OAuth flows resolve an external
// client (a network read of its document, a write of its row) before the
// authorization transaction opens, never inside it. Complete may call these
// only before its repository Begin, and the closure handed to Complete (it
// runs inside the transaction) may not call them at all.
var resolvers = map[string]bool{"TicketClient": true, "resolve": true, "ExternalClient": true, "RequestAccess": true, "Document": true}

func transactionViolations(files []goFile) []string {
	var out []string
	for _, f := range files {
		dir := dirOf(f.rel)
		if !outboundScope(strings.TrimPrefix(dir, "")) {
			continue
		}
		for _, decl := range f.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// Complete itself: resolution calls must precede Begin.
			if fn.Name.Name == "Complete" && strings.HasSuffix(dir, "oauthsvc") {
				begin := token.NoPos
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Begin" && begin == token.NoPos {
							begin = call.Pos()
						}
					}
					return true
				})
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok && resolvers[sel.Sel.Name] && begin != token.NoPos && call.Pos() > begin {
							out = append(out, fmt.Sprintf("%s:%d: %s calls %s after Begin; resolve the client before the transaction opens (M-5)", f.rel, f.fset.Position(call.Pos()).Line, funcKey(fn), sel.Sel.Name))
						}
					}
					return true
				})
			}
			// The closure handed to Complete runs inside the transaction.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Complete" {
					return true
				}
				for _, arg := range call.Args {
					lit, ok := arg.(*ast.FuncLit)
					if !ok {
						continue
					}
					ast.Inspect(lit.Body, func(m ast.Node) bool {
						if inner, ok := m.(*ast.CallExpr); ok {
							if s, ok := inner.Fun.(*ast.SelectorExpr); ok && resolvers[s.Sel.Name] {
								out = append(out, fmt.Sprintf("%s:%d: %s calls %s inside the closure of Complete, which runs in the transaction (M-5)", f.rel, f.fset.Position(inner.Pos()).Line, funcKey(fn), s.Sel.Name))
							}
						}
						return true
					})
				}
				return true
			})
		}
	}
	sort.Strings(out)
	return out
}

func TestOAuthResolvesClientsBeforeTheTransaction(t *testing.T) {
	files := sources(t, false)
	report(t, transactionViolations(files))
	// The rule has something to check: Complete exists in oauthsvc.
	found := false
	for _, f := range files {
		for _, decl := range f.file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "Complete" && strings.HasSuffix(dirOf(f.rel), "oauthsvc") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("oauthsvc.Complete not found (update the rule when it moves)")
	}
}

func TestTransactionLintCatchesViolations(t *testing.T) {
	files := parseFixtures(t, map[string]string{
		"oauth/oauthsvc/ok.go": `package oauthsvc
func (s *Service) Complete() { s.TicketClient(); tx, _ := s.repository.Begin(); _ = tx }
`,
		"oauth/oauthsvc/bad.go": `package oauthsvc
func (s *Service) Complete() { tx, _ := s.repository.Begin(); s.TicketClient(); s.documents.Document(); _ = tx }
`,
		"oauth/adapters/oauthhttp/h.go": `package oauthhttp
func (h *Handler) finish() { h.flows.Complete(func() { h.flows.RequestAccess() }) }
func (h *Handler) fine() { h.flows.RequestAccess(); h.flows.Complete(func() { x() }) }
`,
	})
	expectViolations(t, transactionViolations(files),
		"oauth/adapters/oauthhttp/h.go:2: (*Handler).finish calls RequestAccess inside the closure of Complete",
		"oauth/oauthsvc/bad.go:2: (*Service).Complete calls Document after Begin",
		"oauth/oauthsvc/bad.go:2: (*Service).Complete calls TicketClient after Begin",
	)
}
