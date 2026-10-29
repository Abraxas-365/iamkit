package architecture_test

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"testing"
)

// delegatedGrants are the functions that issue tokens without the user at
// the keyboard or on someone else's behalf: token exchange (resource and
// impersonation), client_credentials, the RFC 7523 jwt-bearer grant and the
// device grant. Each must keep clients named by a Client ID Metadata
// Document out (D16, D18), either by refusing the client
// (oauth.Client.Delegable) or by never letting a URL client_id reach it
// (oauth.ExternalClientID, checked by the token dispatcher that calls them).
// The database holds the same line (oauth_clients_external_check). Keys
// are "<dir relative to internal/, without iam/> <func>"; values the
// identifier the function must reference. client_credentials, the device
// grant, jwt-bearer and impersonation are reached only through the token
// dispatcher.
var delegatedGrants = map[string]string{
	"oauth/oauthsvc (*Service).ExchangeResource": "Delegable",
	"oauth/adapters/oauthhttp (*Handler).token":  "ExternalClientID",
}

// admissionChecks are the places a token of an external client is used or
// refreshed. Each must reference Admitted, so blocking a client or the end
// of its approval stops its tokens at once, whether or not the eager
// revocation (BlockClient, the client_admission_expire job) has run (M3).
// Same key format as delegatedGrants.
var admissionChecks = map[string]string{
	"oauth/adapters/oauthhttp (*Handler).liveIntrospection": "Admitted",
	"oauth/adapters/oauthhttp (*Handler).opaqueToken":       "Admitted",
	"oauth/adapters/oauthhttp (*Handler).finish":            "Admitted",
	"oauth/adapters/oauthhttp (*Handler).token":             "Admitted",
}

// externalClientViolations checks rules (see delegatedGrants) and that
// every listed function still exists.
func externalClientViolations(files []goFile, rules map[string]string) []string {
	return ruleViolations(files, rules, "clients named by a metadata document never use delegated grants")
}

// admissionViolations checks admissionChecks.
func admissionViolations(files []goFile, rules map[string]string) []string {
	return ruleViolations(files, rules, "tokens of external clients must stop when IT blocks them or their approval ends")
}

func ruleViolations(files []goFile, rules map[string]string, why string) []string {
	found := map[string]bool{}
	var out []string
	for _, f := range files {
		dir := dirOf(f.rel)
		for _, decl := range f.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := dir + " " + funcKey(fn)
			want, listed := rules[key]
			if !listed {
				continue
			}
			found[key] = true
			if !references(fn.Body, want) {
				out = append(out, fmt.Sprintf("%s: %s must reference %s (%s)", f.rel, funcKey(fn), want, why))
			}
		}
	}
	for key := range rules {
		if !found[key] {
			out = append(out, fmt.Sprintf("%s: function not found (update delegatedGrants when it moves)", key))
		}
	}
	sort.Strings(out)
	return out
}

func dirOf(rel string) string {
	for i := len(rel) - 1; i >= 0; i-- {
		if rel[i] == '/' {
			return rel[:i]
		}
	}
	return ""
}

func funcKey(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	switch t := fn.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return "(*" + id.Name + ")." + fn.Name.Name
		}
	case *ast.Ident:
		return "(" + t.Name + ")." + fn.Name.Name
	}
	return fn.Name.Name
}

// references reports whether body names ident (as a selector or an
// identifier).
func references(body *ast.BlockStmt, ident string) bool {
	hit := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if x.Sel.Name == ident {
				hit = true
			}
		case *ast.Ident:
			if x.Name == ident {
				hit = true
			}
		}
		return !hit
	})
	return hit
}

// TestExternalClientsNotDelegable: see delegatedGrants.
func TestExternalClientsNotDelegable(t *testing.T) {
	report(t, externalClientViolations(sources(t, false), delegatedGrants))
}

// TestExternalClientTokensStopWhenNotAdmitted: see admissionChecks.
func TestExternalClientTokensStopWhenNotAdmitted(t *testing.T) {
	report(t, admissionViolations(sources(t, false), admissionChecks))
}

func TestExternalClientLintCatchesViolations(t *testing.T) {
	files := parseFixtures(t, map[string]string{
		"iam/widget/widgetsvc/exchange.go": `package widgetsvc
func (s *Service) Exchange(c *Client) error { return nil }
func (s *Service) Guarded(c *Client) error { return c.Delegable() }
`,
	})
	expectViolations(t, externalClientViolations(files, map[string]string{
		"iam/widget/widgetsvc (*Service).Exchange": "Delegable",
		"iam/widget/widgetsvc (*Service).Guarded":  "Delegable",
		"iam/widget/widgetsvc (*Service).Missing":  "Delegable",
	}),
		"iam/widget/widgetsvc/exchange.go: (*Service).Exchange must reference Delegable",
		"iam/widget/widgetsvc (*Service).Missing: function not found",
	)
}

// lookupSources are the client lookups that decide which kind of client a
// presented client_id may name (H-1). A registered client is named by its
// row uuid, a client named by a metadata document by its URL; the uuid of a
// document client must never work as a client_id, or the guards that only a
// URL client_id meets (the grant allowlist of the token endpoint, the
// allow_client_metadata and feature checks of authorize) are skipped.
// Each function must reference the identifier shown.
var lookupSources = map[string]string{
	"oauth/adapters/oauthpg (*Repository).FindActive":   "SourceRegistered",
	"oauth/adapters/oauthpg (*Repository).FindExternal": "SourceCIMD",
}

// sourceFiltered are the SQL-bearing lookups whose statement must filter by
// c.source, so a caller cannot pick the wrong kind.
var sourceFiltered = map[string]bool{
	"oauth/adapters/oauthpg (*Repository).findClient": true,
}

// idForbidden are functions that turn a client_id into a client and must
// not accept the row uuid of the bound client (the identifier is the
// uuid field).
var idForbidden = map[string]string{
	"oauth/adapters/oauthfosite (*Store).Client": "ID",
}

var sourceFilter = regexp.MustCompile(`(?i)\bc\.source\s*=`)

// lookupViolations checks the three rules above.
func lookupViolations(files []goFile, rules map[string]string, filtered map[string]bool, forbidden map[string]string) []string {
	out := ruleViolations(files, rules, "the uuid of a document client is not a client_id (H-1)")
	found := map[string]bool{}
	for _, f := range files {
		dir := dirOf(f.rel)
		for _, decl := range f.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := dir + " " + funcKey(fn)
			if filtered[key] {
				found[key] = true
				hit := false
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if sql, err := strconv.Unquote(lit.Value); err == nil && sourceFilter.MatchString(sql) {
							hit = true
						}
					}
					return true
				})
				if !hit {
					out = append(out, fmt.Sprintf("%s: %s must filter its statement by c.source (H-1)", f.rel, funcKey(fn)))
				}
			}
			if ident, ok := forbidden[key]; ok {
				found[key] = true
				if references(fn.Body, ident) {
					out = append(out, fmt.Sprintf("%s: %s must not reference %s: the row uuid of a document client is not a client_id (H-1)", f.rel, funcKey(fn), ident))
				}
			}
		}
	}
	for key := range filtered {
		if !found[key] {
			out = append(out, fmt.Sprintf("%s: function not found (update sourceFiltered when it moves)", key))
		}
	}
	for key := range forbidden {
		if !found[key] {
			out = append(out, fmt.Sprintf("%s: function not found (update idForbidden when it moves)", key))
		}
	}
	sort.Strings(out)
	return out
}

// TestClientLookupsFilterBySource: see lookupSources.
func TestClientLookupsFilterBySource(t *testing.T) {
	report(t, lookupViolations(sources(t, false), lookupSources, sourceFiltered, idForbidden))
}

func TestClientLookupLintCatchesViolations(t *testing.T) {
	files := parseFixtures(t, map[string]string{
		"iam/widget/widgetpg/find.go": "package widgetpg\n" +
			"func (r *Repo) Good() { q(`SELECT 1 FROM oauth_clients c WHERE c.source=$3`) }\n" +
			"func (r *Repo) Bad() { q(`SELECT 1 FROM oauth_clients c WHERE c.id=$1`) }\n" +
			"func (s *Store) Client() string { return s.Bound.ID.String() }\n" +
			"func (s *Store) Fine() string { return s.Bound.PublicID() }\n",
	})
	expectViolations(t, lookupViolations(files,
		map[string]string{"iam/widget/widgetpg (*Repo).Good": "SourceRegistered"},
		map[string]bool{"iam/widget/widgetpg (*Repo).Good": true, "iam/widget/widgetpg (*Repo).Bad": true, "iam/widget/widgetpg (*Repo).Gone": true},
		map[string]string{"iam/widget/widgetpg (*Store).Client": "ID", "iam/widget/widgetpg (*Store).Fine": "ID"}),
		"iam/widget/widgetpg/find.go: (*Repo).Bad must filter its statement by c.source",
		"iam/widget/widgetpg/find.go: (*Repo).Good must reference SourceRegistered",
		"iam/widget/widgetpg/find.go: (*Store).Client must not reference ID",
		"iam/widget/widgetpg (*Repo).Gone: function not found",
	)
}
