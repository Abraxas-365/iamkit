package architecture_test

import (
	"fmt"
	"go/ast"
	"sort"
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

// externalClientViolations checks rules (see delegatedGrants) and that
// every listed function still exists.
func externalClientViolations(files []goFile, rules map[string]string) []string {
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
				out = append(out, fmt.Sprintf("%s: %s must reference %s (clients named by a metadata document never use delegated grants)", f.rel, funcKey(fn), want))
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
