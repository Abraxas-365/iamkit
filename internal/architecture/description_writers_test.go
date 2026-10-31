package architecture_test

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

// descriptionWriters are the functions that may write permission_descriptions
// (D40): ReplaceDescriptions swaps a resource's whole set under a lock on
// the resource row (so it is checked against the catalog it keeps) and
// UpdateCatalog deletes the descriptions of the permissions it removes, in
// the catalog's transaction. Every statement they run is limited to one
// resource (resource_id = …), so no writer can touch another resource's
// texts. Keys are "<dir without iam/> <func>".
var descriptionWriters = map[string]bool{
	"authorization/adapters/authzpg (*Repository).ReplaceDescriptions": true,
	"authorization/adapters/authzpg (*Repository).UpdateCatalog":       true,
}

var (
	descriptionWrite = regexp.MustCompile(`(?is)\b(insert\s+into|update|delete\s+from)\s+permission_descriptions\b`)
	descriptionScope = regexp.MustCompile(`(?is)\bresource_id\s*=\s*\$\d`)
)

func descriptionWriteViolations(files []goFile, writers map[string]bool) []string {
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
				if err != nil || !descriptionWrite.MatchString(sql) {
					return true
				}
				where := fmt.Sprintf("%s:%d", f.rel, f.fset.Position(lit.Pos()).Line)
				switch {
				case !writers[key]:
					out = append(out, fmt.Sprintf("%s: %s writes permission_descriptions; only the description writers may (descriptionWriters)", where, funcKey(fn)))
				case strings.HasPrefix(strings.ToLower(strings.TrimSpace(sql)), "insert"):
					// Inserts carry their resource in the values.
				case !descriptionScope.MatchString(sql):
					out = append(out, fmt.Sprintf("%s: %s changes permission_descriptions beyond one resource (WHERE resource_id=$n)", where, funcKey(fn)))
				}
				return true
			})
		}
	}
	for key := range writers {
		if !seen[key] {
			out = append(out, fmt.Sprintf("%s: function not found (update descriptionWriters when it moves)", key))
		}
	}
	sort.Strings(out)
	return out
}

func TestPermissionDescriptionsHaveTwoWriters(t *testing.T) {
	report(t, descriptionWriteViolations(sources(t, false), descriptionWriters))
}

func TestDescriptionWriterLintCatchesViolations(t *testing.T) {
	files := parseFixtures(t, map[string]string{
		"authorization/adapters/authzpg/descriptions.go": "package authzpg\n" +
			"func (r *Repository) ReplaceDescriptions() { exec(`DELETE FROM permission_descriptions WHERE resource_id=$1`) }\n" +
			"func (r *Repository) UpdateCatalog() { exec(`DELETE FROM permission_descriptions WHERE permission<>ALL($1)`) }\n" +
			"func (r *Repository) Rename() { exec(`UPDATE permission_descriptions SET permission=$2 WHERE resource_id=$1`) }\n",
		"oauth/adapters/oauthpg/x.go": "package oauthpg\n" +
			"func purge() { exec(`INSERT INTO permission_descriptions(resource_id) VALUES($1)`) }\n" +
			"func read() { get(`SELECT display_name FROM permission_descriptions WHERE resource_id=$1`) }\n",
	})
	expectViolations(t, descriptionWriteViolations(files, map[string]bool{
		"authorization/adapters/authzpg (*Repository).ReplaceDescriptions": true,
		"authorization/adapters/authzpg (*Repository).UpdateCatalog":       true,
		"authorization/adapters/authzpg (*Repository).Gone":                true,
	}),
		"authorization/adapters/authzpg (*Repository).Gone: function not found (update descriptionWriters when it moves)",
		"authorization/adapters/authzpg/descriptions.go:3: (*Repository).UpdateCatalog changes permission_descriptions beyond one resource (WHERE resource_id=$n)",
		"authorization/adapters/authzpg/descriptions.go:4: (*Repository).Rename writes permission_descriptions; only the description writers may (descriptionWriters)",
		"oauth/adapters/oauthpg/x.go:2: purge writes permission_descriptions; only the description writers may (descriptionWriters)",
	)
}
