package architecture_test

// Architecture tests: the layout rules of the go-hex-architecture skill as a
// lint that runs in `go test` (go/ast only, no extra dependencies). Each rule
// is a function over parsed files returning violations, so it is proven on
// fixtures (TestArchitectureRulesCatchViolations) and run on the real code.
//
// IAMKit groups modules under internal/iam/, so paths are normalised with
// norm() ("iam/user/usersvc" reads as "user/usersvc") and a module's service
// and assembler are the sub-packages ending in "svc" / "module" (authsvc,
// fedmodule, sacctmodule...). Never weaken a rule to make a violation pass —
// fix the code or, if the rule is wrong, change the rule here and in
// AGENTS.md together.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// modulePath is the Go module path + "/internal/".
const modulePath = "github.com/Abraxas-365/iamkit/internal/"

// foundation packages (first path segment under internal/) import no domain.
var foundation = map[string]bool{
	"errx": true, "identity": true, "query": true, "config": true,
	"blob": true, "httpx": true, "i18n": true, "netx": true, "ptrx": true,
	"cryptox": true, "cache": true, "telemetry": true, "worker": true, "console": true,
}

// wiring packages (composition root) may import everything.
var wiring = map[string]bool{"bootstrap": true, "server": true, "architecture": true, "openapigen": true}

// norm drops IAMKit's iam/ grouping so iam/<module>/... reads as <module>/...
func norm(rel string) string { return strings.TrimPrefix(rel, "iam/") }

// sharedSQL are the documented exceptions to "adapters import no other
// adapter": SQL packages that PostgreSQL adapters (*pg) of other modules call
// inside their own transaction. Nothing else is allowlisted.
var sharedSQL = map[string]string{
	"event/adapters/eventpg":         "every write records its event in the writer's own transaction (TestEventWriterOnlyInPostgresAdapters)",
	"authentication/adapters/authpg": "authpg.Resolve (one query for a session's access) and authpg.Wrap (a transaction handle) run inside other modules' transactions",
}

// siblingAdapters are the other documented exceptions: one adapter of a
// module importing another adapter of the same module, keyed
// "<from dir> -> <to dir>". Nothing else is allowlisted.
var siblingAdapters = map[string]string{
	"oauth/adapters/oauthhttp -> oauth/adapters/oauthfosite": "oauthhttp is the HTTP front of the fosite protocol engine: it handles fosite's Session (Deadline, AccessClaims, Injected), Store.WithTokenLock and the client-authentication helpers directly; a port over them would restate fosite's API",
}

// forbiddenInCore: a domain root package and its *svc never touch transport
// or SQL; that is the adapters' job.
var forbiddenInCore = []string{
	"net/http", "database/sql", "github.com/jmoiron/sqlx", "github.com/lib/pq",
	"github.com/jackc/pgx", "github.com/gofiber/fiber", "github.com/labstack/echo",
	"github.com/gin-gonic/gin", "google.golang.org/grpc",
}

type goFile struct {
	rel  string // relative to internal/, slash-separated
	file *ast.File
	fset *token.FileSet
}

// sources parses every .go file under internal/ (the test runs in internal/architecture).
func sources(t *testing.T, withTests bool) []goFile {
	t.Helper()
	fset := token.NewFileSet()
	var out []goFile
	root := "../"
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		if !withTests && strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		out = append(out, goFile{rel: norm(filepath.ToSlash(strings.TrimPrefix(p, root))), file: f, fset: fset})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// pkgRole classifies a package dir relative to internal/:
//
//	errx/...                    → "foundation", ""
//	bootstrap                   → "wiring", ""
//	widget                      → "domain", "widget"
//	widget/widgetsvc            → "svc", "widget"
//	widget/widgetmodule         → "module", "widget"
//	widget/adapters/widgetpg    → "adapter", "widget"   (any depth under adapters/)
type pkgRole struct{ kind, domain, dir string }

func roleOf(dir string) pkgRole {
	parts := strings.Split(dir, "/")
	r := pkgRole{dir: dir}
	switch {
	case foundation[parts[0]]:
		r.kind = "foundation"
	case wiring[parts[0]]:
		r.kind = "wiring"
	case len(parts) == 1:
		r.kind, r.domain = "domain", parts[0]
	case parts[1] == "adapters":
		r.kind, r.domain = "adapter", parts[0]
	case strings.HasSuffix(parts[1], "svc"):
		r.kind, r.domain = "svc", parts[0]
	case strings.HasSuffix(parts[1], "module"):
		r.kind, r.domain = "module", parts[0]
	default: // other sub-packages of a domain behave like its root
		r.kind, r.domain = "domain", parts[0]
	}
	return r
}

// importViolations: the dependency rules between layers.
func importViolations(files []goFile) []string {
	var out []string
	for _, f := range files {
		from := roleOf(path.Dir(f.rel))
		for _, imp := range f.file.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			pos := f.fset.Position(imp.Pos()).String()
			if from.kind == "domain" || from.kind == "svc" {
				for _, bad := range forbiddenInCore {
					if p == bad || strings.HasPrefix(p, bad+"/") {
						out = append(out, pos+": "+from.kind+" "+from.dir+" must not import "+p+" (transport/SQL belong in adapters)")
					}
				}
			}
			if !strings.HasPrefix(p, modulePath) {
				continue
			}
			to := roleOf(norm(strings.TrimPrefix(p, modulePath)))
			bad := ""
			switch {
			case to.kind == "wiring" && from.kind != "wiring":
				bad = "only the composition root (and cmd) may import " + to.dir
			case from.kind == "foundation" && to.kind != "foundation":
				bad = "foundation packages import no domain code"
			case from.kind == "wiring", to.kind == "foundation", to.kind == "domain":
				// wiring sees everything; everyone may use foundation and domain roots
			case from.kind == "module" && to.domain == from.domain:
				// the assembler wires its own svc and adapters
			case to.kind == "module":
				bad = "only the composition root imports assemblers (" + to.dir + ")"
			case to.kind == "svc":
				bad = "depend on the Commands/Queries ports in " + to.domain + ", not on the service " + to.dir
			case to.kind == "adapter" && from.kind == "adapter" && to.dir != from.dir && strings.HasPrefix(to.dir, from.dir+"/"):
				// an adapter's own sub-package
			case to.kind == "adapter" && from.kind == "adapter" && sharedSQL[to.dir] != "" && strings.HasSuffix(path.Base(from.dir), "pg"):
				// documented exception: shared SQL helpers used by PostgreSQL adapters
			case to.kind == "adapter" && from.kind == "adapter" && siblingAdapters[from.dir+" -> "+to.dir] != "":
				// documented exception: see siblingAdapters
			case to.kind == "adapter":
				bad = "adapters are wired by the assembler; " + from.kind + " " + from.dir + " must not import " + to.dir
			}
			if bad != "" {
				out = append(out, pos+": "+bad)
			}
		}
	}
	sort.Strings(out)
	return out
}

// portsViolations: ports.go declares only interfaces.
func portsViolations(files []goFile) []string {
	var out []string
	for _, f := range files {
		if path.Base(f.rel) != "ports.go" {
			continue
		}
		for _, decl := range f.file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				out = append(out, f.fset.Position(d.Pos()).String()+": ports.go declares only interfaces (func "+d.Name.Name+")")
			case *ast.GenDecl:
				if d.Tok == token.IMPORT {
					continue
				}
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						out = append(out, f.fset.Position(spec.Pos()).String()+": ports.go declares only interfaces (no const/var)")
						continue
					}
					if _, ok := ts.Type.(*ast.InterfaceType); !ok {
						out = append(out, f.fset.Position(ts.Pos()).String()+": ports.go declares only interfaces ("+ts.Name.Name+" is not one)")
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// serviceConstViolations: a *svc only orchestrates; statuses, kinds and rules
// live in the domain package, tuning knobs stay unexported.
func serviceConstViolations(files []goFile) []string {
	var out []string
	for _, f := range files {
		if roleOf(path.Dir(f.rel)).kind != "svc" {
			continue
		}
		for _, decl := range f.file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
				continue
			}
			for _, spec := range gen.Specs {
				for _, name := range spec.(*ast.ValueSpec).Names {
					if name.IsExported() {
						out = append(out, f.fset.Position(name.Pos()).String()+": exported "+gen.Tok.String()+" "+
							name.Name+" in a service; move it to the domain package or unexport it")
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// repositoryIDViolations: a repository receives the IDs the service generated
// (Commands generate, Repository receives); a *pg adapter never calls
// identity.New<Entity>ID().
func repositoryIDViolations(files []goFile) []string {
	var out []string
	for _, f := range files {
		dir := path.Dir(f.rel)
		if roleOf(dir).kind != "adapter" || !strings.HasSuffix(path.Base(dir), "pg") {
			continue
		}
		ast.Inspect(f.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if ok && pkg.Name == "identity" && strings.HasPrefix(sel.Sel.Name, "New") && strings.HasSuffix(sel.Sel.Name, "ID") {
				out = append(out, f.fset.Position(call.Pos()).String()+": "+"identity."+sel.Sel.Name+
					"() in a repository; the service generates IDs and passes them down")
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}

func report(t *testing.T, violations []string) {
	t.Helper()
	for _, v := range violations {
		t.Error(v)
	}
}

func TestLayerDependencies(t *testing.T)  { report(t, importViolations(sources(t, false))) }
func TestPortsAreInterfaces(t *testing.T) { report(t, portsViolations(sources(t, false))) }
func TestServicesExportNoConstants(t *testing.T) {
	report(t, serviceConstViolations(sources(t, false)))
}
func TestRepositoriesDoNotGenerateIDs(t *testing.T) {
	report(t, repositoryIDViolations(sources(t, false)))
}

// ---- fixtures: prove every rule fires (and stays quiet on correct code) ----

func parseFixtures(t *testing.T, fixtures map[string]string) []goFile {
	t.Helper()
	fset := token.NewFileSet()
	var files []goFile
	for rel, src := range fixtures {
		f, err := parser.ParseFile(fset, rel, src, 0)
		if err != nil {
			t.Fatal(rel, err)
		}
		files = append(files, goFile{rel: rel, file: f, fset: fset})
	}
	return files
}

func expectViolations(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d violations, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			file, msg, _ := strings.Cut(w, ": ")
			found = found || (strings.HasPrefix(g, file+":") && strings.Contains(g, msg)) || strings.Contains(g, w)
		}
		if !found {
			t.Errorf("missing violation containing %q in:\n%s", w, strings.Join(got, "\n"))
		}
	}
}

func TestArchitectureRulesCatchViolations(t *testing.T) {
	m := modulePath
	files := parseFixtures(t, map[string]string{
		// correct code: no violations expected from these
		"errx/errx.go":     `package errx`,
		"bootstrap/b.go":   `package bootstrap; import (_ "` + m + `widget/widgetmodule"; _ "` + m + `order/ordermodule")`,
		"widget/ports.go":  `package widget; import "context"; type Commands interface{ Create(context.Context) error }`,
		"widget/widget.go": `package widget; import (_ "` + m + `errx"; _ "` + m + `order")`,
		"widget/widgetsvc/s.go": `package widgetsvc
import (_ "` + m + `widget"; _ "` + m + `errx")
const batch = 10`,
		"widget/adapters/widgetpg/r.go":       `package widgetpg; import (_ "database/sql"; _ "` + m + `widget")`,
		"widget/adapters/widgethttp/h.go":     `package widgethttp; import _ "` + m + `widget/adapters/widgethttp/dto"`,
		"widget/adapters/widgethttp/dto/d.go": `package dto`,
		"widget/widgetmodule/m.go": `package widgetmodule
import (_ "` + m + `widget/widgetsvc"; _ "` + m + `widget/adapters/widgetpg")`,
		"order/order.go": `package order`,

		// violations
		"identity/id.go":                `package identity; import _ "` + m + `widget"`,                                        // foundation → domain
		"order/ordersvc/s.go":           `package ordersvc; import _ "` + m + `widget/widgetsvc"; const Max = 3`,               // svc → svc, exported const
		"order/orderdb.go":              `package order; import _ "github.com/jmoiron/sqlx"`,                                   // SQL in domain
		"order/adapters/orderhttp/h.go": `package orderhttp; import _ "` + m + `widget/adapters/widgetpg"`,                     // adapter → adapter
		"order/ordermodule/m.go":        `package ordermodule; import _ "` + m + `widget/widgetmodule"`,                        // module → other module
		"order/ports.go":                `package order; type Status string; func Helper() {}`,                                 // ports with non-interfaces
		"widget/widget_boot.go":         `package widget; import _ "` + m + `bootstrap"`,                                       // domain → wiring
		"order/adapters/orderpg/r.go":   `package orderpg; import "` + m + `identity"; func f() { _ = identity.NewOrderID() }`, // repository generates an ID
	})
	expectViolations(t, importViolations(files),
		"identity/id.go: foundation packages import no domain code",
		"order/ordersvc/s.go: depend on the Commands/Queries ports in widget",
		"order/orderdb.go: domain order must not import github.com/jmoiron/sqlx",
		"order/adapters/orderhttp/h.go: adapters are wired by the assembler",
		"order/ordermodule/m.go: only the composition root imports assemblers",
		"widget/widget_boot.go: only the composition root (and cmd) may import bootstrap",
	)
	expectViolations(t, portsViolations(files),
		"order/ports.go: ports.go declares only interfaces (Status is not one)",
		"order/ports.go: ports.go declares only interfaces (func Helper)",
	)
	expectViolations(t, serviceConstViolations(files), "exported const Max in a service")
	expectViolations(t, repositoryIDViolations(files), "order/adapters/orderpg/r.go: identity.NewOrderID() in a repository")
}
