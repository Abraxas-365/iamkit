package architecture_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Validation rules (AGENTS.md "Rules", go-hex-architecture: "Validation lives
// on the domain struct; the service calls it"). Two checks, as a lint over the
// source (go/ast, no type checker):
//
//  1. An exported method of a service package (<x>svc) that takes a value of
//     a type with `Validate() error` must call <param>.Validate() in its body.
//  2. A Validate() method must call Validate() on each of its struct's fields
//     whose type has its own Validate() (Create.Content, Filter.Ref...).
//
// Types are resolved through the file's imports, so "risk.Create" in
// core/risk/risksvc means the type Create declared in core/risk.

// typeKey is "<dir relative to internal/>.<TypeName>", e.g. "core/risk.Create".
type typeKey string

// validateExempt lists the only inputs a service may take without calling
// their Validate(). Key: a typeKey (every parameter of that type) or
// "<package dir>.<Func>(<param>)" (one parameter). Each entry states why
// validating there would change what the service accepts. Dirs are relative
// to internal/ without the iam/ grouping.
var validateExempt = map[string]string{
	"authentication.Context":        "a partial scope by design: hosted pages and MFA enrollment pass only the environment (or no organization yet) and each method checks the fields it needs; Context.Validate demands all four IDs and is called where they are all required (Login, Refresh, login challenges)",
	"federation/fedsvc.Start(back)": "federation.Return is optional: unset means a plain redirect flow, and Validate applies only when it is Set (returnable)",
}

type validationIndex struct {
	validators map[typeKey]bool            // types with Validate() error
	structs    map[typeKey]*ast.StructType // struct declarations
	methods    map[typeKey]*ast.FuncDecl   // Validate methods
	files      map[*ast.FuncDecl]goFile    // file of each Validate method
}

func indexValidation(files []goFile) validationIndex {
	ix := validationIndex{
		validators: map[typeKey]bool{},
		structs:    map[typeKey]*ast.StructType{},
		methods:    map[typeKey]*ast.FuncDecl{},
		files:      map[*ast.FuncDecl]goFile{},
	}
	for _, f := range files {
		dir := path.Dir(f.rel)
		for _, decl := range f.file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if name := receiverType(d); name != "" && isValidateMethod(d) {
					k := typeKey(dir + "." + name)
					ix.validators[k] = true
					ix.methods[k] = d
					ix.files[d] = f
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if ts, ok := spec.(*ast.TypeSpec); ok {
						if st, ok := ts.Type.(*ast.StructType); ok {
							ix.structs[typeKey(dir+"."+ts.Name.Name)] = st
						}
					}
				}
			}
		}
	}
	return ix
}

// validationViolations runs both checks over files and returns sorted messages.
func validationViolations(files []goFile) []string {
	ix := indexValidation(files)
	var out []string

	// 1. Services call Validate on their inputs.
	for _, f := range files {
		if !strings.HasSuffix(path.Base(path.Dir(f.rel)), "svc") || strings.HasSuffix(f.rel, "_test.go") {
			continue
		}
		for _, decl := range f.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !fn.Name.IsExported() || fn.Body == nil {
				continue
			}
			for _, field := range fn.Type.Params.List {
				k, ok := resolveType(f, field.Type)
				if !ok || !ix.validators[k] || validateExempt[string(k)] != "" {
					continue
				}
				if len(field.Names) == 0 {
					out = append(out, f.fset.Position(field.Pos()).String()+": "+fn.Name.Name+
						": unnamed "+string(k)+" parameter can't be validated; name it and call .Validate()")
					continue
				}
				for _, name := range field.Names {
					if validateExempt[path.Dir(f.rel)+"."+fn.Name.Name+"("+name.Name+")"] != "" {
						continue
					}
					if name.Name == "_" || !callsValidate(fn.Body, name.Name, "") {
						out = append(out, f.fset.Position(name.Pos()).String()+": "+fn.Name.Name+
							" takes "+string(k)+" but never calls "+name.Name+".Validate()")
					}
				}
			}
		}
	}

	// 2. Validate covers fields that can validate themselves.
	for k, fn := range ix.methods {
		st := ix.structs[k]
		if st == nil || fn.Body == nil {
			continue
		}
		f := ix.files[fn]
		recv := receiverName(fn)
		for _, field := range st.Fields.List {
			fk, ok := resolveType(f, field.Type)
			if !ok || !ix.validators[fk] {
				continue
			}
			names := field.Names
			if len(names) == 0 { // embedded: the field is named after its type
				names = []*ast.Ident{ast.NewIdent(string(fk[strings.LastIndex(string(fk), ".")+1:]))}
			}
			for _, name := range names {
				if recv == "" || !callsValidate(fn.Body, recv, name.Name) {
					out = append(out, f.fset.Position(fn.Pos()).String()+": "+string(k)+
						".Validate does not call "+recv+"."+name.Name+".Validate() ("+string(fk)+")")
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func isValidateMethod(fn *ast.FuncDecl) bool {
	if fn.Name.Name != "Validate" || fn.Type.Params.NumFields() != 0 || fn.Type.Results.NumFields() != 1 {
		return false
	}
	id, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	return ok && id.Name == "error"
}

func receiverType(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return ""
	}
	t := fn.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) != 1 {
		return ""
	}
	return fn.Recv.List[0].Names[0].Name
}

// resolveType maps T, *T and pkg.T (a module-internal import) to a typeKey.
func resolveType(f goFile, expr ast.Expr) (typeKey, bool) {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	switch t := expr.(type) {
	case *ast.Ident:
		return typeKey(path.Dir(f.rel) + "." + t.Name), true
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		for _, imp := range f.file.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if !strings.HasPrefix(p, modulePath) {
				continue
			}
			local := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				local = imp.Name.Name
			}
			if local == pkg.Name {
				return typeKey(norm(strings.TrimPrefix(p, modulePath)) + "." + t.Sel.Name), true
			}
		}
	}
	return "", false
}

// callsValidate reports a call to <root>.Validate() (field == "") or
// <root>.<field>.Validate() anywhere in body.
func callsValidate(body *ast.BlockStmt, root, field string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found {
			return !found
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Validate" || len(call.Args) != 0 {
			return true
		}
		switch x := sel.X.(type) {
		case *ast.Ident:
			found = field == "" && x.Name == root
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			found = ok && field != "" && id.Name == root && x.Sel.Name == field
		}
		return !found
	})
	return found
}

// TestServicesValidateInputs runs the lint over the real code.
func TestServicesValidateInputs(t *testing.T) {
	for _, v := range validationViolations(sources(t, false)) {
		t.Error(v)
	}
}

// TestValidationLintCatchesViolations proves the lint on fixtures: it must
// flag a service that skips Validate and a Validate that skips a field, and
// accept the correct forms (pointer params, embedded fields, imported types).
func TestValidationLintCatchesViolations(t *testing.T) {
	fixtures := map[string]string{
		"core/widget/widget.go": `package widget
type Content struct{ URL string }
func (c Content) Validate() error { return nil }
type Create struct {
	Content
	Title string
}
func (c Create) Validate() error { return c.Content.Validate() }
type Update struct{ Content Content }
func (u Update) Validate() error { return nil } // BAD: skips u.Content
type Filter struct{ Q string } // no Validate: never required
`,
		"core/widget/widgetsvc/service.go": `package widgetsvc
import w "` + modulePath + `core/widget"
type Service struct{}
func (s *Service) Create(input w.Create) error { return input.Validate() }
func (s *Service) CreatePtr(input *w.Create) error {
	if err := input.Validate(); err != nil { return err }
	return nil
}
func (s *Service) Update(input w.Update) error { return nil } // BAD
func (s *Service) Skip(_ w.Create) error { return nil }      // BAD
func (s *Service) List(f w.Filter) error { return nil }
func (s *Service) internal(input w.Update) error { return nil } // unexported: not checked
`,
	}
	fset := token.NewFileSet()
	var files []goFile
	for rel, src := range fixtures {
		f, err := parser.ParseFile(fset, rel, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, goFile{rel: rel, file: f, fset: fset})
	}
	got := validationViolations(files)
	want := []string{
		"Skip takes core/widget.Create but never calls _.Validate()",
		"Update takes core/widget.Update but never calls input.Validate()",
		"core/widget.Update.Validate does not call u.Content.Validate() (core/widget.Content)",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d violations, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || strings.Contains(g, w)
		}
		if !found {
			t.Errorf("missing violation %q in:\n%s", w, strings.Join(got, "\n"))
		}
	}
}
