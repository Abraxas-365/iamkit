package architecture_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Keep domain/use-case packages independent of their implementation adapters.
func TestDomainDependencyDirection(t *testing.T) {
	err := filepath.WalkDir("../iam", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		normalized := filepath.ToSlash(path)
		if strings.Contains(normalized, "/adapters/") || strings.Contains(normalized, "module/") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			forbidden := strings.Contains(name, "/adapters/") || strings.Contains(name, "/internal/server") || strings.Contains(name, "/internal/bootstrap")
			for _, prefix := range []string{"database/sql", "net/http", "github.com/gofiber/", "github.com/jmoiron/sqlx", "github.com/lib/pq", "github.com/ory/fosite", "golang.org/x/crypto/bcrypt"} {
				forbidden = forbidden || strings.HasPrefix(name, prefix)
			}
			if forbidden {
				t.Errorf("%s imports infrastructure %s", path, name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestModuleAssemblyOnlyUsedByCompositionRoot(t *testing.T) {
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if strings.Contains(name, "module") && !strings.Contains(filepath.ToSlash(path), "/bootstrap/") {
				t.Errorf("%s imports module assembly %s outside bootstrap", path, name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestAdaptersDirectoryIsNotPackage(t *testing.T) {
	err := filepath.WalkDir("../iam", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && filepath.Base(filepath.Dir(path)) == "adapters" {
			t.Errorf("grouping directory must not contain Go files: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
