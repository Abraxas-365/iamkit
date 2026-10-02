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
			forbidden := strings.Contains(name, "/adapters/") || strings.Contains(name, "/internal/server") || strings.Contains(name, "/internal/bootstrap") || strings.HasSuffix(name, "/internal/telemetry") || strings.Contains(name, "/internal/cache/")
			for _, prefix := range []string{"database/sql", "net/http", "github.com/gofiber/", "github.com/jmoiron/sqlx", "github.com/lib/pq", "github.com/ory/fosite", "golang.org/x/crypto/bcrypt", "go.opentelemetry.io/", "github.com/redis/"} {
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

// The shared event writer (eventpg) is SQL: only PostgreSQL adapters, the
// event module's own adapters and the composition root may use it.
func TestEventWriterOnlyInPostgresAdapters(t *testing.T) {
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
		dir := filepath.Base(filepath.Dir(path))
		normalized := filepath.ToSlash(path)
		allowed := strings.HasSuffix(dir, "pg") || strings.Contains(normalized, "/iam/event/") || strings.Contains(normalized, "/bootstrap/")
		for _, spec := range file.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if strings.HasSuffix(name, "/event/adapters/eventpg") && !allowed {
				t.Errorf("%s imports the event writer %s outside a PostgreSQL adapter", path, name)
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

// Redis is an optional adapter: only cacheredis talks to it, and only the
// composition root picks a cache adapter.
func TestCacheAdapters(t *testing.T) {
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
		normalized := filepath.ToSlash(path)
		for _, spec := range file.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if strings.HasPrefix(name, "github.com/redis/") && !strings.Contains(normalized, "/cache/cacheredis/") {
				t.Errorf("%s imports %s outside cacheredis", path, name)
			}
			adapter := strings.HasSuffix(name, "/internal/cache/cacheredis") || strings.HasSuffix(name, "/internal/cache/cachememory")
			if adapter && !strings.Contains(normalized, "/bootstrap/") && !strings.Contains(normalized, "/cache/") {
				t.Errorf("%s imports cache adapter %s outside bootstrap", path, name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
