package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestSpecIsCurrent fails when api/openapi.json no longer matches the
// routes and handlers: run make openapi.
func TestSpecIsCurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("loads every package")
	}
	root := filepath.Join("..", "..")
	want, warnings, err := Generate(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		t.Error(w)
	}
	got, err := os.ReadFile(filepath.Join(root, "api", "openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("api/openapi.json is stale: run make openapi")
	}
}
