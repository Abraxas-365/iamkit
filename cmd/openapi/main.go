// Command openapi writes api/openapi.json from the server's routes and the
// source of their handlers (make openapi). A test keeps the committed file
// current.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/openapigen"
	"github.com/jmoiron/sqlx"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	out, warnings, err := Generate(*root)
	if err != nil {
		log.Fatal(err)
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	if err := os.WriteFile(filepath.Join(*root, "api", "openapi.json"), out, 0o644); err != nil {
		log.Fatal(err)
	}
}

// Generate builds the document. The server is assembled exactly as it runs,
// with a database handle that is never connected.
func Generate(root string) ([]byte, []string, error) {
	db, err := sqlx.Open("postgres", "postgres://openapi@127.0.0.1:1/openapi?sslmode=disable")
	if err != nil {
		return nil, nil, err
	}
	defer db.Close()
	key, err := bootstrap.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	sealer, err := cryptox.Parse("", "")
	if err != nil {
		return nil, nil, err
	}
	app := bootstrap.New(db, key, "https://iam.example", nil, bootstrap.WithSealer(sealer), bootstrap.WithBreaches(nil)).App()
	defer app.Shutdown()
	analyzer, err := openapigen.Load(root)
	if err != nil {
		return nil, nil, err
	}
	doc, warnings := openapigen.Build(analyzer, openapigen.Routes(app), "1")
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), warnings, nil
}
