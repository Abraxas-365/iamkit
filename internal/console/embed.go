// Package console provides the embedded operator dashboard (React SPA).
//
// The dist/ directory is populated by the frontend build step. When building
// without the frontend (e.g. go test), dist/ may be empty; in that case
// Assets returns nil and the server skips SPA serving.
package console

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// Assets returns the frontend filesystem rooted at dist/, or nil if the
// build produced no files (development / test builds without Node).
func Assets() fs.FS {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		return nil
	}
	// Check if index.html exists — if not, the dist/ dir is empty.
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}
