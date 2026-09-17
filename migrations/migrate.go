// Package migrations embeds the ordered IAMKit schema migrations.
package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/jmoiron/sqlx"
)

//go:embed *.up.sql
var files embed.FS

// Apply runs pending migrations transactionally under a database-wide lock.
// Existing unmanaged schemas are deliberately rejected, not silently adopted.
func Apply(ctx context.Context, db *sqlx.DB) error {
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return errx.Wrap(err, "begin migrations", errx.TypeInternal)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(734982342)`); err != nil {
		return errx.Wrap(err, "lock migrations", errx.TypeInternal)
	}
	var ledger, existing bool
	if err = tx.GetContext(ctx, &ledger, `SELECT to_regclass('public.iamkit_migrations') IS NOT NULL`); err != nil {
		return errx.Wrap(err, "inspect migration ledger", errx.TypeInternal)
	}
	if !ledger {
		if err = tx.GetContext(ctx, &existing, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE')`); err != nil {
			return errx.Wrap(err, "inspect schema", errx.TypeInternal)
		}
		if existing {
			return errx.Conflict("unmanaged database schema: use an empty database; automatic legacy adoption is forbidden")
		}
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS iamkit_migrations(name text PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return errx.Wrap(err, "create migration ledger", errx.TypeInternal)
	}
	entries, err := files.ReadDir(".")
	if err != nil {
		return errx.Wrap(err, "read migrations", errx.TypeInternal)
	}
	names := []string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		content, err := files.ReadFile(name)
		if err != nil {
			return errx.Wrap(err, "read migration", errx.TypeInternal)
		}
		hash := sha256.Sum256(content)
		checksum := hex.EncodeToString(hash[:])
		var stored string
		err = tx.GetContext(ctx, &stored, `SELECT checksum FROM iamkit_migrations WHERE name=$1`, name)
		if err == nil {
			if stored != checksum {
				return errx.Conflict("applied migration checksum changed: " + name)
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return errx.Wrap(err, "read migration state", errx.TypeInternal)
		}
		if _, err = tx.ExecContext(ctx, string(content)); err != nil {
			return errx.Wrap(err, "apply migration "+name, errx.TypeInternal)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO iamkit_migrations(name,checksum) VALUES($1,$2)`, name, checksum); err != nil {
			return errx.Wrap(err, "record migration", errx.TypeInternal)
		}
	}
	if err = tx.Commit(); err != nil {
		return errx.Wrap(err, "commit migrations", errx.TypeInternal)
	}
	return nil
}
