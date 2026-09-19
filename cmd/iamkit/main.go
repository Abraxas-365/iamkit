package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/migrations"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	db, err := bootstrap.OpenDatabase()
	if err != nil {
		return err
	}
	defer db.Close()
	if len(os.Args) == 2 && os.Args[1] == "migrate" {
		return migrations.Apply(context.Background(), db)
	}
	if len(os.Args) > 1 && (os.Args[1] == "bootstrap" || os.Args[1] == "recover-owner") {
		args := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
		email := args.String("email", "", "owner operator email")
		name := args.String("workspace", "", "workspace name for bootstrap; workspace UUID for recover-owner")
		output := args.String("output", "", "new private file for one-time management credential")
		if err = args.Parse(os.Args[2:]); err != nil {
			return err
		}
		if *output == "" {
			return errx.Validation("--output is required; credential will not be written to logs")
		}
		f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		var raw string
		if os.Args[1] == "recover-owner" {
			wsID, parseErr := identity.ParseWorkspaceID(*name)
			if parseErr != nil {
				return parseErr
			}
			raw, err = bootstrap.Management(db).RecoverOwner(context.Background(), wsID, *email)
		} else {
			raw, err = bootstrap.Management(db).Bootstrap(context.Background(), *email, *name)
		}
		if err != nil {
			f.Close()
			os.Remove(*output)
			return err
		}
		if err = json.NewEncoder(f).Encode(map[string]string{"management_key": raw}); err != nil {
			return errx.Wrap(err, "credential change committed but credential file write failed", errx.TypeInternal)
		}
		if err = f.Sync(); err != nil {
			return err
		}
		fmt.Println("Credential saved to the private output file; expires in 24 hours.")
		return nil
	}
	if len(os.Args) > 1 {
		return errx.Validation("usage: iamkit [migrate | bootstrap | recover-owner] (see --help)")
	}

	// ── Auto-migrate ──────────────────────────────────────────────────
	log.Println("iamkit: running migrations…")
	if err = migrations.Apply(context.Background(), db); err != nil {
		return err
	}
	log.Println("iamkit: migrations up to date")

	// ── Auto-bootstrap (first boot only) ──────────────────────────────
	if email := os.Getenv("IAMKIT_BOOTSTRAP_EMAIL"); email != "" {
		workspace := os.Getenv("IAMKIT_BOOTSTRAP_WORKSPACE")
		if workspace == "" {
			workspace = "Default"
		}
		mgmt := bootstrap.ManagementWithPasswords(db)
		raw, err := mgmt.Bootstrap(context.Background(), email, workspace)
		if err != nil {
			var ex *errx.Error
			if errors.As(err, &ex) && ex.Type == errx.TypeConflict {
				// Already bootstrapped — skip silently.
				log.Println("iamkit: workspace already exists, skipping bootstrap")
			} else {
				return err
			}
		} else {
			log.Printf("iamkit: bootstrapped workspace %q with operator %s", workspace, email)
			log.Printf("iamkit: management API key (expires in 24h): %s", raw)

			// If a password was provided, set it immediately so Login works.
			if password := os.Getenv("IAMKIT_BOOTSTRAP_PASSWORD"); password != "" {
				p, err := mgmt.Authenticate(context.Background(), raw)
				if err != nil {
					return fmt.Errorf("auto-bootstrap: authenticate to set password: %w", err)
				}
				if err = mgmt.SetPassword(context.Background(), p, password); err != nil {
					return fmt.Errorf("auto-bootstrap: set password: %w", err)
				}
				log.Println("iamkit: operator password set from IAMKIT_BOOTSTRAP_PASSWORD")
			}
		}
	}

	// ── Serve ─────────────────────────────────────────────────────────
	s, err := bootstrap.FromEnvironment(db)
	if err != nil {
		return err
	}
	app := s.App()
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- app.Listen(":" + port) }()
	select {
	case err = <-done:
		return err
	case <-ctx.Done():
		return app.ShutdownWithTimeout(10 * time.Second)
	}
}
