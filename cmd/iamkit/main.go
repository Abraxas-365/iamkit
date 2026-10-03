package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/Abraxas-365/iamkit/migrations"
)

func main() {
	// Log lines carry the request id and trace/span ids of their context.
	slog.SetDefault(slog.New(telemetry.LogHandler(slog.NewTextHandler(os.Stderr, nil))))
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// version is the module version the binary was built from ("dev" in a
// local build).
func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return ""
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
	slog.Info("running migrations")
	if err = migrations.Apply(context.Background(), db); err != nil {
		return err
	}
	slog.Info("migrations up to date")

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
				slog.Info("workspace already exists, skipping bootstrap")
				if os.Getenv("IAMKIT_BOOTSTRAP_PASSWORD") != "" {
					slog.Warn("IAMKIT_BOOTSTRAP_PASSWORD is still set after bootstrap and is ignored: remove it from the environment")
				}
			} else {
				return err
			}
		} else {
			slog.Info("bootstrapped workspace", "workspace", workspace, "operator", email)
			fmt.Printf("iamkit: management API key (expires in 24h): %s\n", raw)

			// If a password was provided, set it immediately so Login works.
			// It sits in plaintext in the deployment, so the first sign-in
			// must replace it.
			if password := os.Getenv("IAMKIT_BOOTSTRAP_PASSWORD"); password != "" {
				p, err := mgmt.Authenticate(context.Background(), raw)
				if err != nil {
					return fmt.Errorf("auto-bootstrap: authenticate to set password: %w", err)
				}
				if err = mgmt.SetTemporaryPassword(context.Background(), p, password); err != nil {
					return fmt.Errorf("auto-bootstrap: set password: %w", err)
				}
				slog.Info("operator password set from IAMKIT_BOOTSTRAP_PASSWORD; it must be changed at the first sign-in")
			}
		}
	}

	// ── Serve ─────────────────────────────────────────────────────────
	// Only the server exports telemetry (the global providers delegate, so
	// the database pool metrics registered at open still arrive). Nothing
	// is exported unless OTEL_* or IAMKIT_METRICS_ADDR ask for it.
	cfg := telemetry.FromEnvironment()
	cfg.Version = version()
	shutdownTelemetry, err := telemetry.Setup(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTelemetry(ctx); err != nil {
			slog.Warn("telemetry shutdown", "err", err)
		}
	}()
	if cfg.Enabled() {
		slog.Info("telemetry enabled", "traces", cfg.Traces, "metrics", cfg.Metrics, "metrics_addr", cfg.MetricsAddr)
	}
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
	s.Start(ctx)
	if s.Workers != nil {
		slog.Info("background jobs", "state", s.Workers.State(), "jobs", s.Workers.Jobs())
	}
	done := make(chan error, 1)
	go func() { done <- app.Listen(":" + port) }()
	slog.Info("server listening", "port", port)
	select {
	case err = <-done:
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
		err = app.ShutdownWithTimeout(10 * time.Second)
		if s.WaitDeliveries != nil && !s.WaitDeliveries(10*time.Second) {
			slog.Warn("code emails still being sent at exit")
		}
		if s.Workers != nil && !s.Workers.Wait(10*time.Second) {
			slog.Warn("background jobs still running at exit")
		}
		if !s.WaitFlushed(10 * time.Second) {
			slog.Warn("usage counters not flushed at exit")
		}
		if s.CloseCache != nil {
			_ = s.CloseCache()
		}
		return err
	}
}
