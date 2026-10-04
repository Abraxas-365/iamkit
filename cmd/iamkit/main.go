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
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/Abraxas-365/iamkit/migrations"
)

func main() {
	// Log lines carry the request id and trace/span ids of their context.
	slog.SetDefault(slog.New(telemetry.LogHandler(slog.NewTextHandler(os.Stderr, nil))))
	if err := run(); err != nil {
		if errors.Is(err, errReported) {
			os.Exit(2)
		}
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

// errReported marks an error already written to stderr (flag parsing prints
// its own message and usage): main exits nonzero without printing it again.
var errReported = errors.New("reported")

const usage = "usage: iamkit [migrate | bootstrap | recover-owner] (see --help)"

// credentialArgs are the flags of bootstrap and recover-owner.
type credentialArgs struct {
	email, output string
	workspace     string
	workspaceID   identity.WorkspaceID // recover-owner only
}

// parseCredentialArgs reads and checks the flags before any database or file
// is touched, so a mistake leaves nothing behind. It returns flag.ErrHelp for
// --help.
func parseCredentialArgs(command string, argv []string) (credentialArgs, error) {
	var in credentialArgs
	args := flag.NewFlagSet(command, flag.ContinueOnError)
	args.StringVar(&in.email, "email", "", "owner operator email")
	args.StringVar(&in.workspace, "workspace", "", "workspace name for bootstrap; workspace UUID for recover-owner")
	args.StringVar(&in.output, "output", "", "new private file for one-time management credential")
	if err := args.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return in, err
		}
		return in, errReported // the flag package already printed it
	}
	if args.NArg() > 0 {
		return in, errx.Validation(fmt.Sprintf("unexpected argument %q; %s takes only --email, --workspace and --output", args.Arg(0), command))
	}
	switch {
	case in.output == "":
		return in, errx.Validation("--output is required; credential will not be written to logs")
	case in.email == "":
		return in, errx.Validation("--email is required")
	case in.workspace == "" && command == "bootstrap":
		return in, errx.Validation("--workspace is required: the name of the workspace to create")
	case in.workspace == "":
		return in, errx.Validation("--workspace is required: the UUID of the workspace to recover")
	}
	if _, err := identity.Email(in.email); err != nil {
		return in, errx.Validation(fmt.Sprintf("--email %q is not a valid email address", in.email))
	}
	if command == "recover-owner" {
		id, err := identity.ParseWorkspaceID(in.workspace)
		if err != nil || id.IsZero() {
			return in, errx.Validation(fmt.Sprintf("--workspace %q is not a workspace UUID (recover-owner takes the UUID, not the name)", in.workspace))
		}
		in.workspaceID = id
	}
	return in, nil
}

func run() error {
	// Check the command line before connecting: a typo or --help must not
	// need a database.
	var credentials credentialArgs
	command := ""
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	switch command {
	case "":
	case "migrate":
		if len(os.Args) != 2 {
			return errx.Validation(usage)
		}
	case "bootstrap", "recover-owner":
		var err error
		if credentials, err = parseCredentialArgs(command, os.Args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
	default:
		return errx.Validation(usage)
	}

	db, err := bootstrap.OpenDatabase()
	if err != nil {
		return err
	}
	defer db.Close()
	if command == "migrate" {
		return migrations.Apply(context.Background(), db)
	}
	if command != "" {
		f, err := os.OpenFile(credentials.output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return errx.Validation(fmt.Sprintf("--output %s already exists; choose a new file (an old credential is never overwritten)", credentials.output))
			}
			return fmt.Errorf("--output: %w", err)
		}
		defer f.Close()
		var raw string
		if command == "recover-owner" {
			raw, err = bootstrap.Management(db).RecoverOwner(context.Background(), credentials.workspaceID, credentials.email)
		} else {
			raw, err = bootstrap.Management(db).Bootstrap(context.Background(), credentials.email, credentials.workspace)
		}
		if err != nil {
			f.Close()
			os.Remove(credentials.output)
			return err
		}
		if err = json.NewEncoder(f).Encode(map[string]string{"management_key": raw}); err != nil {
			return errx.Wrap(err, "credential change committed but credential file write failed", errx.TypeInternal)
		}
		if err = f.Sync(); err != nil {
			return errx.Wrap(err, "credential change committed but credential file could not be flushed", errx.TypeInternal)
		}
		fmt.Println("Credential saved to the private output file; expires in 24 hours.")
		if command == "bootstrap" {
			// Only the automatic bootstrap reads IAMKIT_BOOTSTRAP_PASSWORD;
			// say so instead of leaving an operator that cannot sign in.
			if os.Getenv("IAMKIT_BOOTSTRAP_PASSWORD") != "" {
				slog.Warn("IAMKIT_BOOTSTRAP_PASSWORD is ignored by the bootstrap command: the operator has no password")
			}
			fmt.Println("The operator has no password yet: set one with POST /management/v1/password and the credential's X-API-Key, or use \"Set up your account\" in the console.")
		}
		return nil
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
		// Refuse a password the policy would reject before the workspace
		// exists: afterwards a restart would skip bootstrap and leave an
		// owner with no password for good.
		if password := os.Getenv("IAMKIT_BOOTSTRAP_PASSWORD"); password != "" &&
			(len(password) < config.PasswordMinLength || len(password) > config.PasswordMaxLength) {
			return errx.Validation(fmt.Sprintf("IAMKIT_BOOTSTRAP_PASSWORD must be %d-%d characters long", config.PasswordMinLength, config.PasswordMaxLength))
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
