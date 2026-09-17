package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
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
			raw, err = bootstrap.Management(db).RecoverOwner(context.Background(), *name, *email)
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
		return errx.Validation("usage: iamkit [bootstrap|recover-owner --email EMAIL --workspace NAME_OR_ID --output FILE]")
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
	done := make(chan error, 1)
	go func() { done <- app.Listen(":" + port) }()
	select {
	case err = <-done:
		return err
	case <-ctx.Done():
		return app.ShutdownWithTimeout(10 * time.Second)
	}
}
