package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

type eventRetentionView struct {
	Security *int64 `json:"security_retention_seconds"`
	Default  *int64 `json:"default_retention_seconds"`
	Ceilings struct {
		Security int64 `json:"security"`
		Default  int64 `json:"default"`
	} `json:"ceilings"`
	Effective struct {
		Security int64 `json:"security"`
		Default  int64 `json:"default"`
	} `json:"effective"`
}

// retentionDays shows seconds as days ("-" = not set).
func retentionDays(seconds *int64) string {
	if seconds == nil {
		return "-"
	}
	return strconv.FormatInt(*seconds/86400, 10) + "d"
}

func printEventRetention(data json.RawMessage) error {
	p := newPrinter()
	if p.wantJSON() {
		p.JSON(data)
		return nil
	}
	var v eventRetentionView
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	days := func(s int64) string { return retentionDays(&s) }
	rows := []map[string]any{
		{"class": "security", "effective": days(v.Effective.Security), "ceiling": days(v.Ceilings.Security), "environment": retentionDays(v.Security)},
		{"class": "default", "effective": days(v.Effective.Default), "ceiling": days(v.Ceilings.Default), "environment": retentionDays(v.Default)},
	}
	table, _ := json.Marshal(rows)
	p.table(table, []string{"CLASS", "EFFECTIVE", "CEILING", "ENVIRONMENT"}, func(m map[string]any) []string {
		return []string{str(m, "class"), str(m, "effective"), str(m, "ceiling"), str(m, "environment")}
	})
	return nil
}

// parseRetention reads a duration in days (30d) or Go syntax (720h) as
// whole seconds; "default" is nil, the deployment's ceiling.
func parseRetention(flag, value string) (*int64, error) {
	if value == "default" {
		return nil, nil
	}
	var d time.Duration
	if n, err := strconv.Atoi(value[:max(len(value)-1, 0)]); err == nil && value[len(value)-1] == 'd' {
		d = time.Duration(n) * 24 * time.Hour
	} else if d, err = time.ParseDuration(value); err != nil {
		return nil, fmt.Errorf("--%s: %q is not a duration like 30d or 720h (or \"default\")", flag, value)
	}
	seconds := int64(d.Seconds())
	return &seconds, nil
}

func eventRetentionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "event-retention",
		Short: "Read and shorten how long the environment keeps events",
		Long: `Events are kept per class. Security events (sign-ins, sessions, tokens,
credentials, consents) follow IAMKIT_SECURITY_EVENT_RETENTION (default 365
days); every other event follows IAMKIT_EVENT_RETENTION (default 90 days).
The environment may keep either class for less, at least one day, never for
more than the deployment's ceiling. The database is not an archive: stream
events to S3 or Datadog with log streams to keep them longer. Only workspace
owners change the retention.`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get",
		Short: "Show the effective retention, the ceilings and the environment's values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/event-retention")
			if err != nil {
				return err
			}
			return printEventRetention(data)
		},
	})
	var security, other string
	set := &cobra.Command{
		Use:   "set",
		Short: "Change the retention of a class (a flag left out keeps the current value)",
		Example: `  iam event-retention set --security 180d --default 30d
  iam event-retention set --default default   # back to the ceiling`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if security == "" && other == "" {
				return fmt.Errorf("give --security and/or --default")
			}
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/event-retention")
			if err != nil {
				return err
			}
			var current eventRetentionView
			if err := json.Unmarshal(data, &current); err != nil {
				return err
			}
			body := map[string]any{"security_retention_seconds": current.Security, "default_retention_seconds": current.Default}
			for flag, value := range map[string]string{"security": security, "default": other} {
				if value == "" {
					continue
				}
				seconds, err := parseRetention(flag, value)
				if err != nil {
					return err
				}
				body[flag+"_retention_seconds"] = seconds
			}
			out, err := c.put(envPath()+"/event-retention", body)
			if err != nil {
				return err
			}
			return printEventRetention(out)
		},
	}
	set.Flags().StringVar(&security, "security", "", "security events: 30d, 720h or default (the ceiling)")
	set.Flags().StringVar(&other, "default", "", "other events: 30d, 720h or default (the ceiling)")
	cmd.AddCommand(set)
	return cmd
}
