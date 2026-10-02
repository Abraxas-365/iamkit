package cli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// limitNames is the limit catalog (usage.Catalog), in display order.
var limitNames = []string{"users_max", "organizations_max", "applications_max", "requests_per_minute", "emails_per_day", "sms_per_day", "action_calls_per_minute"}

// metricNames are the daily usage metrics (usage.Metrics), in display order.
var metricNames = []string{"logins", "users_created", "tokens", "emails", "sms", "action_calls", "api_requests"}

type limitsView struct {
	Deployment  map[string]int64 `json:"deployment"`
	Environment map[string]int64 `json:"environment"`
	Effective   map[string]int64 `json:"effective"`
}

// printLimits shows one row per limit ("-" = unlimited).
func printLimits(data json.RawMessage) error {
	p := newPrinter()
	if p.wantJSON() {
		p.JSON(data)
		return nil
	}
	var v limitsView
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	cell := func(m map[string]int64, name string) string {
		if n, ok := m[name]; ok {
			return strconv.FormatInt(n, 10)
		}
		return "-"
	}
	rows := make([]map[string]any, 0, len(limitNames))
	for _, name := range limitNames {
		rows = append(rows, map[string]any{"name": name, "effective": cell(v.Effective, name), "deployment": cell(v.Deployment, name), "environment": cell(v.Environment, name)})
	}
	table, _ := json.Marshal(rows)
	p.table(table, []string{"LIMIT", "EFFECTIVE", "DEPLOYMENT", "ENVIRONMENT"}, func(m map[string]any) []string {
		return []string{str(m, "name"), str(m, "effective"), str(m, "deployment"), str(m, "environment")}
	})
	return nil
}

func limitsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "limits",
		Short: "Read and tighten the environment's limits",
		Long: `Limits bound an environment: users_max, organizations_max and
applications_max (what exists, 422 QUOTA_EXCEEDED), emails_per_day and
sms_per_day (per UTC day, 429) and requests_per_minute and
action_calls_per_minute (429). The deployment sets caps with IAMKIT_LIMITS
("users_max=10000,requests_per_minute=600"); an environment's own limits can
only tighten them. Unset = unlimited. Only workspace owners change limits.`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get",
		Short: "Show the deployment caps, the environment's limits and the effective values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/limits")
			if err != nil {
				return err
			}
			return printLimits(data)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "set NAME=VALUE...",
		Short: "Change some of the environment's limits (VALUE none removes one)",
		Example: `  iam limits set users_max=5000 emails_per_day=2000
  iam limits set sms_per_day=none`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/limits")
			if err != nil {
				return err
			}
			var current limitsView
			if err := json.Unmarshal(data, &current); err != nil {
				return err
			}
			body := map[string]any{}
			for name, n := range current.Environment {
				body[name] = n
			}
			for _, arg := range args {
				name, value, ok := strings.Cut(arg, "=")
				if !ok {
					return fmt.Errorf("%q: want NAME=VALUE", arg)
				}
				if value == "none" {
					body[name] = nil
					continue
				}
				n, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					return fmt.Errorf("%s: %q is not a whole number", name, value)
				}
				body[name] = n
			}
			out, err := c.put(envPath()+"/limits", body)
			if err != nil {
				return err
			}
			return printLimits(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "clear",
		Short: "Remove every environment limit (the deployment caps apply)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := mustClient(cmd).put(envPath()+"/limits", map[string]any{})
			if err != nil {
				return err
			}
			return printLimits(out)
		},
	})
	return cmd
}

func usageCmd() *cobra.Command {
	var days int
	cmd := &cobra.Command{
		Use:   "usage",
		Short: "Show the environment's daily usage",
		Long: `Daily usage per UTC day, oldest first: sign-ins and created users (rolled up
from the event log about a minute after they happen), tokens, emails, SMS,
action calls and API requests (counted by each replica, written every 30s).
Totals and what exists now against its limits follow.`,
		Example: `  iam usage --days 7`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/usage?days=" + strconv.Itoa(days))
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			var report struct {
				Days []struct {
					Day     string           `json:"day"`
					Metrics map[string]int64 `json:"metrics"`
				} `json:"days"`
				Totals map[string]int64 `json:"totals"`
				Now    []struct {
					Name  string `json:"name"`
					Count int64  `json:"count"`
					Max   *int64 `json:"max"`
				} `json:"now"`
			}
			if err := json.Unmarshal(data, &report); err != nil {
				return err
			}
			row := func(day string, metrics map[string]int64) map[string]any {
				out := map[string]any{"day": day}
				for _, m := range metricNames {
					out[m] = strconv.FormatInt(metrics[m], 10)
				}
				return out
			}
			rows := make([]map[string]any, 0, len(report.Days)+1)
			for _, d := range report.Days {
				rows = append(rows, row(d.Day, d.Metrics))
			}
			rows = append(rows, row("TOTAL", report.Totals))
			table, _ := json.Marshal(rows)
			columns := []string{"DAY"}
			for _, m := range metricNames {
				columns = append(columns, strings.ToUpper(m))
			}
			p.table(table, columns, func(m map[string]any) []string {
				out := []string{str(m, "day")}
				for _, name := range metricNames {
					out = append(out, str(m, name))
				}
				return out
			})
			fmt.Fprintln(p.out)
			for _, x := range report.Now {
				max := "unlimited"
				if x.Max != nil {
					max = strconv.FormatInt(*x.Max, 10)
				}
				fmt.Fprintf(p.out, "%s: %d of %s\n", x.Name, x.Count, max)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&days, "days", 30, "days to show, today included (1–366)")
	return cmd
}
