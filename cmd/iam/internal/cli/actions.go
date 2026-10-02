package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func actionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "actions",
		Aliases: []string{"action"},
		Short:   "Actions: call your endpoints during sign-in, token issuance and management requests",
	}
	targets := &cobra.Command{Use: "targets", Aliases: []string{"target"}, Short: "Endpoints actions call (signed per Standard Webhooks)"}
	targets.AddCommand(actionTargetsListCmd(), actionTargetsGetCmd(), actionTargetsCreateCmd(), actionTargetsUpdateCmd(),
		actionTargetsDeleteCmd(), actionTargetsRotateCmd(), actionTargetsTestCmd())
	cmd.AddCommand(targets, actionConditionsCmd(), actionExecutionsCmd(), actionSetCmd(), actionClearCmd(), actionCallsCmd())
	return cmd
}

func actionTargetPath(id string) string { return envPath() + "/action-targets/" + url.PathEscape(id) }

// actionExecutionPath escapes the condition (function:pre_sign_in).
func actionExecutionPath(condition string) string {
	return envPath() + "/action-executions/" + url.PathEscape(condition)
}

func actionTargetsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List action targets",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/action-targets")
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "NAME", "URL", "KIND", "TIMEOUT MS", "INTERRUPT ON ERROR"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name"), str(m, "url"), str(m, "kind"), str(m, "timeout_ms"), str(m, "interrupt_on_error")}
			})
			return nil
		},
	}
}

func actionTargetsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get ID",
		Short: "Show an action target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(actionTargetPath(args[0]))
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func actionTargetsCreateCmd() *cobra.Command {
	var name, endpoint, kind string
	var timeout int
	var interrupt bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Register an endpoint (the signing secret is shown once)",
		Example: `  iam actions targets create --name Risk --url https://risk.example/iam --interrupt-on-error
  iam actions targets create --name Audit --url https://audit.example/iam --kind async`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).post(envPath()+"/action-targets", map[string]any{"name": name, "url": endpoint, "kind": kind, "timeout_ms": timeout, "interrupt_on_error": interrupt})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Name (required)")
	cmd.Flags().StringVar(&endpoint, "url", "", "HTTPS endpoint (required; http only for localhost)")
	cmd.Flags().StringVar(&kind, "kind", "call", "call (apply the answer), webhook (2xx only) or async (background)")
	cmd.Flags().IntVar(&timeout, "timeout-ms", 0, "Call timeout in milliseconds (default 5000, at most 10000)")
	cmd.Flags().BoolVar(&interrupt, "interrupt-on-error", false, "Stop the flow when the target fails (not for async)")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("url")
	return cmd
}

func actionTargetsUpdateCmd() *cobra.Command {
	var name, endpoint, kind string
	var timeout int
	var interrupt bool
	cmd := &cobra.Command{
		Use:   "update ID",
		Short: "Change an action target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if cmd.Flags().Changed("name") {
				body["name"] = name
			}
			if cmd.Flags().Changed("url") {
				body["url"] = endpoint
			}
			if cmd.Flags().Changed("kind") {
				body["kind"] = kind
			}
			if cmd.Flags().Changed("timeout-ms") {
				body["timeout_ms"] = timeout
			}
			if cmd.Flags().Changed("interrupt-on-error") {
				body["interrupt_on_error"] = interrupt
			}
			data, err := mustClient(cmd).patch(actionTargetPath(args[0]), body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Name")
	cmd.Flags().StringVar(&endpoint, "url", "", "Endpoint URL")
	cmd.Flags().StringVar(&kind, "kind", "", "call, webhook or async")
	cmd.Flags().IntVar(&timeout, "timeout-ms", 0, "Call timeout in milliseconds")
	cmd.Flags().BoolVar(&interrupt, "interrupt-on-error", false, "Stop the flow when the target fails (--interrupt-on-error=false to continue)")
	return cmd
}

func actionTargetsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete ID",
		Short: "Delete a target (it is removed from every condition)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(actionTargetPath(args[0])); err != nil {
				return err
			}
			newPrinter().ok("Action target deleted: " + args[0])
			return nil
		},
	}
}

func actionTargetsRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate-secret ID",
		Short: "Issue a new signing secret (the previous one keeps signing for 24 hours)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).post(actionTargetPath(args[0])+"/rotate-secret", map[string]any{})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func actionTargetsTestCmd() *cobra.Command {
	var condition, input string
	cmd := &cobra.Command{
		Use:     "test ID",
		Short:   "Call a target with a sample input; the answer is shown, never applied",
		Example: `  iam actions targets test 0190… --condition function:pre_sign_in --input '{"user":{"email":"ada@example.com"}}'`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{"condition": condition}
			if input != "" {
				if !json.Valid([]byte(input)) {
					return fmt.Errorf("--input is not valid JSON")
				}
				body["input"] = json.RawMessage(input)
			}
			data, err := mustClient(cmd).post(actionTargetPath(args[0])+"/test", body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&condition, "condition", "", "Condition to simulate (see iam actions conditions)")
	cmd.Flags().StringVar(&input, "input", "", "JSON input fields to send (user, organization_id, request, …)")
	cmd.MarkFlagRequired("condition")
	return cmd
}

func actionConditionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "conditions",
		Short: "List the conditions targets can be bound to and what they may answer",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/action-conditions")
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"CONDITION", "DENY", "CLAIMS", "PATCH", "DESCRIPTION"}, func(m map[string]any) []string {
				return []string{str(m, "name"), str(m, "deny"), str(m, "claims"), joinColumn(m, "patch"), str(m, "description")}
			})
			return nil
		},
	}
}

func actionExecutionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "executions",
		Short: "List the conditions with targets, in call order",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/action-executions")
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"CONDITION", "TARGETS", "UPDATED"}, func(m map[string]any) []string {
				return []string{str(m, "condition"), joinColumn(m, "targets"), str(m, "updated_at")}
			})
			return nil
		},
	}
}

func actionSetCmd() *cobra.Command {
	var targets string
	cmd := &cobra.Command{
		Use:     "set CONDITION --targets ID[,ID…]",
		Short:   "Choose the targets a condition calls, in order",
		Example: `  iam actions set function:pre_sign_in --targets 0190…,0191…`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).put(actionExecutionPath(args[0]), map[string]any{"targets": splitCSV(targets)})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&targets, "targets", "", "Comma-separated target ids, in call order (required)")
	cmd.MarkFlagRequired("targets")
	return cmd
}

func actionClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear CONDITION",
		Short: "Stop calling targets for a condition",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(actionExecutionPath(args[0])); err != nil {
				return err
			}
			newPrinter().ok("Condition cleared: " + args[0])
			return nil
		},
	}
}

func actionCallsCmd() *cobra.Command {
	var target, condition, outcome string
	var limit int
	cmd := &cobra.Command{
		Use:   "calls",
		Short: "List recent target calls, newest first (kept 7 days)",
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			for key, value := range map[string]string{"target_id": target, "condition": condition, "outcome": outcome} {
				if value != "" {
					params.Set(key, value)
				}
			}
			if limit > 0 {
				params.Set("limit", strconv.Itoa(limit))
			}
			path := envPath() + "/action-calls"
			if len(params) > 0 {
				path += "?" + params.Encode()
			}
			data, err := mustClient(cmd).get(path)
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "TARGET", "CONDITION", "OUTCOME", "HTTP", "MS", "ERROR", "AT"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "target_id"), str(m, "condition"), str(m, "outcome"), str(m, "status"), str(m, "duration_ms"), str(m, "error"), str(m, "created_at")}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "Only this target id")
	cmd.Flags().StringVar(&condition, "condition", "", "Only this condition")
	cmd.Flags().StringVar(&outcome, "outcome", "", "ok, denied, failed or skipped")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results (default 50)")
	return cmd
}

// joinColumn joins a string-array member for a table cell.
func joinColumn(m map[string]any, key string) string {
	items, _ := m[key].([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return strings.Join(out, ",")
}
