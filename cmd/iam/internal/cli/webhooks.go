package cli

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func webhooksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "webhooks",
		Aliases: []string{"webhook"},
		Short:   "Event webhook subscriptions (signed per Standard Webhooks)",
	}
	cmd.AddCommand(webhooksListCmd(), webhooksGetCmd(), webhooksCreateCmd(), webhooksUpdateCmd(), webhooksDeleteCmd(),
		webhooksRotateCmd(), webhooksTestCmd(), webhooksReplayCmd(), webhooksDeliveriesCmd(), webhooksRetryCmd())
	return cmd
}

func webhookPath(id string) string { return envPath() + "/webhooks/" + url.PathEscape(id) }

func typesColumn(m map[string]any) string {
	types, _ := m["types"].([]any)
	if len(types) == 0 {
		return "*"
	}
	out := make([]string, len(types))
	for i, t := range types {
		out[i], _ = t.(string)
	}
	return strings.Join(out, ",")
}

func webhooksListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List webhook subscriptions",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/webhooks")
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "NAME", "URL", "EVENTS", "ACTIVE", "FAILING SINCE", "PENDING"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name"), str(m, "url"), typesColumn(m), str(m, "active"), str(m, "failing_since"), str(m, "pending")}
			})
			return nil
		},
	}
}

func webhooksGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get ID",
		Short: "Show a webhook subscription",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(webhookPath(args[0]))
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func webhooksCreateCmd() *cobra.Command {
	var name, endpoint, types string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Subscribe an endpoint to events (the signing secret is shown once)",
		Example: `  iam webhooks create --name CRM --url https://crm.example/iam --types "user.*,membership.created"
  iam webhooks create --name Everything --url https://hooks.example/all`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).post(envPath()+"/webhooks", map[string]any{"name": name, "url": endpoint, "types": splitCSV(types)})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Name (required)")
	cmd.Flags().StringVar(&endpoint, "url", "", "HTTPS endpoint (required; http only for localhost)")
	cmd.Flags().StringVar(&types, "types", "", "Comma-separated event types or families (empty = every event)")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("url")
	return cmd
}

func webhooksUpdateCmd() *cobra.Command {
	var name, endpoint, types string
	var allTypes, enable, disable bool
	cmd := &cobra.Command{
		Use:   "update ID",
		Short: "Change a subscription; --enable resumes a disabled one",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if cmd.Flags().Changed("name") {
				body["name"] = name
			}
			if cmd.Flags().Changed("url") {
				body["url"] = endpoint
			}
			if cmd.Flags().Changed("types") {
				body["types"] = splitCSV(types)
			}
			if allTypes {
				body["types"] = []string{}
			}
			if enable {
				body["active"] = true
			}
			if disable {
				body["active"] = false
			}
			data, err := mustClient(cmd).patch(webhookPath(args[0]), body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Name")
	cmd.Flags().StringVar(&endpoint, "url", "", "Endpoint URL")
	cmd.Flags().StringVar(&types, "types", "", "Comma-separated event types or families")
	cmd.Flags().BoolVar(&allTypes, "all-events", false, "Subscribe to every event")
	cmd.Flags().BoolVar(&enable, "enable", false, "Resume delivery")
	cmd.Flags().BoolVar(&disable, "disable", false, "Pause delivery (events keep queuing)")
	cmd.MarkFlagsMutuallyExclusive("enable", "disable")
	cmd.MarkFlagsMutuallyExclusive("types", "all-events")
	return cmd
}

func webhooksDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete ID",
		Short: "Delete a subscription and its pending deliveries",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(webhookPath(args[0])); err != nil {
				return err
			}
			newPrinter().ok("Webhook deleted: " + args[0])
			return nil
		},
	}
}

func webhooksRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate-secret ID",
		Short: "Issue a new signing secret (the previous one keeps signing for 24 hours)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).post(webhookPath(args[0])+"/rotate-secret", map[string]any{})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func webhooksTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test ID",
		Short: "Send a webhook.test event now",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).post(webhookPath(args[0])+"/test", map[string]any{})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func webhooksReplayCmd() *cobra.Command {
	var from int64
	cmd := &cobra.Command{
		Use:   "replay ID --from EVENT_ID",
		Short: "Queue the subscription's events from an event id again (at most 10,000)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).post(webhookPath(args[0])+"/replay", map[string]any{"from": from})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().Int64Var(&from, "from", 0, "First event id (see iam events list)")
	cmd.MarkFlagRequired("from")
	return cmd
}

func webhooksDeliveriesCmd() *cobra.Command {
	var status string
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "deliveries ID",
		Short: "List a subscription's deliveries, newest first",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			if status != "" {
				params.Set("status", status)
			}
			if limit > 0 {
				params.Set("limit", strconv.Itoa(limit))
			}
			if offset > 0 {
				params.Set("offset", strconv.Itoa(offset))
			}
			path := webhookPath(args[0]) + "/deliveries"
			if len(params) > 0 {
				path += "?" + params.Encode()
			}
			data, err := mustClient(cmd).get(path)
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "EVENT", "TYPE", "STATUS", "ATTEMPTS", "HTTP", "LAST ERROR", "QUEUED"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "event_id"), str(m, "event_type"), str(m, "status"), str(m, "attempts"), str(m, "response_status"), str(m, "last_error"), str(m, "queued_at")}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&status, "status", "", "pending, delivered or failed")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	return cmd
}

func webhooksRetryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "retry ID DELIVERY_ID",
		Short: "Send a failed delivery again",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).post(webhookPath(args[0])+"/deliveries/"+url.PathEscape(args[1])+"/retry", map[string]any{}); err != nil {
				return err
			}
			newPrinter().ok("Delivery queued again: " + args[1])
			return nil
		},
	}
}
