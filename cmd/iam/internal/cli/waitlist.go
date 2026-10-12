package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/spf13/cobra"
)

func waitlistCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "waitlist",
		Short: "Review the sign-up waitlist (turn it on with iam sign-in-policy set --waitlist)",
		Long: `Review the sign-up waitlist. With the waitlist on, people who ask to sign up
are listed as pending until an operator approves them: approving emails them a
single-use sign-up link (valid 7 days), rejecting is silent unless --notify,
and deleting an entry lets the address join again. Federation, invitations,
SCIM and operator-created users never wait.`,
	}
	cmd.AddCommand(waitlistListCmd(), waitlistGetCmd(), waitlistApproveCmd(), waitlistRejectCmd(), waitlistDeleteCmd())
	return cmd
}

func waitlistPath(id string) string { return envPath() + "/waitlist/" + url.PathEscape(id) }

func waitlistListCmd() *cobra.Command {
	var status, email string
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List waitlist entries, newest first",
		Example: `  iam waitlist list --status pending
  iam waitlist list --email ana`,
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			if status != "" {
				params.Set("status", status)
			}
			if email != "" {
				params.Set("email", email)
			}
			if limit > 0 {
				params.Set("limit", strconv.Itoa(limit))
			}
			if offset > 0 {
				params.Set("offset", strconv.Itoa(offset))
			}
			path := envPath() + "/waitlist"
			if len(params) > 0 {
				path += "?" + params.Encode()
			}
			data, err := mustClient(cmd).get(path)
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "EMAIL", "NAME", "STATUS", "CREATED", "DECIDED"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "email"), str(m, "name"), str(m, "status"), str(m, "created_at"), str(m, "decided_at")}
			})
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&status, "status", "", "pending, approved, rejected or completed")
	f.StringVar(&email, "email", "", "Email prefix")
	f.IntVar(&limit, "limit", 0, "Max results")
	f.IntVar(&offset, "offset", 0, "Offset")
	return cmd
}

func waitlistGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get ID",
		Short: "Show a waitlist entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(waitlistPath(args[0]))
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func waitlistApproveCmd() *cobra.Command {
	var allPending bool
	cmd := &cobra.Command{
		Use:   "approve ID... | --all-pending",
		Short: "Approve entries and email each person their sign-up link",
		Long: `Approve the listed entries, or every pending one with --all-pending (oldest
first, in batches of at most 500 until none remain). Approving an approved
entry sends a new link.`,
		Example: `  iam waitlist approve ID
  iam waitlist approve --all-pending`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if allPending == (len(args) > 0) {
				return errors.New("give entry ids or --all-pending, not both and not neither")
			}
			c := mustClient(cmd)
			if len(args) == 1 {
				data, err := c.post(waitlistPath(args[0])+"/approve", map[string]any{})
				if err != nil {
					return err
				}
				newPrinter().detail(data)
				return nil
			}
			body := map[string]any{"all_pending": true}
			if !allPending {
				body = map[string]any{"ids": args}
			}
			var approved, skipped int
			for {
				data, err := c.post(envPath()+"/waitlist/approve", body)
				if err != nil {
					return err
				}
				var out struct {
					Approved int  `json:"approved"`
					Skipped  int  `json:"skipped"`
					More     bool `json:"more"`
				}
				if err := json.Unmarshal(data, &out); err != nil {
					return err
				}
				approved += out.Approved
				skipped += out.Skipped
				// Stop when nothing moved, or a loop would never end.
				if !allPending || !out.More || out.Approved == 0 {
					break
				}
			}
			newPrinter().ok(fmt.Sprintf("Approved: %d, skipped: %d", approved, skipped))
			return nil
		},
	}
	cmd.Flags().BoolVar(&allPending, "all-pending", false, "Approve every pending entry")
	return cmd
}

func waitlistRejectCmd() *cobra.Command {
	var notify bool
	cmd := &cobra.Command{
		Use:   "reject ID",
		Short: "Reject an entry (silent unless --notify)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).post(waitlistPath(args[0])+"/reject", map[string]any{"notify": notify})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().BoolVar(&notify, "notify", false, "Email the person that they were not accepted")
	return cmd
}

func waitlistDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete ID",
		Short: "Delete an entry, so its email can join again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(waitlistPath(args[0])); err != nil {
				return err
			}
			newPrinter().ok("Waitlist entry deleted: " + args[0])
			return nil
		},
	}
}
