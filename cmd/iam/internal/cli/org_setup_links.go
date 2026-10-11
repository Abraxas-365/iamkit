package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// orgsSetupLinkCmd manages an organization's setup links.
func orgsSetupLinkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "setup-link",
		Aliases: []string{"setup-links"},
		Short:   "Give an organization's IT administrator a setup link",
		Long: `Setup links open a restricted organization admin portal for the customer's
IT administrator, who needs no IAMKit account, to configure single sign-on
(sso), SCIM directory sync (directory) and verified domains (domains).
A link expires (7 days by default, at most 30) and can be revoked, which
also ends the sessions already opened from it.`,
	}
	cmd.AddCommand(orgsSetupLinkCreateCmd())
	cmd.AddCommand(orgsSetupLinkListCmd())
	cmd.AddCommand(orgsSetupLinkRevokeCmd())
	return cmd
}

func setupLinksPath(org string) string { return envPath() + "/organizations/" + org + "/setup-links" }

func orgsSetupLinkCreateCmd() *cobra.Command {
	var intents []string
	var expiresIn string
	cmd := &cobra.Command{
		Use:   "create ORG_ID",
		Short: "Create a setup link (the URL is shown once)",
		Example: `  iam organizations setup-link create ORG_ID --intent sso --intent directory
  iam organizations setup-link create ORG_ID --intent domains --expires-in 72h`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{"intents": intents}
			if expiresIn != "" {
				body["expires_in"] = expiresIn
			}
			data, err := mustClient(cmd).post(setupLinksPath(args[0]), body)
			if err != nil {
				return err
			}
			p := newPrinter()
			if !p.wantJSON() {
				fmt.Fprintln(os.Stderr, "The URL is shown once: copy it now.")
			}
			p.detail(data)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&intents, "intent", nil, "What the link may configure: "+strings.Join([]string{"sso", "directory", "domains"}, ", ")+" (repeatable, required)")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "Lifetime as a duration, e.g. 72h (default 168h, max 720h)")
	cmd.MarkFlagRequired("intent")
	return cmd
}

func orgsSetupLinkListCmd() *cobra.Command {
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list ORG_ID",
		Short: "List the organization's setup links (never their secrets)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(setupLinksPath(args[0]) + listQuery(limit, offset, ""))
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "INTENTS", "EXPIRES", "REVOKED", "LAST USED"}, func(m map[string]any) []string {
				intents := []string{}
				if list, ok := m["intents"].([]any); ok {
					for _, i := range list {
						intents = append(intents, fmt.Sprint(i))
					}
				}
				return []string{str(m, "id"), strings.Join(intents, ","), str(m, "expires_at"), str(m, "revoked_at"), str(m, "last_used_at")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	return cmd
}

func orgsSetupLinkRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke ORG_ID LINK_ID",
		Short: "Revoke a setup link and the sessions opened from it",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(setupLinksPath(args[0]) + "/" + args[1]); err != nil {
				return err
			}
			newPrinter().ok("Revoked setup link " + args[1])
			return nil
		},
	}
}
