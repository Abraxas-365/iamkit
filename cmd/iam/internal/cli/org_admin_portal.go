package cli

import (
	"github.com/spf13/cobra"
)

func orgAdminPortalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "org-admin-portal",
		Short: "Turn the hosted organization admin portal on or off",
		Long: `The organization admin portal is a page IAMKit hosts at
/org-admin/<environment> where your customers' administrators manage their
own organization: members, users, roles, invitations, domains, single
sign-on, branding and password rules. They sign in through the hosted login
and see only what their organization roles (iam:org:*) allow.

Turning it on registers IAMKit's own public OAuth client on the IAM
resource (operators cannot edit it). Turning it off signs everyone out of
the portal at once; the organization admin API keeps working for your own
app.`,
	}
	cmd.AddCommand(orgAdminPortalGetCmd(), orgAdminPortalEnableCmd(), orgAdminPortalDisableCmd())
	return cmd
}

func orgAdminPortalGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Show whether the portal is on and its link",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/org-admin-portal")
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func orgAdminPortalEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "enable",
		Short:   "Turn the portal on (idempotent)",
		Example: `  iam org-admin-portal enable`,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).put(envPath()+"/org-admin-portal", map[string]any{})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func orgAdminPortalDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Turn the portal off and sign everyone out of it",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(envPath() + "/org-admin-portal"); err != nil {
				return err
			}
			newPrinter().ok("Organization admin portal turned off")
			return nil
		},
	}
}
