package cli

import "github.com/spf13/cobra"

func serviceAccountsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "service-accounts",
		Aliases: []string{"sa"},
		Short:   "Manage service accounts",
	}
	cmd.AddCommand(saListCmd())
	cmd.AddCommand(saCreateCmd())
	cmd.AddCommand(saRevokeCmd())
	return cmd
}

func saListCmd() *cobra.Command {
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List service accounts",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/service-accounts" + listQuery(limit, offset, search))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME", "APPLICATION", "RESOURCE", "PERMISSIONS", "EXPIRES", "STATUS"}, func(m map[string]any) []string {
				app := str(m, "application_name")
				if app == "" {
					app = truncateID(str(m, "application_id"))
				}
				res := str(m, "resource_name")
				if res == "" {
					res = truncateID(str(m, "resource_id"))
				}
				status := "active"
				if str(m, "revoked_at") != "" && str(m, "revoked_at") != "<nil>" {
					status = "revoked"
				}
				return []string{
					str(m, "id"), str(m, "name"), app, res,
					collapsePerms(m["permissions"]), str(m, "expires_at"), status,
				}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	return cmd
}

func saCreateCmd() *cobra.Command {
	var name, app, resource, permissions, expiresIn string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a service account",
		Long:  "Creates a service account. The secret is shown only once — save it immediately.",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]any{
				"name": name, "application_id": app,
				"resource_id": resource, "permissions": splitCSV(permissions),
			}
			if expiresIn != "" {
				body["expires_in"] = expiresIn
			}
			data, err := c.post(envPath()+"/service-accounts", body)
			if err != nil {
				return err
			}
			// Always output full JSON — the secret must be captured.
			p.JSON(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Service account name (required)")
	cmd.Flags().StringVar(&app, "app", "", "Application ID (required)")
	cmd.Flags().StringVar(&resource, "resource", "", "Resource ID (required)")
	cmd.Flags().StringVar(&permissions, "permissions", "", "Comma-separated permissions (required)")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "Expiration (e.g. 720h, default: 24h)")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("app")
	cmd.MarkFlagRequired("resource")
	cmd.MarkFlagRequired("permissions")
	return cmd
}

func saRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke ACCOUNT_ID",
		Short: "Revoke a service account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/service-accounts/" + args[0])
			if err != nil {
				return err
			}
			p.ok("Service account revoked: " + args[0])
			return nil
		},
	}
}
