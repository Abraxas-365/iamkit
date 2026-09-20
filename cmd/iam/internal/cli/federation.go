package cli

import "github.com/spf13/cobra"

func federationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "federation",
		Aliases: []string{"fed"},
		Short:   "Manage federation connections (external identity providers)",
	}
	cmd.AddCommand(fedListCmd())
	cmd.AddCommand(fedGetCmd())
	cmd.AddCommand(fedCreateCmd())
	cmd.AddCommand(fedDisableCmd())
	return cmd
}

func fedListCmd() *cobra.Command {
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List federation connections",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/federation-connections" + listQuery(limit, offset, search))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME", "ISSUER", "CLIENT ID", "STATUS", "LINKED"}, func(m map[string]any) []string {
				return []string{
					str(m, "id"), str(m, "name"), str(m, "issuer"),
					str(m, "client_id"), activeStr(m, "active"), str(m, "linked"),
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

func fedGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get CONNECTION_ID",
		Short: "Get connection details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/federation-connections/" + args[0])
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
}

func fedCreateCmd() *cobra.Command {
	var name, issuer, clientID, secretEnv string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a federation connection",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.post(envPath()+"/federation-connections", map[string]string{
				"name": name, "issuer": issuer, "client_id": clientID, "secret_env": secretEnv,
			})
			if err != nil {
				return err
			}
			p.created("federation connection", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Connection name (required)")
	cmd.Flags().StringVar(&issuer, "issuer", "", "OIDC issuer URL (required)")
	cmd.Flags().StringVar(&clientID, "client-id", "", "OAuth client ID (required)")
	cmd.Flags().StringVar(&secretEnv, "secret-env", "", "Env var name holding client secret (required)")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("issuer")
	cmd.MarkFlagRequired("client-id")
	cmd.MarkFlagRequired("secret-env")
	return cmd
}

func fedDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable CONNECTION_ID",
		Short: "Disable a federation connection",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/federation-connections/" + args[0])
			if err != nil {
				return err
			}
			p.ok("Federation connection disabled: " + args[0])
			return nil
		},
	}
}
