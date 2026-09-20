package cli

import "github.com/spf13/cobra"

func sessionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "sessions",
		Aliases: []string{"session"},
		Short:   "View and revoke user sessions",
	}
	cmd.AddCommand(sessionsListCmd())
	cmd.AddCommand(sessionsRevokeCmd())
	return cmd
}

func sessionsListCmd() *cobra.Command {
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/sessions" + listQuery(limit, offset, ""))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "USER", "CREATED", "EXPIRES"}, func(m map[string]any) []string {
				usr := str(m, "user_name")
				if usr == "" {
					usr = str(m, "user_id")
				}
				return []string{str(m, "id"), usr, str(m, "created_at"), str(m, "expires_at")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	return cmd
}

func sessionsRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke SESSION_ID",
		Short: "Revoke a session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/sessions/" + args[0])
			if err != nil {
				return err
			}
			p.ok("Session revoked: " + args[0])
			return nil
		},
	}
}
