package cli

import "github.com/spf13/cobra"

func keysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "keys",
		Aliases: []string{"key"},
		Short:   "Manage management API keys",
	}
	cmd.AddCommand(keysListCmd())
	cmd.AddCommand(keysCreateCmd())
	cmd.AddCommand(keysRevokeCmd())
	return cmd
}

func keysListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List API keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get("/keys")
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "EXPIRES_AT"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "expires_at")}
			})
			return nil
		},
	}
}

func keysCreateCmd() *cobra.Command {
	var expiresIn string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new API key",
		Long:  "Creates a new management API key. The secret is shown only once — save it immediately.",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			var body any
			if expiresIn != "" {
				body = map[string]string{"expires_in": expiresIn}
			}
			data, err := c.post("/keys", body)
			if err != nil {
				return err
			}
			p.JSON(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "Key expiration (e.g. 720h)")
	return cmd
}

func keysRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke KEY_ID",
		Short: "Revoke an API key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete("/keys/" + args[0])
			if err != nil {
				return err
			}
			p.ok("Key revoked: " + args[0])
			return nil
		},
	}
}
