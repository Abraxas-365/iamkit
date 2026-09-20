package cli

import "github.com/spf13/cobra"

func operatorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "operators",
		Aliases: []string{"operator"},
		Short:   "Manage workspace operators",
	}
	cmd.AddCommand(operatorsListCmd())
	cmd.AddCommand(operatorsCreateCmd())
	cmd.AddCommand(operatorsDisableCmd())
	return cmd
}

func operatorsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List operators",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get("/operators")
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "EMAIL", "ROLE", "ACTIVE"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "email"), str(m, "role"), activeStr(m, "active")}
			})
			return nil
		},
	}
}

func operatorsCreateCmd() *cobra.Command {
	var email, role, expiresIn string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create (delegate) an operator",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]string{"email": email, "role": role}
			if expiresIn != "" {
				body["expires_in"] = expiresIn
			}
			data, err := c.post("/operators", body)
			if err != nil {
				return err
			}
			p.JSON(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "Operator email (required)")
	cmd.Flags().StringVar(&role, "role", "", "Role: owner, admin, viewer (required)")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "Credential expiration (e.g. 24h)")
	cmd.MarkFlagRequired("email")
	cmd.MarkFlagRequired("role")
	return cmd
}

func operatorsDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable OPERATOR_ID",
		Short: "Disable an operator",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete("/operators/" + args[0])
			if err != nil {
				return err
			}
			p.ok("Operator disabled: " + args[0])
			return nil
		},
	}
}
