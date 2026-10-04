package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func operatorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "operators",
		Aliases: []string{"operator"},
		Short:   "Manage workspace operators",
	}
	cmd.AddCommand(operatorsListCmd())
	cmd.AddCommand(operatorsCreateCmd())
	cmd.AddCommand(operatorsDisableCmd())
	cmd.AddCommand(operatorsRoleCmd())
	cmd.AddCommand(operatorsPasswordAccessCmd())
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
	cmd.Flags().StringVar(&role, "role", "", "Role: admin or viewer (required)")
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

func operatorsRoleCmd() *cobra.Command {
	var role string
	cmd := &cobra.Command{
		Use:   "role OPERATOR_ID",
		Short: "Change an operator's role (owner only)",
		Long: "Change an operator's role to owner, admin or viewer. It applies to the\n" +
			"operator's live keys and sessions at once. The last owner cannot step down.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if role != "owner" && role != "admin" && role != "viewer" {
				return fmt.Errorf("--role must be owner, admin or viewer")
			}
			c := mustClient(cmd)
			if _, err := c.put("/operators/"+args[0]+"/role", map[string]string{"role": role}); err != nil {
				return err
			}
			newPrinter().ok("Operator " + args[0] + " is now " + role)
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "", "New role: owner, admin or viewer (required)")
	cmd.MarkFlagRequired("role")
	return cmd
}

func operatorsPasswordAccessCmd() *cobra.Command {
	var allow, deny bool
	cmd := &cobra.Command{
		Use:   "password-access OPERATOR_ID",
		Short: "Grant or remove emergency password sign-in (owner only)",
		Long: "With single sign-on configured, console passwords default to break-glass\n" +
			"mode: only operators granted access here can still sign in with one.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if allow == deny {
				return fmt.Errorf("pass exactly one of --allow or --deny")
			}
			c := mustClient(cmd)
			if _, err := c.put("/operators/"+args[0]+"/password-access", map[string]bool{"allowed": allow}); err != nil {
				return err
			}
			state := "removed from"
			if allow {
				state = "granted to"
			}
			newPrinter().ok("Emergency password access " + state + " " + args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&allow, "allow", false, "Grant emergency password access")
	cmd.Flags().BoolVar(&deny, "deny", false, "Remove emergency password access")
	return cmd
}
