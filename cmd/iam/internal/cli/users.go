package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

func usersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "users",
		Aliases: []string{"user"},
		Short:   "Manage users",
	}
	cmd.AddCommand(usersListCmd())
	cmd.AddCommand(usersGetCmd())
	cmd.AddCommand(usersCreateCmd())
	cmd.AddCommand(usersUpdateCmd())
	cmd.AddCommand(usersSuspendCmd())
	return cmd
}

func usersListCmd() *cobra.Command {
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List users",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/users" + listQuery(limit, offset, search))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME", "EMAIL", "STATUS"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name"), str(m, "email"), activeStr(m, "active")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	return cmd
}

func usersGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get USER_ID",
		Short: "Get user details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/users/" + args[0])
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
}

func usersCreateCmd() *cobra.Command {
	var name, email, password string
	var otpEnabled bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]any{"name": name, "email": email}
			if password != "" {
				body["password"] = password
			}
			if otpEnabled {
				body["otp_enabled"] = true
			}
			data, err := c.post(envPath()+"/users", body)
			if err != nil {
				return err
			}
			p.created("user", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "User name (required)")
	cmd.Flags().StringVar(&email, "email", "", "User email (required)")
	cmd.Flags().StringVar(&password, "password", "", "User password")
	cmd.Flags().BoolVar(&otpEnabled, "otp", false, "Enable OTP")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("email")
	return cmd
}

func usersUpdateCmd() *cobra.Command {
	var name string
	var active string
	var otpEnabled string
	cmd := &cobra.Command{
		Use:   "update USER_ID",
		Short: "Update a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]any{}
			if cmd.Flags().Changed("name") {
				body["name"] = name
			}
			if cmd.Flags().Changed("active") {
				body["active"] = strings.EqualFold(active, "true")
			}
			if cmd.Flags().Changed("otp") {
				body["otp_enabled"] = strings.EqualFold(otpEnabled, "true")
			}
			_, err := c.patch(envPath()+"/users/"+args[0], body)
			if err != nil {
				return err
			}
			p.ok("User updated: " + args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "New name")
	cmd.Flags().StringVar(&active, "active", "", "true or false")
	cmd.Flags().StringVar(&otpEnabled, "otp", "", "true or false")
	return cmd
}

func usersSuspendCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "suspend USER_ID",
		Short: "Suspend a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/users/" + args[0])
			if err != nil {
				return err
			}
			p.ok("User suspended: " + args[0])
			return nil
		},
	}
}
