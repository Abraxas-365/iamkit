package cli

import (
	"net/url"
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
	cmd.AddCommand(usersUnlockCmd())
	cmd.AddCommand(usersStateCmd("deactivate", "Suspend a user (audited; ends their sessions)", "User deactivated: "))
	cmd.AddCommand(usersStateCmd("reactivate", "Lift a user's suspension", "User reactivated: "))
	cmd.AddCommand(metadataCmd("users", "user"))
	cmd.AddCommand(usersProfileCmd())
	return cmd
}

func usersStateCmd(action, short, done string) *cobra.Command {
	return &cobra.Command{
		Use:   action + " USER_ID",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.post(envPath()+"/users/"+args[0]+"/"+action, nil); err != nil {
				return err
			}
			newPrinter().ok(done + args[0])
			return nil
		},
	}
}

func usersUnlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock USER_ID",
		Short: "Clear a user's wrong-password count and lockout",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.post(envPath()+"/users/"+args[0]+"/unlock", nil); err != nil {
				return err
			}
			newPrinter().ok("User unlocked: " + args[0])
			return nil
		},
	}
}

func usersListCmd() *cobra.Command {
	var limit, offset int
	var search, state, home string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List users",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			q := listQuery(limit, offset, search)
			if state != "" {
				sep := "?"
				if q != "" {
					sep = "&"
				}
				q += sep + "state=" + url.QueryEscape(state)
			}
			if home != "" {
				sep := "?"
				if q != "" {
					sep = "&"
				}
				q += sep + "home_organization_id=" + url.QueryEscape(home)
			}
			data, err := c.get(envPath() + "/users" + q)
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME", "EMAIL", "STATE"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name"), str(m, "email"), str(m, "state")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	cmd.Flags().StringVar(&state, "state", "", "Only users in this state: suspended, locked, initial, inactive, active")
	cmd.Flags().StringVar(&home, "home-organization", "", "Only users whose record belongs to this organization")
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
	var name, email, password, avatar, username, home string
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
			if avatar != "" {
				body["avatar_url"] = avatar
			}
			if username != "" {
				body["username"] = username
			}
			if home != "" {
				body["home_organization_id"] = home
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
	cmd.Flags().StringVar(&avatar, "avatar-url", "", "Avatar image, an https URL")
	cmd.Flags().StringVar(&username, "username", "", "Username to sign in with besides the email (optional)")
	cmd.Flags().StringVar(&home, "home-organization", "", "Organization that owns the record; the user joins it and its administrators may edit the user")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("email")
	return cmd
}

func usersUpdateCmd() *cobra.Command {
	var name string
	var active string
	var otpEnabled string
	var phone, phoneVerified, avatar, username, home string
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
			if cmd.Flags().Changed("phone") {
				body["phone"] = phone
			}
			if cmd.Flags().Changed("phone-verified") {
				body["phone_verified"] = strings.EqualFold(phoneVerified, "true")
			}
			if cmd.Flags().Changed("avatar-url") {
				body["avatar_url"] = avatar
			}
			if cmd.Flags().Changed("username") {
				body["username"] = username
			}
			if cmd.Flags().Changed("home-organization") {
				body["home_organization_id"] = home
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
	cmd.Flags().StringVar(&phone, "phone", "", `Phone number in E.164, e.g. +14155550100 ("" clears it)`)
	cmd.Flags().StringVar(&phoneVerified, "phone-verified", "", "Mark the phone number verified: true or false (audited)")
	cmd.Flags().StringVar(&avatar, "avatar-url", "", `Avatar image, an https URL ("" removes it)`)
	cmd.Flags().StringVar(&username, "username", "", `Username ("" removes it)`)
	cmd.Flags().StringVar(&home, "home-organization", "", `Organization that owns the record, one the user belongs to ("" clears it)`)
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
