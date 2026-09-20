package cli

import "github.com/spf13/cobra"

func organizationsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "organizations",
		Aliases: []string{"org", "orgs"},
		Short:   "Manage organizations",
	}
	cmd.AddCommand(orgsListCmd())
	cmd.AddCommand(orgsGetCmd())
	cmd.AddCommand(orgsCreateCmd())
	cmd.AddCommand(orgsUpdateCmd())
	cmd.AddCommand(orgsMembersCmd())
	return cmd
}

func orgsListCmd() *cobra.Command {
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List organizations",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/organizations" + listQuery(limit, offset, search))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	return cmd
}

func orgsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get ORG_ID",
		Short: "Get organization details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/organizations/" + args[0])
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
}

func orgsCreateCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.post(envPath()+"/organizations", map[string]string{"name": name})
			if err != nil {
				return err
			}
			p.created("organization", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Organization name (required)")
	cmd.MarkFlagRequired("name")
	return cmd
}

func orgsUpdateCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "update ORG_ID",
		Short: "Update an organization",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]any{}
			if cmd.Flags().Changed("name") {
				body["name"] = name
			}
			_, err := c.patch(envPath()+"/organizations/"+args[0], body)
			if err != nil {
				return err
			}
			p.ok("Organization updated: " + args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "New name")
	return cmd
}

// --- Members subcommand ---

func orgsMembersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "members",
		Aliases: []string{"member"},
		Short:   "Manage organization members",
	}
	cmd.AddCommand(orgsMembersListCmd())
	cmd.AddCommand(orgsMembersAddCmd())
	cmd.AddCommand(orgsMembersRemoveCmd())
	return cmd
}

func orgsMembersListCmd() *cobra.Command {
	var org string
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List members of an organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/organizations/" + org + "/members" + listQuery(limit, offset, ""))
			if err != nil {
				return err
			}
			p.table(data, []string{"USER_ID", "NAME", "EMAIL"}, func(m map[string]any) []string {
				return []string{str(m, "user_id"), str(m, "name"), str(m, "email")}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.MarkFlagRequired("org")
	return cmd
}

func orgsMembersAddCmd() *cobra.Command {
	var org, user string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a user to an organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.post(envPath()+"/memberships", map[string]string{
				"organization_id": org,
				"user_id":         user,
			})
			if err != nil {
				return err
			}
			p.ok("Added user " + user + " to organization " + org)
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&user, "user", "", "User ID (required)")
	cmd.MarkFlagRequired("org")
	cmd.MarkFlagRequired("user")
	return cmd
}

func orgsMembersRemoveCmd() *cobra.Command {
	var org, user string
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a user from an organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/organizations/" + org + "/members/" + user)
			if err != nil {
				return err
			}
			p.ok("Removed user " + user + " from organization " + org)
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&user, "user", "", "User ID (required)")
	cmd.MarkFlagRequired("org")
	cmd.MarkFlagRequired("user")
	return cmd
}
