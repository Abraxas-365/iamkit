package cli

import "github.com/spf13/cobra"

func rolesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "roles",
		Aliases: []string{"role"},
		Short:   "Manage roles and role assignments",
	}
	cmd.AddCommand(rolesListCmd())
	cmd.AddCommand(rolesGetCmd())
	cmd.AddCommand(rolesCreateCmd())
	cmd.AddCommand(rolesUpdateCmd())
	cmd.AddCommand(rolesDeleteCmd())
	cmd.AddCommand(roleAssignmentsCmd())
	return cmd
}

func rolesListCmd() *cobra.Command {
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List roles",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/roles" + listQuery(limit, offset, search))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME", "RESOURCE", "PERMISSIONS"}, func(m map[string]any) []string {
				res := str(m, "resource_name")
				if res == "" {
					res = str(m, "resource_id")
				}
				return []string{str(m, "id"), str(m, "name"), res, collapsePerms(m["permissions"])}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	return cmd
}

func rolesGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get ROLE_ID",
		Short: "Get role details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/roles/" + args[0])
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
}

func rolesCreateCmd() *cobra.Command {
	var name, resource, permissions string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a role",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.post(envPath()+"/roles", map[string]any{
				"name": name, "resource_id": resource, "permissions": splitCSV(permissions),
			})
			if err != nil {
				return err
			}
			p.created("role", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Role name (required)")
	cmd.Flags().StringVar(&resource, "resource", "", "Resource ID (required)")
	cmd.Flags().StringVar(&permissions, "permissions", "", "Comma-separated permissions (required)")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("resource")
	cmd.MarkFlagRequired("permissions")
	return cmd
}

func rolesUpdateCmd() *cobra.Command {
	var name, resource, permissions string
	cmd := &cobra.Command{
		Use:   "update ROLE_ID",
		Short: "Update a role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]any{}
			if cmd.Flags().Changed("name") {
				body["name"] = name
			}
			if cmd.Flags().Changed("resource") {
				body["resource_id"] = resource
			}
			if cmd.Flags().Changed("permissions") {
				body["permissions"] = splitCSV(permissions)
			}
			_, err := c.put(envPath()+"/roles/"+args[0], body)
			if err != nil {
				return err
			}
			p.ok("Role updated: " + args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "New name")
	cmd.Flags().StringVar(&resource, "resource", "", "Resource ID")
	cmd.Flags().StringVar(&permissions, "permissions", "", "Comma-separated permissions")
	return cmd
}

func rolesDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete ROLE_ID",
		Short: "Delete a role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/roles/" + args[0])
			if err != nil {
				return err
			}
			p.ok("Role deleted: " + args[0])
			return nil
		},
	}
}

// --- Role assignments ---

func roleAssignmentsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "assignments",
		Aliases: []string{"assignment", "assign"},
		Short:   "Manage role assignments",
	}
	cmd.AddCommand(roleAssignmentsListCmd())
	cmd.AddCommand(roleAssignmentsAssignCmd())
	cmd.AddCommand(roleAssignmentsRemoveCmd())
	return cmd
}

func roleAssignmentsListCmd() *cobra.Command {
	var roleID, orgID, userID, resourceID string
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List role assignments",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			q := listQuery(limit, offset, search)
			// Append filter params
			sep := "?"
			if q != "" {
				sep = "&"
			}
			filters := ""
			if roleID != "" {
				filters += sep + "role_id=" + roleID
				sep = "&"
			}
			if orgID != "" {
				filters += sep + "organization_id=" + orgID
				sep = "&"
			}
			if userID != "" {
				filters += sep + "user_id=" + userID
				sep = "&"
			}
			if resourceID != "" {
				filters += sep + "resource_id=" + resourceID
			}
			data, err := c.get(envPath() + "/role-assignments" + q + filters)
			if err != nil {
				return err
			}
			p.table(data, []string{"ROLE", "ROLE NAME", "ORGANIZATION", "USER", "RESOURCE"}, func(m map[string]any) []string {
				return []string{
					str(m, "role_id"), str(m, "role_name"),
					str(m, "organization_name"), str(m, "user_name"),
					str(m, "resource_name"),
				}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&roleID, "role", "", "Filter by role ID")
	cmd.Flags().StringVar(&orgID, "org", "", "Filter by organization ID")
	cmd.Flags().StringVar(&userID, "user", "", "Filter by user ID")
	cmd.Flags().StringVar(&resourceID, "resource", "", "Filter by resource ID")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	return cmd
}

func roleAssignmentsAssignCmd() *cobra.Command {
	var org, user, role string
	cmd := &cobra.Command{
		Use:   "assign",
		Short: "Assign a role to a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.post(envPath()+"/role-assignments", map[string]string{
				"organization_id": org, "user_id": user, "role_id": role,
			})
			if err != nil {
				return err
			}
			p.ok("Role " + role + " assigned to user " + user + " in org " + org)
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&user, "user", "", "User ID (required)")
	cmd.Flags().StringVar(&role, "role", "", "Role ID (required)")
	cmd.MarkFlagRequired("org")
	cmd.MarkFlagRequired("user")
	cmd.MarkFlagRequired("role")
	return cmd
}

func roleAssignmentsRemoveCmd() *cobra.Command {
	var role, org, user string
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a role assignment",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/role-assignments/" + role + "/" + org + "/" + user)
			if err != nil {
				return err
			}
			p.ok("Unassigned role " + role + " from user " + user + " in org " + org)
			return nil
		},
	}
	cmd.Flags().StringVar(&role, "role", "", "Role ID (required)")
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&user, "user", "", "User ID (required)")
	cmd.MarkFlagRequired("role")
	cmd.MarkFlagRequired("org")
	cmd.MarkFlagRequired("user")
	return cmd
}
