package cli

import (
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

// groupsCmd manages an organization's groups, their members, and the roles
// every member holds through them.
func groupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "groups",
		Aliases: []string{"group"},
		Short:   "Manage organization groups and the roles they grant",
	}
	cmd.AddCommand(groupsListCmd())
	cmd.AddCommand(groupsGetCmd())
	cmd.AddCommand(groupsCreateCmd())
	cmd.AddCommand(groupsUpdateCmd())
	cmd.AddCommand(groupsDeleteCmd())
	cmd.AddCommand(groupsMembersCmd())
	cmd.AddCommand(groupsRolesCmd())
	return cmd
}

func groupsPath(org string) string {
	return envPath() + "/organizations/" + org + "/groups"
}

// withQuery appends the non-empty filters to a listQuery result.
func withQuery(q string, filters map[string]string) string {
	params := url.Values{}
	for k, v := range filters {
		if v != "" {
			params.Set(k, v)
		}
	}
	if len(params) == 0 {
		return q
	}
	if q == "" {
		return "?" + params.Encode()
	}
	return q + "&" + params.Encode()
}

func groupSource(m map[string]any) string {
	if str(m, "connection_id") != "" {
		return "directory"
	}
	return "manual"
}

func groupsListCmd() *cobra.Command {
	var org, source, search string
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the groups of an organization",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(groupsPath(org) + withQuery(listQuery(limit, offset, search), map[string]string{"source": source}))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME", "MEMBERS", "SOURCE"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name"), str(m, "member_count"), groupSource(m)}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&source, "source", "", "Only manual or directory (SCIM) groups")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	cmd.MarkFlagRequired("org")
	return cmd
}

func groupsGetCmd() *cobra.Command {
	var org string
	cmd := &cobra.Command{
		Use:   "get GROUP_ID",
		Short: "Get group details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(groupsPath(org) + "/" + args[0])
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.MarkFlagRequired("org")
	return cmd
}

func groupsCreateCmd() *cobra.Command {
	var org, name, description string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a group",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.post(groupsPath(org), map[string]string{"name": name, "description": description})
			if err != nil {
				return err
			}
			p.created("group", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "Group name, unique in the organization (required)")
	cmd.Flags().StringVar(&description, "description", "", "Description")
	cmd.MarkFlagRequired("org")
	cmd.MarkFlagRequired("name")
	return cmd
}

func groupsUpdateCmd() *cobra.Command {
	var org, name, description string
	cmd := &cobra.Command{
		Use:   "update GROUP_ID",
		Short: "Rename or describe a group (manual groups only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]any{}
			if cmd.Flags().Changed("name") {
				body["name"] = name
			}
			if cmd.Flags().Changed("description") {
				body["description"] = description
			}
			if _, err := c.patch(groupsPath(org)+"/"+args[0], body); err != nil {
				return err
			}
			p.ok("Group updated: " + args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "New name")
	cmd.Flags().StringVar(&description, "description", "", "New description")
	cmd.MarkFlagRequired("org")
	return cmd
}

func groupsDeleteCmd() *cobra.Command {
	var org string
	cmd := &cobra.Command{
		Use:   "delete GROUP_ID",
		Short: "Delete a group; its members lose the roles it granted",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			if _, err := c.delete(groupsPath(org) + "/" + args[0]); err != nil {
				return err
			}
			p.ok("Group deleted: " + args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.MarkFlagRequired("org")
	return cmd
}

// --- Members subcommand ---

func groupsMembersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "members",
		Aliases: []string{"member"},
		Short:   "Manage group members (manual groups only)",
	}
	cmd.AddCommand(groupsMembersListCmd())
	cmd.AddCommand(groupsMembersChangeCmd("add", "Add organization members to a group"))
	cmd.AddCommand(groupsMembersChangeCmd("remove", "Remove members from a group"))
	return cmd
}

func groupsMembersListCmd() *cobra.Command {
	var org, group, search string
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the members of a group",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(groupsPath(org) + "/" + group + "/members" + listQuery(limit, offset, search))
			if err != nil {
				return err
			}
			p.table(data, []string{"USER_ID", "NAME", "EMAIL", "STATUS"}, func(m map[string]any) []string {
				return []string{str(m, "user_id"), str(m, "user_name"), str(m, "user_email"), activeStr(m, "active")}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&group, "group", "", "Group ID (required)")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	cmd.MarkFlagRequired("org")
	cmd.MarkFlagRequired("group")
	return cmd
}

// groupsMembersChangeCmd builds `members add` and `members remove`; both post
// to the same endpoint, which is idempotent for repeated users.
func groupsMembersChangeCmd(op, short string) *cobra.Command {
	var org, group string
	var users []string
	cmd := &cobra.Command{
		Use:   op,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			if _, err := c.post(groupsPath(org)+"/"+group+"/members", map[string][]string{op: users}); err != nil {
				return err
			}
			verb := "Added"
			if op == "remove" {
				verb = "Removed"
			}
			p.ok(verb + " " + strings.Join(users, ", ") + " (group " + group + ")")
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&group, "group", "", "Group ID (required)")
	cmd.Flags().StringSliceVar(&users, "user", nil, "User ID; repeat or comma-separate for several (required)")
	cmd.MarkFlagRequired("org")
	cmd.MarkFlagRequired("group")
	cmd.MarkFlagRequired("user")
	return cmd
}

// --- Roles subcommand ---

func groupsRolesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "roles",
		Aliases: []string{"role"},
		Short:   "Manage the roles every member of a group holds",
	}
	cmd.AddCommand(groupsRolesListCmd())
	cmd.AddCommand(groupsRolesAssignCmd())
	cmd.AddCommand(groupsRolesRemoveCmd())
	return cmd
}

func groupsRolesListCmd() *cobra.Command {
	var org, group, role, resource, search string
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List roles assigned to groups",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			q := withQuery(listQuery(limit, offset, search), map[string]string{
				"organization_id": org, "group_id": group, "role_id": role, "resource_id": resource,
			})
			data, err := c.get(envPath() + "/group-role-assignments" + q)
			if err != nil {
				return err
			}
			p.table(data, []string{"GROUP", "GROUP NAME", "ROLE", "ROLE NAME", "RESOURCE", "ORGANIZATION"}, func(m map[string]any) []string {
				return []string{
					str(m, "group_id"), str(m, "group_name"),
					str(m, "role_id"), str(m, "role_name"),
					str(m, "resource_name"), str(m, "organization_name"),
				}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Filter by organization ID")
	cmd.Flags().StringVar(&group, "group", "", "Filter by group ID")
	cmd.Flags().StringVar(&role, "role", "", "Filter by role ID")
	cmd.Flags().StringVar(&resource, "resource", "", "Filter by resource ID")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	return cmd
}

func groupsRolesAssignCmd() *cobra.Command {
	var org, group, role string
	cmd := &cobra.Command{
		Use:   "assign",
		Short: "Assign a role to a group; every member holds it",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.post(envPath()+"/group-role-assignments", map[string]string{
				"organization_id": org, "group_id": group, "role_id": role,
			})
			if err != nil {
				return err
			}
			p.ok("Role " + role + " assigned to group " + group + " in org " + org)
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&group, "group", "", "Group ID (required)")
	cmd.Flags().StringVar(&role, "role", "", "Role ID (required)")
	cmd.MarkFlagRequired("org")
	cmd.MarkFlagRequired("group")
	cmd.MarkFlagRequired("role")
	return cmd
}

func groupsRolesRemoveCmd() *cobra.Command {
	var org, group, role string
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Unassign a role from a group",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			if _, err := c.delete(envPath() + "/group-role-assignments/" + role + "/" + org + "/" + group); err != nil {
				return err
			}
			p.ok("Unassigned role " + role + " from group " + group + " in org " + org)
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&group, "group", "", "Group ID (required)")
	cmd.Flags().StringVar(&role, "role", "", "Role ID (required)")
	cmd.MarkFlagRequired("org")
	cmd.MarkFlagRequired("group")
	cmd.MarkFlagRequired("role")
	return cmd
}
