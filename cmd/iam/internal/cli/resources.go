package cli

import (
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

func resourcesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "resources",
		Aliases: []string{"resource", "res"},
		Short:   "Manage resources and permission catalogs",
	}
	cmd.AddCommand(resourcesListCmd())
	cmd.AddCommand(resourcesGetCmd())
	cmd.AddCommand(resourcesCreateCmd())
	cmd.AddCommand(resourcesUpdateCmd())
	cmd.AddCommand(resourcesAccessCmd())
	cmd.AddCommand(resourceGrantsCmd())
	return cmd
}

func resourcesListCmd() *cobra.Command {
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/resources" + listQuery(limit, offset, search))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME", "PREFIX", "AUDIENCE", "OWNER", "PERMISSIONS"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name"), str(m, "prefix"), str(m, "audience"), str(m, "owner_organization_id"), collapsePerms(m["permissions"])}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	return cmd
}

func resourcesGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get RESOURCE_ID",
		Short: "Get resource details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/resources/" + args[0])
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
}

func resourcesCreateCmd() *cobra.Command {
	var name, prefix, audience, permissions string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a resource",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			perms := splitCSV(permissions)
			data, err := c.post(envPath()+"/resources", map[string]any{
				"name": name, "prefix": prefix, "audience": audience, "permissions": perms,
			})
			if err != nil {
				return err
			}
			p.created("resource", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Resource name (required)")
	cmd.Flags().StringVar(&prefix, "prefix", "", "Permission prefix (required)")
	cmd.Flags().StringVar(&audience, "audience", "", "API audience URL (required)")
	cmd.Flags().StringVar(&permissions, "permissions", "", "Comma-separated permissions (required)")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("prefix")
	cmd.MarkFlagRequired("audience")
	cmd.MarkFlagRequired("permissions")
	return cmd
}

func resourcesUpdateCmd() *cobra.Command {
	var name, permissions string
	cmd := &cobra.Command{
		Use:   "update RESOURCE_ID",
		Short: "Update a resource's name and permission catalog",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]any{}
			if cmd.Flags().Changed("name") {
				body["name"] = name
			}
			if cmd.Flags().Changed("permissions") {
				body["permissions"] = splitCSV(permissions)
			}
			_, err := c.put(envPath()+"/resources/"+args[0], body)
			if err != nil {
				return err
			}
			p.ok("Resource updated: " + args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "New name")
	cmd.Flags().StringVar(&permissions, "permissions", "", "Comma-separated permissions")
	return cmd
}

func resourcesAccessCmd() *cobra.Command {
	var owner string
	var requireGrant bool
	cmd := &cobra.Command{
		Use:   "access RESOURCE_ID",
		Short: "Set the owner organization and whether the resource requires a grant",
		Long: `Set which organization owns the resource (--owner, empty = the environment)
and whether only the owner and granted organizations reach it (--require-grant).
Organizations losing access have their sessions for the resource ended.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]any{"owner_organization_id": nil, "require_grant": requireGrant}
			if owner != "" {
				body["owner_organization_id"] = owner
			}
			if _, err := c.put(envPath()+"/resources/"+args[0]+"/access", body); err != nil {
				return err
			}
			p.ok("Resource access updated: " + args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&owner, "owner", "", "Owner organization ID (empty = owned by the environment)")
	cmd.Flags().BoolVar(&requireGrant, "require-grant", false, "Only the owner and granted organizations reach the resource")
	return cmd
}

func resourceGrantsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "grants",
		Aliases: []string{"grant"},
		Short:   "Grant resources to organizations",
	}
	cmd.AddCommand(resourceGrantsListCmd())
	cmd.AddCommand(resourceGrantsSetCmd())
	cmd.AddCommand(resourceGrantsDeleteCmd())
	return cmd
}

func resourceGrantsListCmd() *cobra.Command {
	var limit, offset int
	var search, resource, org string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List resource grants",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			q := listQuery(limit, offset, search)
			for key, value := range map[string]string{"resource_id": resource, "organization_id": org} {
				if value == "" {
					continue
				}
				if q == "" {
					q = "?"
				} else {
					q += "&"
				}
				q += key + "=" + url.QueryEscape(value)
			}
			data, err := c.get(envPath() + "/resource-grants" + q)
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "RESOURCE", "ORGANIZATION", "ROLES"}, func(m map[string]any) []string {
				roles := "all"
				if list, ok := m["role_ids"].([]any); ok {
					roles = collapsePerms(list)
				}
				return []string{str(m, "id"), str(m, "resource_name"), str(m, "organization_name"), roles}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	cmd.Flags().StringVar(&resource, "resource", "", "Only grants of this resource")
	cmd.Flags().StringVar(&org, "org", "", "Only grants to this organization")
	return cmd
}

func resourceGrantsSetCmd() *cobra.Command {
	var resource, org, roles string
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Grant a resource to an organization (or replace the granted roles)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]any{"resource_id": resource, "organization_id": org, "role_ids": nil}
			if cmd.Flags().Changed("roles") {
				body["role_ids"] = splitCSV(roles)
			}
			data, err := c.put(envPath()+"/resource-grants", body)
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&resource, "resource", "", "Resource ID (required)")
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&roles, "roles", "", "Comma-separated role IDs to grant (omit = every role)")
	cmd.MarkFlagRequired("resource")
	cmd.MarkFlagRequired("org")
	return cmd
}

func resourceGrantsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete GRANT_ID",
		Short: "Revoke a resource grant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			if _, err := c.delete(envPath() + "/resource-grants/" + args[0]); err != nil {
				return err
			}
			p.ok("Resource grant revoked: " + args[0])
			return nil
		},
	}
}

// splitCSV splits a comma-separated string into a slice, trimming spaces.
func splitCSV(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
