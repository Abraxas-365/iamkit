package cli

import (
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
			p.table(data, []string{"ID", "NAME", "PREFIX", "AUDIENCE", "PERMISSIONS"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name"), str(m, "prefix"), str(m, "audience"), collapsePerms(m["permissions"])}
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
