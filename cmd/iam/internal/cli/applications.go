package cli

import (
	"strings"

	"github.com/spf13/cobra"
)

func applicationsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "applications",
		Aliases: []string{"app", "apps"},
		Short:   "Manage applications",
	}
	cmd.AddCommand(appsListCmd())
	cmd.AddCommand(appsGetCmd())
	cmd.AddCommand(appsCreateCmd())
	cmd.AddCommand(appsUpdateCmd())
	cmd.AddCommand(appsResourcesCmd())
	return cmd
}

func appsListCmd() *cobra.Command {
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List applications",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/applications" + listQuery(limit, offset, search))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME", "REDIRECT URIS", "STATUS"}, func(m map[string]any) []string {
				uris := ""
				if arr, ok := m["redirect_uris"].([]any); ok {
					parts := make([]string, len(arr))
					for i, u := range arr {
						parts[i] = str(map[string]any{"v": u}, "v")
					}
					uris = strings.Join(parts, ", ")
				}
				return []string{str(m, "id"), str(m, "name"), uris, activeStr(m, "active")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	return cmd
}

func appsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get APP_ID",
		Short: "Get application details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/applications/" + args[0])
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
}

func appsCreateCmd() *cobra.Command {
	var name, redirectURIs string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an application",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]any{"name": name}
			if redirectURIs != "" {
				body["redirect_uris"] = strings.Split(redirectURIs, ",")
			} else {
				body["redirect_uris"] = []string{}
			}
			data, err := c.post(envPath()+"/applications", body)
			if err != nil {
				return err
			}
			p.created("application", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Application name (required)")
	cmd.Flags().StringVar(&redirectURIs, "redirect-uris", "", "Comma-separated redirect URIs")
	cmd.MarkFlagRequired("name")
	return cmd
}

func appsUpdateCmd() *cobra.Command {
	var name, redirectURIs, active string
	cmd := &cobra.Command{
		Use:   "update APP_ID",
		Short: "Update an application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			body := map[string]any{}
			if cmd.Flags().Changed("name") {
				body["name"] = name
			}
			if cmd.Flags().Changed("redirect-uris") {
				body["redirect_uris"] = strings.Split(redirectURIs, ",")
			}
			if cmd.Flags().Changed("active") {
				body["active"] = strings.EqualFold(active, "true")
			}
			_, err := c.patch(envPath()+"/applications/"+args[0], body)
			if err != nil {
				return err
			}
			p.ok("Application updated: " + args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "New name")
	cmd.Flags().StringVar(&redirectURIs, "redirect-uris", "", "Comma-separated redirect URIs")
	cmd.Flags().StringVar(&active, "active", "", "true or false")
	return cmd
}

// --- Application resources subcommand ---

func appsResourcesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "resources",
		Aliases: []string{"res"},
		Short:   "Manage application-resource links",
	}
	cmd.AddCommand(appsResourcesListCmd())
	cmd.AddCommand(appsResourcesLinkCmd())
	cmd.AddCommand(appsResourcesUnlinkCmd())
	return cmd
}

func appsResourcesListCmd() *cobra.Command {
	var app string
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List resources linked to an application",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/applications/" + app + "/resources" + listQuery(limit, offset, ""))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME", "PREFIX", "AUDIENCE", "PERMISSIONS"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name"), str(m, "prefix"), str(m, "audience"), collapsePerms(m["permissions"])}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Application ID (required)")
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.MarkFlagRequired("app")
	return cmd
}

func appsResourcesLinkCmd() *cobra.Command {
	var app, resource string
	cmd := &cobra.Command{
		Use:   "link",
		Short: "Link an application to a resource",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.post(envPath()+"/application-resources", map[string]string{
				"application_id": app,
				"resource_id":    resource,
			})
			if err != nil {
				return err
			}
			p.ok("Linked application " + app + " → resource " + resource)
			return nil
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Application ID (required)")
	cmd.Flags().StringVar(&resource, "resource", "", "Resource ID (required)")
	cmd.MarkFlagRequired("app")
	cmd.MarkFlagRequired("resource")
	return cmd
}

func appsResourcesUnlinkCmd() *cobra.Command {
	var app, resource string
	cmd := &cobra.Command{
		Use:   "unlink",
		Short: "Unlink an application from a resource",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/application-resources/" + app + "/" + resource)
			if err != nil {
				return err
			}
			p.ok("Unlinked application " + app + " from resource " + resource)
			return nil
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Application ID (required)")
	cmd.Flags().StringVar(&resource, "resource", "", "Resource ID (required)")
	cmd.MarkFlagRequired("app")
	cmd.MarkFlagRequired("resource")
	return cmd
}
