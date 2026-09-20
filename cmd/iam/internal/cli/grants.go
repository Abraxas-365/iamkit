package cli

import "github.com/spf13/cobra"

func grantsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "grants",
		Aliases: []string{"grant"},
		Short:   "Manage direct permission grants",
	}
	cmd.AddCommand(grantsListCmd())
	cmd.AddCommand(grantsGetCmd())
	cmd.AddCommand(grantsSetCmd())
	cmd.AddCommand(grantsDeleteCmd())
	return cmd
}

func grantsListCmd() *cobra.Command {
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List grants",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/grants" + listQuery(limit, offset, search))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "ORGANIZATION", "USER", "RESOURCE", "PERMISSIONS"}, func(m map[string]any) []string {
				org := str(m, "organization_name")
				if org == "" {
					org = str(m, "organization_id")
				}
				usr := str(m, "user_name")
				if usr == "" {
					usr = str(m, "user_id")
				}
				res := str(m, "resource_name")
				if res == "" {
					res = str(m, "resource_id")
				}
				return []string{str(m, "id"), org, usr, res, collapsePerms(m["permissions"])}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	return cmd
}

func grantsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get GRANT_ID",
		Short: "Get grant details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/grants/" + args[0])
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
}

func grantsSetCmd() *cobra.Command {
	var org, user, resource, permissions string
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set (create/replace) a direct grant",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.put(envPath()+"/grants", map[string]any{
				"organization_id": org, "user_id": user,
				"resource_id": resource, "permissions": splitCSV(permissions),
			})
			if err != nil {
				return err
			}
			p.created("grant", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "", "Organization ID (required)")
	cmd.Flags().StringVar(&user, "user", "", "User ID (required)")
	cmd.Flags().StringVar(&resource, "resource", "", "Resource ID (required)")
	cmd.Flags().StringVar(&permissions, "permissions", "", "Comma-separated permissions (required)")
	cmd.MarkFlagRequired("org")
	cmd.MarkFlagRequired("user")
	cmd.MarkFlagRequired("resource")
	cmd.MarkFlagRequired("permissions")
	return cmd
}

func grantsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete GRANT_ID",
		Short: "Delete a grant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/grants/" + args[0])
			if err != nil {
				return err
			}
			p.ok("Grant deleted: " + args[0])
			return nil
		},
	}
}
