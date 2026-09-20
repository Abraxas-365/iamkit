package cli

import "github.com/spf13/cobra"

func projectsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "projects",
		Aliases: []string{"project"},
		Short:   "Manage projects",
	}

	cmd.AddCommand(projectsListCmd())
	cmd.AddCommand(projectsCreateCmd())
	return cmd
}

func projectsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all projects in the workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get("/projects")
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name")}
			})
			return nil
		},
	}
}

func projectsCreateCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a project",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.post("/projects", map[string]string{"name": name})
			if err != nil {
				return err
			}
			p.created("project", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Project name (required)")
	cmd.MarkFlagRequired("name")
	return cmd
}
