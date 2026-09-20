package cli

import "github.com/spf13/cobra"

func environmentsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "environments",
		Aliases: []string{"env", "envs"},
		Short:   "Manage environments within a project",
	}

	cmd.AddCommand(environmentsListCmd())
	cmd.AddCommand(environmentsCreateCmd())
	return cmd
}

func environmentsListCmd() *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List environments in a project",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get("/projects/" + project + "/environments")
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name")}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "Project ID (required)")
	cmd.MarkFlagRequired("project")
	return cmd
}

func environmentsCreateCmd() *cobra.Command {
	var project, name string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an environment",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.post("/projects/"+project+"/environments", map[string]string{"name": name})
			if err != nil {
				return err
			}
			p.created("environment", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "Project ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "Environment name (required)")
	cmd.MarkFlagRequired("project")
	cmd.MarkFlagRequired("name")
	return cmd
}
