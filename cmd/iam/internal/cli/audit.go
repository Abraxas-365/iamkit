package cli

import "github.com/spf13/cobra"

func auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "View audit events",
	}
	cmd.AddCommand(auditListCmd())
	return cmd
}

func auditListCmd() *cobra.Command {
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List audit events",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/audit-events" + listQuery(limit, offset, ""))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "ACTOR", "ACTION", "TARGET", "TIMESTAMP"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "actor"), str(m, "action"), str(m, "target"), str(m, "created_at")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	return cmd
}
