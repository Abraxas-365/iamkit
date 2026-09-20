package cli

import "github.com/spf13/cobra"

func meCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "me",
		Short: "Show current operator identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get("/me")
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
}
