package cli

import "github.com/spf13/cobra"

func deliveryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delivery",
		Short: "Manage email delivery webhook configuration",
	}
	cmd.AddCommand(deliveryGetCmd())
	cmd.AddCommand(deliverySetCmd())
	cmd.AddCommand(deliveryDeleteCmd())
	return cmd
}

func deliveryGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Get current delivery configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/delivery")
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
}

func deliverySetCmd() *cobra.Command {
	var webhookURL, webhookToken string
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set delivery webhook configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.put(envPath()+"/delivery", map[string]string{
				"webhook_url": webhookURL, "webhook_token": webhookToken,
			})
			if err != nil {
				return err
			}
			p.ok("Delivery configuration updated")
			return nil
		},
	}
	cmd.Flags().StringVar(&webhookURL, "webhook-url", "", "Webhook URL (required)")
	cmd.Flags().StringVar(&webhookToken, "webhook-token", "", "Webhook auth token (required)")
	cmd.MarkFlagRequired("webhook-url")
	cmd.MarkFlagRequired("webhook-token")
	return cmd
}

func deliveryDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete",
		Short: "Delete delivery configuration (restore global fallback)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/delivery")
			if err != nil {
				return err
			}
			p.ok("Delivery configuration deleted")
			return nil
		},
	}
}
