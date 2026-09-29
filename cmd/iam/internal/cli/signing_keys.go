package cli

import (
	"github.com/spf13/cobra"
)

func signingKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "signing-keys",
		Aliases: []string{"signing-key", "sk"},
		Short:   "Rotate the environment's token signing keys",
		Long: `Rotate the keys an environment's tokens are signed with.

An environment without an active key signs with the deployment key
(JWT_PRIVATE_KEY_PATH). To rotate: create a key (published in the JWKS
at once), wait for relying parties to refresh their JWKS cache, activate
it, then retire the previous key once its tokens have expired.
Creating keys needs IAMKIT_ENCRYPTION_KEY on the server.`,
	}
	cmd.AddCommand(signingKeysListCmd())
	cmd.AddCommand(signingKeysGetCmd())
	cmd.AddCommand(signingKeysCreateCmd())
	cmd.AddCommand(signingKeysActivateCmd())
	cmd.AddCommand(signingKeysRetireCmd())
	return cmd
}

func signingKeysListCmd() *cobra.Command {
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List signing keys (active first)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/signing-keys" + listQuery(limit, offset, ""))
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"KID", "STATE", "CREATED", "ACTIVATED", "RETIRE AFTER"}, func(m map[string]any) []string {
				return []string{str(m, "kid"), str(m, "state"), str(m, "created_at"), str(m, "activated_at"), str(m, "retire_after")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	return cmd
}

func signingKeysGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get KID",
		Short: "Show a signing key and its public JWK",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/signing-keys/" + args[0])
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func signingKeysCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create",
		Short: "Generate a next key (published, not signing yet)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.post(envPath()+"/signing-keys", nil)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func signingKeysActivateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "activate KID",
		Short: "Sign the environment's tokens with KID (the previous key starts retiring)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.post(envPath()+"/signing-keys/"+args[0]+"/activate", nil); err != nil {
				return err
			}
			newPrinter().ok("Signing key active: " + args[0])
			return nil
		},
	}
}

func signingKeysRetireCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "retire KID",
		Short: "Unpublish a next or retiring key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.post(envPath()+"/signing-keys/"+args[0]+"/retire", map[string]any{"force": force}); err != nil {
				return err
			}
			newPrinter().ok("Signing key retired: " + args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Retire before tokens it signed expire (they stop validating at once)")
	return cmd
}
