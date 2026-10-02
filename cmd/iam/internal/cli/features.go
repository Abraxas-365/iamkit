package cli

import (
	"strconv"

	"github.com/spf13/cobra"
)

func featuresCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "features",
		Aliases: []string{"feature"},
		Short:   "Turn IAMKit's beta features on and off",
		Long: `Read and override IAMKit's own feature flags (not a flag service for your
applications). Each flag has a default; the deployment sets values for every
environment with IAMKIT_FEATURES ("saml_idp=false,beta_languages=true").
Environment-scoped flags can be overridden per environment; deployment-scoped
ones only by IAMKIT_FEATURES. Effective value: environment › deployment ›
default.`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the features and their state in the environment",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/features")
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"NAME", "ENABLED", "SCOPE", "DEFAULT", "DEPLOYMENT", "ENVIRONMENT"}, func(m map[string]any) []string {
				return []string{str(m, "name"), str(m, "enabled"), str(m, "scope"), str(m, "default"), str(m, "deployment"), str(m, "environment")}
			})
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "get NAME",
		Short: "Show a feature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/features/" + args[0])
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:     "set NAME true|false",
		Short:   "Override an environment-scoped feature for the environment",
		Example: `  iam features set beta_languages false`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			enabled, err := strconv.ParseBool(args[1])
			if err != nil {
				return err
			}
			data, err := mustClient(cmd).put(envPath()+"/features/"+args[0], map[string]any{"enabled": enabled})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "reset NAME",
		Short: "Remove the environment's override (the deployment value or default applies)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).delete(envPath() + "/features/" + args[0])
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	})
	return cmd
}
