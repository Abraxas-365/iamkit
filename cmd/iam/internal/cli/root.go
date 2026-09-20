// Package cli implements the iam command-line interface.
// It is a pure HTTP client — it never imports server or domain packages.
package cli

import (
	"github.com/spf13/cobra"
)

// Global flags populated by root persistent flags.
var (
	flagURL         string
	flagKey         string
	flagEnvironment string
	flagOutput      string
	flagProfile     string
)

// Root returns the top-level cobra command.
func Root() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "iam",
		Short: "IAMKit CLI — manage identity and access from the command line",
		Long: `iam is a command-line client for the IAMKit management API.

Configure with:
  iam configure                       # interactive setup → ~/.iam/

Or with environment variables:
  export IAMKIT_URL=http://localhost:8080
  export IAMKIT_KEY=ik_mgmt_...
  export IAMKIT_ENVIRONMENT=<uuid>

Resolution order (highest wins):
  1. --url / --key / --environment flags
  2. IAMKIT_URL / IAMKIT_KEY / IAMKIT_ENVIRONMENT env vars
  3. ~/.iam/config + ~/.iam/credentials (selected by --profile, default: "default")

Most entity commands require --environment (or IAMKIT_ENVIRONMENT).
Workspace-level commands (me, projects, environments, operators, keys) do not.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	pf := cmd.PersistentFlags()
	pf.StringVar(&flagURL, "url", "", "IAMKit base URL (env: IAMKIT_URL)")
	pf.StringVar(&flagKey, "key", "", "Management API key (env: IAMKIT_KEY)")
	pf.StringVarP(&flagEnvironment, "environment", "e", "", "Environment ID (env: IAMKIT_ENVIRONMENT)")
	pf.StringVarP(&flagOutput, "output", "o", "", "Output format: json, table (default: auto-detect)")
	pf.StringVar(&flagProfile, "profile", "", "Named profile from ~/.iam/ (default: \"default\")")

	// Configuration
	cmd.AddCommand(configureCmd())

	// Workspace commands (no --environment required)
	cmd.AddCommand(meCmd())
	cmd.AddCommand(projectsCmd())
	cmd.AddCommand(environmentsCmd())
	cmd.AddCommand(operatorsCmd())
	cmd.AddCommand(keysCmd())

	// Entity commands (require --environment)
	cmd.AddCommand(usersCmd())
	cmd.AddCommand(organizationsCmd())
	cmd.AddCommand(applicationsCmd())
	cmd.AddCommand(resourcesCmd())
	cmd.AddCommand(rolesCmd())
	cmd.AddCommand(grantsCmd())
	cmd.AddCommand(serviceAccountsCmd())
	cmd.AddCommand(federationCmd())
	cmd.AddCommand(sessionsCmd())
	cmd.AddCommand(auditCmd())
	cmd.AddCommand(deliveryCmd())
	cmd.AddCommand(seedCmd())

	return cmd
}
