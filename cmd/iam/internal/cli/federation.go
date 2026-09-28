package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func federationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "federation",
		Aliases: []string{"fed"},
		Short:   "Manage federation connections (external identity providers)",
	}
	cmd.AddCommand(fedListCmd())
	cmd.AddCommand(fedGetCmd())
	cmd.AddCommand(fedCreateCmd())
	cmd.AddCommand(fedDisableCmd())
	return cmd
}

func fedListCmd() *cobra.Command {
	var limit, offset int
	var search string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List federation connections",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/federation-connections" + listQuery(limit, offset, search))
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "NAME", "ISSUER", "CLIENT ID", "STATUS", "LINKED"}, func(m map[string]any) []string {
				return []string{
					str(m, "id"), str(m, "name"), str(m, "issuer"),
					str(m, "client_id"), activeStr(m, "active"), str(m, "linked"),
				}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search query")
	return cmd
}

func fedGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get CONNECTION_ID",
		Short: "Get connection details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.get(envPath() + "/federation-connections/" + args[0])
			if err != nil {
				return err
			}
			p.detail(data)
			return nil
		},
	}
}

func fedCreateCmd() *cobra.Command {
	var name, provider, issuer, clientID, secretEnv, secretFile, tenant, team, key, org, signupOrg, signupGroup string
	var tenants, domains []string
	var linkEmail bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a federation connection",
		Example: `  iam federation create --provider google --name Google --client-id ID --client-secret-file secret.txt --link-email
  iam federation create --provider microsoft --tenant common --name Microsoft --client-id ID --client-secret-file secret.txt
  iam federation create --provider google --domains acme.com --name "Acme Google" --client-id ID --client-secret-file secret.txt --organization ORG_ID
  iam federation create --provider apple --name Apple --client-id com.example.web --team-id TEAM --key-id KEY --client-secret-file AuthKey.p8
  iam federation create --name Okta --issuer https://acme.okta.com --client-id ID --secret-env IAMKIT_PROVIDER_OKTA --organization ORG_ID`,
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{"name": name, "provider": provider, "client_id": clientID}
			if issuer != "" {
				body["issuer"] = issuer
			}
			switch {
			case (secretEnv == "") == (secretFile == ""):
				return fmt.Errorf("provide exactly one of --secret-env or --client-secret-file")
			case secretEnv != "":
				body["secret_env"] = secretEnv
			default:
				secret, err := os.ReadFile(secretFile)
				if err != nil {
					return err
				}
				body["client_secret"] = strings.TrimSpace(string(secret))
			}
			options := map[string]any{}
			if tenant != "" {
				options["tenant"] = tenant
			}
			if len(tenants) > 0 {
				options["tenants"] = tenants
			}
			if len(domains) > 0 {
				options["domains"] = domains
			}
			if team != "" {
				options["team_id"] = team
			}
			if key != "" {
				options["key_id"] = key
			}
			if len(options) > 0 {
				body["options"] = options
			}
			if org != "" {
				body["organization_id"] = org
			}
			if signupOrg != "" {
				body["signup"], body["signup_organization_id"] = true, signupOrg
			}
			if signupGroup != "" {
				body["signup_group_id"] = signupGroup
			}
			if linkEmail {
				body["link_email"] = true
			}
			c := mustClient(cmd)
			p := newPrinter()
			data, err := c.post(envPath()+"/federation-connections", body)
			if err != nil {
				return err
			}
			p.created("federation connection", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Connection name, shown as \"Continue with NAME\" (required)")
	cmd.Flags().StringVar(&provider, "provider", "oidc", "oidc, google, microsoft, github or apple")
	cmd.Flags().StringVar(&issuer, "issuer", "", "OIDC issuer URL (provider oidc only)")
	cmd.Flags().StringVar(&clientID, "client-id", "", "OAuth client ID; Apple: the Services ID (required)")
	cmd.Flags().StringVar(&secretEnv, "secret-env", "", "Env var name holding the client secret")
	cmd.Flags().StringVar(&secretFile, "client-secret-file", "", "File with the client secret, stored encrypted; Apple: the .p8 key")
	cmd.Flags().StringVar(&tenant, "tenant", "", "Microsoft: common, organizations, consumers or a tenant ID")
	cmd.Flags().StringSliceVar(&tenants, "tenants", nil, "Microsoft: tenant IDs allowed under common/organizations")
	cmd.Flags().StringSliceVar(&domains, "domains", nil, "Google: only accept Google Workspace accounts of these domains")
	cmd.Flags().StringVar(&team, "team-id", "", "Apple: team ID")
	cmd.Flags().StringVar(&key, "key-id", "", "Apple: key ID")
	cmd.Flags().StringVar(&org, "organization", "", "Organization ID for an organization SSO connection")
	cmd.Flags().StringVar(&signupOrg, "signup-organization", "", "Sign up new users into this organization (environment connections)")
	cmd.Flags().StringVar(&signupGroup, "signup-group", "", "Default group for signed-up users")
	cmd.Flags().BoolVar(&linkEmail, "link-email", false, "Link existing users by verified email (environment connections)")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("client-id")
	return cmd
}

func fedDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable CONNECTION_ID",
		Short: "Disable a federation connection",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			_, err := c.delete(envPath() + "/federation-connections/" + args[0])
			if err != nil {
				return err
			}
			p.ok("Federation connection disabled: " + args[0])
			return nil
		},
	}
}
