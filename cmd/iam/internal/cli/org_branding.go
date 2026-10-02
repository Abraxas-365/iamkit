package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

// orgsBrandingCmd manages an organization's overrides of the hosted pages.
func orgsBrandingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "branding",
		Short: "Manage an organization's sign-in branding",
		Long: `Manage an organization's overrides of the hosted pages. They lay over the
OAuth client's style and the environment default, field by field (unset
fields inherit), once a sign-in knows the organization: the application's
hint (the organization_id authorization parameter or the
urn:iamkit:org:id:<id> scope, which also limits the sign-in to it), the
organization the user chose, or a verified domain of the typed email.
Invitation pages and emails into the organization use it too; codes and
other emails keep the environment brand.`,
	}
	cmd.AddCommand(orgsBrandingGetCmd())
	cmd.AddCommand(orgsBrandingSetCmd())
	cmd.AddCommand(orgsBrandingDeleteCmd())
	return cmd
}

func orgBrandingPath(org string) string { return envPath() + "/login-settings/organizations/" + org }

func orgsBrandingGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get ORG_ID",
		Short: "Get the organization's overrides (null fields inherit)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(orgBrandingPath(args[0]))
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func orgsBrandingSetCmd() *cobra.Command {
	var name, logo, accent, theme, locale string
	var inherit []string
	cmd := &cobra.Command{
		Use:   "set ORG_ID",
		Short: "Change the organization's overrides",
		Long: `Change the organization's overrides. Flags left out keep their current
value; --inherit FIELD (display-name, logo-url, accent-color, theme, locale)
clears one so it inherits again. --theme takes a JSON theme (as in the
environment default) that replaces the inherited one whole. --locale sets the
language of the organization's sign-in and invitation pages and invitation
emails (one of the environment's enabled languages).`,
		Example: `  iam organizations branding set ORG_ID --display-name "Acme Corp" --accent-color "#aa0000"
  iam organizations branding set ORG_ID --logo-url https://cdn.acme.example/logo.png
  iam organizations branding set ORG_ID --locale es
  iam organizations branding set ORG_ID --inherit accent-color`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			path := orgBrandingPath(args[0])
			current, err := c.get(path)
			if err != nil {
				return err
			}
			body := map[string]any{}
			if err := json.Unmarshal(current, &body); err != nil {
				return fmt.Errorf("read current branding: %w", err)
			}
			for _, k := range []string{"environment_id", "organization_id", "updated_at"} {
				delete(body, k)
			}
			f := cmd.Flags()
			for flag, value := range map[string]string{"display-name": name, "logo-url": logo, "accent-color": accent, "locale": locale} {
				if f.Changed(flag) {
					body[jsonName(flag)] = value
				}
			}
			if f.Changed("theme") {
				var parsed map[string]any
				if err := json.Unmarshal([]byte(theme), &parsed); err != nil {
					return fmt.Errorf("--theme must be a JSON object: %w", err)
				}
				body["theme"] = parsed
			}
			for _, field := range inherit {
				switch field {
				case "display-name", "logo-url", "accent-color", "theme", "locale":
					if f.Changed(field) {
						return fmt.Errorf("--%s and --inherit %s conflict", field, field)
					}
					body[jsonName(field)] = nil
				default:
					return fmt.Errorf("--inherit: unknown field %q (display-name, logo-url, accent-color, theme, locale)", field)
				}
			}
			data, err := c.put(path, body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "display-name", "", "Name under the logo and in the browser tab")
	f.StringVar(&logo, "logo-url", "", "HTTPS logo URL")
	f.StringVar(&accent, "accent-color", "", "Primary color, #rrggbb")
	f.StringVar(&theme, "theme", "", "Theme JSON (replaces the inherited theme)")
	f.StringVar(&locale, "locale", "", "Language code (e.g. es) of its pages and invitation emails")
	f.StringSliceVar(&inherit, "inherit", nil, "Fields to inherit again (repeatable)")
	return cmd
}

func orgsBrandingDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete ORG_ID",
		Short: "Remove the organization's overrides (everything inherits)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(orgBrandingPath(args[0])); err != nil {
				return err
			}
			newPrinter().ok("Organization branding removed")
			return nil
		},
	}
}
