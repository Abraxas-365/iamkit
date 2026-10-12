package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func samlAppsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "saml-apps",
		Aliases: []string{"saml-app", "saml-sp"},
		Short:   "Manage SAML applications (IAMKit as the identity provider)",
		Long: `Register applications that sign users in with SAML 2.0, IAMKit being
their identity provider.

Give the service provider the metadata URL from "iam saml-apps idp" (or its
SSO URL, entity ID and certificate). Register it with its entity ID and
assertion consumer service URLs; IAMKit accepts AuthnRequests only from that
entity ID and posts responses only to those URLs. Users sign in on the hosted
pages; the response carries the email (or the user ID with
--name-id-format persistent) and the mapped attributes.

Single logout is opt-in per application: give --certificate (the
application's signing certificate, a PEM file path or "-" for stdin) and
--slo-url (where IAMKit answers the application's signed LogoutRequest;
--slo-binding redirect or post) and/or --slo-soap-url (where IAMKit sends a
signed SOAP LogoutRequest when a session the application signed in ends).`,
	}
	cmd.AddCommand(samlAppsIdPCmd())
	cmd.AddCommand(samlAppsListCmd())
	cmd.AddCommand(samlAppsGetCmd())
	cmd.AddCommand(samlAppsCreateCmd())
	cmd.AddCommand(samlAppsUpdateCmd())
	cmd.AddCommand(samlAppsDeleteCmd())
	return cmd
}

// samlAttributes parses name=source pairs.
func samlAttributes(pairs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range pairs {
		name, source, ok := strings.Cut(pair, "=")
		if !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(source) == "" {
			return nil, fmt.Errorf("--attr %q must be NAME=SOURCE", pair)
		}
		out[strings.TrimSpace(name)] = strings.TrimSpace(source)
	}
	return out, nil
}

// samlLogoutFlags are the single logout settings of create and update (on
// update "" clears a URL or the certificate).
type samlLogoutFlags struct {
	url, binding, soapURL, certificate string
}

func (f *samlLogoutFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.url, "slo-url", "", "Where IAMKit answers the application's signed LogoutRequest (HTTPS)")
	cmd.Flags().StringVar(&f.binding, "slo-binding", "", "How IAMKit answers at --slo-url: redirect (default) or post")
	cmd.Flags().StringVar(&f.soapURL, "slo-soap-url", "", "Where IAMKit sends a signed SOAP LogoutRequest when a session ends (HTTPS)")
	cmd.Flags().StringVar(&f.certificate, "certificate", "", "The application's signing certificate: a PEM file path, \"-\" for stdin, or the PEM itself")
}

func (f *samlLogoutFlags) apply(cmd *cobra.Command, body map[string]any) error {
	for _, field := range []struct{ flag, name, value string }{
		{"slo-url", "slo_url", f.url},
		{"slo-binding", "slo_binding", f.binding},
		{"slo-soap-url", "slo_soap_url", f.soapURL},
	} {
		if cmd.Flags().Changed(field.flag) {
			body[field.name] = field.value
		}
	}
	if cmd.Flags().Changed("certificate") {
		pem, err := certificateValue(f.certificate)
		if err != nil {
			return err
		}
		body["certificate"] = pem
	}
	return nil
}

// certificateValue is the PEM a --certificate value stands for: the
// contents of a file ("-": stdin), or the PEM itself.
func certificateValue(v string) (string, error) {
	switch {
	case v == "" || strings.HasPrefix(strings.TrimSpace(v), "-----BEGIN"):
		return v, nil
	case v == "-":
		raw, err := io.ReadAll(os.Stdin)
		return string(raw), err
	}
	raw, err := os.ReadFile(v)
	if err != nil {
		return "", fmt.Errorf("--certificate: %w", err)
	}
	return string(raw), nil
}

func samlAppsIdPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "idp",
		Short: "Show the identity provider settings to give service providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/saml/identity-provider")
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func samlAppsListCmd() *cobra.Command {
	var limit, offset int
	var search, application string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List SAML applications",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			q := listQuery(limit, offset, search)
			if application != "" {
				if q == "" {
					q = "?application_id=" + application
				} else {
					q += "&application_id=" + application
				}
			}
			data, err := c.get(envPath() + "/saml/service-providers" + q)
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "NAME", "ENTITY ID", "APPLICATION", "RESOURCE", "NAMEID"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "name"), str(m, "entity_id"), str(m, "application_name"), str(m, "resource_name"), str(m, "name_id_format")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&search, "search", "", "Search name or entity ID")
	cmd.Flags().StringVar(&application, "application", "", "Only this application's")
	return cmd
}

func samlAppsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get SP_ID",
		Short: "Show a SAML application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/saml/service-providers/" + args[0])
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func samlAppsCreateCmd() *cobra.Command {
	var name, application, resource, entity, format string
	var acs, attrs []string
	var slo samlLogoutFlags
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Register a SAML application",
		Example: `  iam saml-apps create --name Wiki --application APP_ID --resource RES_ID \
    --entity-id https://wiki.example.com/saml --acs https://wiki.example.com/saml/acs \
    --attr mail=email --attr displayName=name --attr roles=permissions

  iam saml-apps create ... --certificate wiki.pem \
    --slo-url https://wiki.example.com/saml/slo --slo-soap-url https://wiki.example.com/saml/soap`,
		RunE: func(cmd *cobra.Command, args []string) error {
			attributes, err := samlAttributes(attrs)
			if err != nil {
				return err
			}
			c := mustClient(cmd)
			body := map[string]any{"name": name, "application_id": application, "resource_id": resource, "entity_id": entity, "acs_urls": acs, "attributes": attributes}
			if format != "" {
				body["name_id_format"] = format
			}
			if err := slo.apply(cmd, body); err != nil {
				return err
			}
			data, err := c.post(envPath()+"/saml/service-providers", body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Display name")
	cmd.Flags().StringVar(&application, "application", "", "Application ID")
	cmd.Flags().StringVar(&resource, "resource", "", "Resource ID (linked to the application)")
	cmd.Flags().StringVar(&entity, "entity-id", "", "The service provider's entity ID")
	cmd.Flags().StringSliceVar(&acs, "acs", nil, "Assertion consumer service URL (repeatable; the first is the default)")
	cmd.Flags().StringVar(&format, "name-id-format", "", "email (default) or persistent (the user ID)")
	cmd.Flags().StringArrayVar(&attrs, "attr", nil, "Attribute NAME=SOURCE, SOURCE one of email, name, user_id, organization_id, permissions (repeatable)")
	slo.register(cmd)
	for _, f := range []string{"name", "application", "resource", "entity-id", "acs"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}

func samlAppsUpdateCmd() *cobra.Command {
	var name, format string
	var acs, attrs []string
	var clearAttrs bool
	var slo samlLogoutFlags
	cmd := &cobra.Command{
		Use:   "update SP_ID",
		Short: "Change a SAML application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			if cmd.Flags().Changed("name") {
				body["name"] = name
			}
			if cmd.Flags().Changed("acs") {
				body["acs_urls"] = acs
			}
			if cmd.Flags().Changed("name-id-format") {
				body["name_id_format"] = format
			}
			if cmd.Flags().Changed("attr") || clearAttrs {
				attributes, err := samlAttributes(attrs)
				if err != nil {
					return err
				}
				body["attributes"] = attributes
			}
			if err := slo.apply(cmd, body); err != nil {
				return err
			}
			c := mustClient(cmd)
			data, err := c.patch(envPath()+"/saml/service-providers/"+args[0], body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Display name")
	cmd.Flags().StringSliceVar(&acs, "acs", nil, "Replace the assertion consumer service URLs")
	cmd.Flags().StringVar(&format, "name-id-format", "", "email or persistent")
	cmd.Flags().StringArrayVar(&attrs, "attr", nil, "Replace the attributes with these NAME=SOURCE pairs")
	cmd.Flags().BoolVar(&clearAttrs, "clear-attrs", false, "Send no attributes")
	slo.register(cmd)
	return cmd
}

func samlAppsDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete SP_ID",
		Short: "Delete a SAML application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.delete(envPath() + "/saml/service-providers/" + args[0]); err != nil {
				return err
			}
			newPrinter().ok("SAML application deleted: " + args[0])
			return nil
		},
	}
}
