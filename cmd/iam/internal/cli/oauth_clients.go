package cli

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func oauthClientsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "oauth-clients",
		Aliases: []string{"oauth-client", "oc"},
		Short:   "Manage OAuth/OIDC clients",
	}
	cmd.AddCommand(oauthClientsListCmd())
	cmd.AddCommand(oauthClientsGetCmd())
	cmd.AddCommand(oauthClientsCreateCmd())
	cmd.AddCommand(oauthClientsUpdateCmd())
	cmd.AddCommand(oauthClientsDisableCmd())
	cmd.AddCommand(logoutDeliveriesCmd())
	return cmd
}

// uriList renders a JSON string array as a comma-separated list.
func uriList(v any) string {
	arr, _ := v.([]any)
	parts := make([]string, len(arr))
	for i, u := range arr {
		parts[i] = str(map[string]any{"v": u}, "v")
	}
	return strings.Join(parts, ", ")
}

// splitList splits a comma-separated flag; empty means an empty list.
func splitList(v string) []string {
	out := []string{}
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func oauthClientsListCmd() *cobra.Command {
	var limit, offset int
	var app string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List OAuth clients",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			p := newPrinter()
			query := listQuery(limit, offset, "")
			if app != "" {
				if query == "" {
					query = "?application_id=" + app
				} else {
					query += "&application_id=" + app
				}
			}
			data, err := c.get(envPath() + "/oauth-clients" + query)
			if err != nil {
				return err
			}
			p.table(data, []string{"ID", "APPLICATION", "RESOURCE", "REDIRECT URIS", "PUBLIC", "TOKENS", "STATUS"}, func(m map[string]any) []string {
				public := "no"
				if b, _ := m["public"].(bool); b {
					public = "yes"
				}
				return []string{str(m, "id"), str(m, "application_name"), str(m, "resource_name"), uriList(m["redirect_uris"]), public, str(m, "access_token_format"), activeStr(m, "active")}
			})
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	cmd.Flags().StringVar(&app, "app", "", "Only clients of this application ID")
	return cmd
}

func oauthClientsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get CLIENT_ID",
		Short: "Get OAuth client details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/oauth-clients/" + args[0])
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func oauthClientsCreateCmd() *cobra.Command {
	var app, resource, redirects, postLogout, origins, format, backchannel, grants string
	var public, hosted, sessionRequired bool
	var auth clientAuthFlags
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Register an OAuth client (the secret is shown once)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			body := map[string]any{"application_id": app, "resource_id": resource, "redirect_uris": splitList(redirects), "post_logout_redirect_uris": splitList(postLogout), "allowed_origins": splitList(origins), "public": public, "hosted_login": hosted}
			if format != "" {
				body["access_token_format"] = format
			}
			if grants != "" {
				body["grant_types"] = grantTypes(grants)
			}
			if backchannel != "" {
				body["backchannel_logout_uri"] = backchannel
				body["backchannel_logout_session_required"] = sessionRequired
			}
			if err := auth.apply(cmd, body); err != nil {
				return err
			}
			data, err := c.post(envPath()+"/oauth-clients", body)
			if err != nil {
				return err
			}
			newPrinter().created("OAuth client", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&app, "app", "", "Application ID (required)")
	cmd.Flags().StringVar(&resource, "resource", "", "Resource ID (required)")
	cmd.Flags().StringVar(&redirects, "redirect-uris", "", "Comma-separated redirect URIs (required for the authorization code grant)")
	cmd.Flags().StringVar(&postLogout, "post-logout-redirect-uris", "", "Comma-separated URIs /oauth/end_session may return to")
	cmd.Flags().StringVar(&origins, "allowed-origins", "", "Comma-separated browser origins of a custom sign-in UI or SPA (CORS)")
	cmd.Flags().BoolVar(&public, "public", false, "Public client (PKCE, no secret)")
	cmd.Flags().BoolVar(&hosted, "hosted-login", false, "Use IAMKit's hosted sign-in pages")
	cmd.Flags().StringVar(&format, "access-token-format", "", "Access token format: jwt (default) or opaque (introspection/userinfo only)")
	cmd.Flags().StringVar(&backchannel, "backchannel-logout-uri", "", "HTTPS URL that receives a logout token when a session of this client ends")
	cmd.Flags().BoolVar(&sessionRequired, "backchannel-logout-session-required", false, "Record that the client needs sid in logout tokens")
	cmd.Flags().StringVar(&grants, "grant-types", "", grantTypesHelp+" (default authorization_code,refresh_token)")
	auth.register(cmd)
	cmd.MarkFlagRequired("app")
	cmd.MarkFlagRequired("resource")
	return cmd
}

func oauthClientsUpdateCmd() *cobra.Command {
	var redirects, postLogout, origins, format, backchannel, grants string
	var hosted, sessionRequired bool
	var auth clientAuthFlags
	cmd := &cobra.Command{
		Use:   "update CLIENT_ID",
		Short: "Change an OAuth client's URIs, allowed origins, hosted login, grant types, access token format, back-channel logout or token endpoint authentication",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			body := map[string]any{}
			if cmd.Flags().Changed("redirect-uris") {
				body["redirect_uris"] = splitList(redirects)
			}
			if cmd.Flags().Changed("post-logout-redirect-uris") {
				body["post_logout_redirect_uris"] = splitList(postLogout)
			}
			if cmd.Flags().Changed("allowed-origins") {
				body["allowed_origins"] = splitList(origins)
			}
			if cmd.Flags().Changed("hosted-login") {
				body["hosted_login"] = hosted
			}
			if cmd.Flags().Changed("access-token-format") {
				body["access_token_format"] = format
			}
			if cmd.Flags().Changed("grant-types") {
				body["grant_types"] = grantTypes(grants)
			}
			if cmd.Flags().Changed("backchannel-logout-uri") {
				body["backchannel_logout_uri"] = backchannel
			}
			if cmd.Flags().Changed("backchannel-logout-session-required") {
				body["backchannel_logout_session_required"] = sessionRequired
			}
			if err := auth.apply(cmd, body); err != nil {
				return err
			}
			if _, err := c.patch(envPath()+"/oauth-clients/"+args[0], body); err != nil {
				return err
			}
			newPrinter().ok("OAuth client updated: " + args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&redirects, "redirect-uris", "", "Comma-separated redirect URIs")
	cmd.Flags().StringVar(&postLogout, "post-logout-redirect-uris", "", "Comma-separated post-logout URIs (empty clears)")
	cmd.Flags().StringVar(&origins, "allowed-origins", "", "Comma-separated browser origins allowed with CORS (empty clears)")
	cmd.Flags().BoolVar(&hosted, "hosted-login", false, "Use IAMKit's hosted sign-in pages")
	cmd.Flags().StringVar(&format, "access-token-format", "", "Access token format: jwt or opaque (introspection/userinfo only)")
	cmd.Flags().StringVar(&backchannel, "backchannel-logout-uri", "", "HTTPS URL that receives logout tokens (empty turns back-channel logout off)")
	cmd.Flags().BoolVar(&sessionRequired, "backchannel-logout-session-required", false, "Record that the client needs sid in logout tokens")
	cmd.Flags().StringVar(&grants, "grant-types", "", grantTypesHelp+" (replaces the list)")
	auth.register(cmd)
	return cmd
}

// deviceCodeGrant is the RFC 8628 grant type; --grant-types accepts
// device_code for it.
const deviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code"

// tokenExchangeGrant is the RFC 8693 grant type; --grant-types accepts
// token_exchange for it.
const tokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"

const grantTypesHelp = "Comma-separated grants: authorization_code, refresh_token, device_code (needs --hosted-login), token_exchange (confidential clients)"

// grantTypes reads --grant-types, expanding device_code and token_exchange
// to their URNs.
func grantTypes(raw string) []string {
	out := []string{}
	for _, grant := range splitList(raw) {
		switch grant {
		case "device_code":
			grant = deviceCodeGrant
		case "token_exchange":
			grant = tokenExchangeGrant
		}
		out = append(out, grant)
	}
	return out
}

func oauthClientsDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable CLIENT_ID",
		Short: "Disable an OAuth client and revoke its tokens",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.delete(envPath() + "/oauth-clients/" + args[0]); err != nil {
				return err
			}
			newPrinter().ok("OAuth client disabled: " + args[0])
			return nil
		},
	}
}

func logoutDeliveriesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "logout-deliveries",
		Aliases: []string{"logouts"},
		Short:   "Back-channel logout notifications sent to OAuth clients",
	}
	var limit, offset int
	var status, client, search string
	list := &cobra.Command{
		Use:   "list",
		Short: "List logout deliveries, newest first",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			params := url.Values{}
			if limit > 0 {
				params.Set("limit", strconv.Itoa(limit))
			}
			if offset > 0 {
				params.Set("offset", strconv.Itoa(offset))
			}
			for key, value := range map[string]string{"search": search, "status": status, "client_id": client} {
				if value != "" {
					params.Set(key, value)
				}
			}
			query := ""
			if len(params) > 0 {
				query = "?" + params.Encode()
			}
			data, err := c.get(envPath() + "/logout-deliveries" + query)
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "USER", "APPLICATION", "STATUS", "ATTEMPTS", "LAST ERROR", "CREATED"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "user_email"), str(m, "application_name"), str(m, "status"), str(m, "attempts"), str(m, "last_error"), str(m, "created_at")}
			})
			return nil
		},
	}
	list.Flags().IntVar(&limit, "limit", 0, "Max results")
	list.Flags().IntVar(&offset, "offset", 0, "Offset")
	list.Flags().StringVar(&status, "status", "", "pending, delivered or failed")
	list.Flags().StringVar(&client, "client", "", "Only deliveries to this OAuth client ID")
	list.Flags().StringVar(&search, "search", "", "Filter by user email or application name")
	retry := &cobra.Command{
		Use:   "retry DELIVERY_ID",
		Short: "Send a failed logout notification again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.post(envPath()+"/logout-deliveries/"+args[0]+"/retry", map[string]any{}); err != nil {
				return err
			}
			newPrinter().ok("Logout delivery queued again: " + args[0])
			return nil
		},
	}
	cmd.AddCommand(list, retry)
	return cmd
}
