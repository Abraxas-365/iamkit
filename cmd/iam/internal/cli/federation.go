package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func federationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "federation",
		Aliases: []string{"fed", "connections"},
		Short:   "Manage federation connections (external identity providers)",
	}
	cmd.AddCommand(fedListCmd())
	cmd.AddCommand(fedGetCmd())
	cmd.AddCommand(fedCreateCmd())
	cmd.AddCommand(fedUpdateCmd())
	cmd.AddCommand(fedDisableCmd())
	cmd.AddCommand(fedEnableCmd())
	cmd.AddCommand(fedTestCmd())
	return cmd
}

func fedTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test CONNECTION_ID",
		Short: "Print a one-time link that signs in through the connection in test mode",
		Long: `Issues a one-time test link (valid 10 minutes) for an OIDC or SAML connection,
active or not. Open it in a browser: it signs in at the identity provider and
shows what came back (claims, mapped email, name and groups). It creates no
session, user or link.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.post(envPath()+"/federation-connections/"+args[0]+"/test", nil)
			if err != nil {
				return err
			}
			p := newPrinter()
			if p.wantJSON() {
				p.JSON(data)
				return nil
			}
			var out struct {
				URL       string `json:"url"`
				ExpiresAt string `json:"expires_at"`
			}
			if json.Unmarshal(data, &out) != nil || out.URL == "" {
				p.JSON(data)
				return nil
			}
			fmt.Fprintf(os.Stderr, "Open this link in a browser within 10 minutes; it works once (expires %s):\n", out.ExpiresAt)
			fmt.Fprintln(p.out, out.URL)
			return nil
		},
	}
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
	var name, provider, issuer, clientID, secretEnv, secretFile, tenant, team, key, org, signupOrg, signupGroup, baseURL string
	var tenants, domains, mappingFlags []string
	var groupsClaim string
	var linkEmail, updateProfile, draft bool
	var o oauth2Flags
	var sf samlFlags
	var lf ldapFlags
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a federation connection",
		Example: `  iam federation create --provider google --name Google --client-id ID --client-secret-file secret.txt --link-email
  iam federation create --provider microsoft --tenant common --name Microsoft --client-id ID --client-secret-file secret.txt
  iam federation create --provider google --domains acme.com --name "Acme Google" --client-id ID --client-secret-file secret.txt --organization ORG_ID
  iam federation create --provider apple --name Apple --client-id com.example.web --team-id TEAM --key-id KEY --client-secret-file AuthKey.p8
  iam federation create --name Okta --issuer https://acme.okta.com --client-id ID --secret-env IAMKIT_PROVIDER_OKTA --organization ORG_ID
  iam federation create --provider gitlab --base-url https://git.acme.com --name GitLab --client-id ID --client-secret-file secret.txt --organization ORG_ID
  iam federation create --provider github_enterprise --base-url https://github.acme.com --name "GitHub Acme" --client-id ID --client-secret-file secret.txt
  iam federation create --provider oauth2 --name Discord --client-id ID --client-secret-file secret.txt \
    --authorize-url https://discord.com/oauth2/authorize --token-url https://discord.com/api/oauth2/token \
    --userinfo-url https://discord.com/api/users/@me --scopes identify,email \
    --claim-subject id --claim-email email --claim-email-verified verified --claim-name global_name
  iam federation create --provider saml --name "Acme Okta" --organization ORG_ID --metadata-url https://acme.okta.com/app/ID/sso/saml/metadata
  iam federation create --provider saml --name "Acme Okta" --organization ORG_ID --draft   # prints the ACS URL and entity ID to give the IdP first
  iam federation create --provider saml --name "Acme ADFS" --organization ORG_ID --metadata-file FederationMetadata.xml --name-id-format transient --attr-subject objectGUID
  iam federation create --provider ldap --name "Acme AD" --organization ORG_ID --ldap-url ldaps://dc1.acme.com \
    --bind-dn "CN=iam,OU=Service,DC=acme,DC=com" --client-secret-file bind-password.txt \
    --user-base-dn "OU=People,DC=acme,DC=com" --user-filter "(sAMAccountName={username})" --ca-file acme-ca.pem`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if provider == "ldap" {
				if clientID != "" || secretEnv != "" || issuer != "" {
					return fmt.Errorf("LDAP connections take --ldap-url, --user-base-dn and optionally --bind-dn with --client-secret-file, not a client ID, secret env or issuer")
				}
				options, err := lf.options(sf)
				if err != nil {
					return err
				}
				body := map[string]any{"name": name, "provider": provider, "organization_id": org, "options": options}
				if secretFile != "" {
					secret, err := os.ReadFile(secretFile)
					if err != nil {
						return err
					}
					body["client_secret"] = strings.TrimSpace(string(secret))
				}
				if linkEmail {
					body["link_email"] = true
				}
				if updateProfile {
					body["update_profile"] = true
				}
				if err := addMappings(body, mappingFlags); err != nil {
					return err
				}
				data, err := mustClient(cmd).post(envPath()+"/federation-connections", body)
				if err != nil {
					return err
				}
				newPrinter().created("federation connection", data)
				return nil
			}
			if provider == "saml" {
				if clientID != "" || secretEnv != "" || secretFile != "" || issuer != "" {
					return fmt.Errorf("SAML connections take --metadata-url or --metadata-file, not a client ID, secret or issuer")
				}
				body := map[string]any{"name": name, "provider": provider, "organization_id": org}
				if draft {
					// A draft has no metadata yet: IAMKit answers with the
					// values to give the identity provider.
					if sf.metadataURL != "" || sf.metadataFile != "" {
						return fmt.Errorf("--draft creates the connection before the identity provider metadata exists; add it afterwards with `iam federation update`")
					}
					body["draft"] = true
					if options := sf.draftOptions(); options != nil {
						body["options"] = options
					}
				} else {
					options, err := sf.options()
					if err != nil {
						return err
					}
					body["options"] = options
				}
				if linkEmail {
					body["link_email"] = true
				}
				if updateProfile {
					body["update_profile"] = true
				}
				if err := addMappings(body, mappingFlags); err != nil {
					return err
				}
				c := mustClient(cmd)
				data, err := c.post(envPath()+"/federation-connections", body)
				if err != nil {
					return err
				}
				p := newPrinter()
				if !draft {
					p.created("federation connection", data)
					return nil
				}
				// A draft's value is the SP side: show it next to the ID.
				var created struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(data, &created) != nil || created.ID == "" {
					p.created("federation connection", data)
					return nil
				}
				detail, err := c.get(envPath() + "/federation-connections/" + created.ID)
				if err != nil {
					return err
				}
				p.draftCreated(created.ID, detail)
				return nil
			}
			if clientID == "" {
				return fmt.Errorf("--client-id is required")
			}
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
			if baseURL != "" {
				options["base_url"] = baseURL
			}
			o.apply(options)
			if groupsClaim != "" {
				options["groups_claim"] = groupsClaim
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
			if updateProfile {
				body["update_profile"] = true
			}
			if err := addMappings(body, mappingFlags); err != nil {
				return err
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
	cmd.Flags().StringVar(&provider, "provider", "oidc", "oidc, google, microsoft, github, apple, gitlab, github_enterprise, oauth2, saml or ldap")
	cmd.Flags().StringVar(&issuer, "issuer", "", "OIDC issuer URL (provider oidc only)")
	cmd.Flags().StringVar(&clientID, "client-id", "", "OAuth client ID; Apple: the Services ID (required except for SAML and LDAP)")
	cmd.Flags().StringVar(&secretEnv, "secret-env", "", "Env var name holding the client secret")
	cmd.Flags().StringVar(&secretFile, "client-secret-file", "", "File with the client secret, stored encrypted; Apple: the .p8 key; LDAP: the bind DN's password")
	cmd.Flags().StringVar(&tenant, "tenant", "", "Microsoft: common, organizations, consumers or a tenant ID")
	cmd.Flags().StringSliceVar(&tenants, "tenants", nil, "Microsoft: tenant IDs allowed under common/organizations")
	cmd.Flags().StringSliceVar(&domains, "domains", nil, "Google: only accept Google Workspace accounts of these domains")
	cmd.Flags().StringVar(&team, "team-id", "", "Apple: team ID")
	cmd.Flags().StringVar(&key, "key-id", "", "Apple: key ID")
	cmd.Flags().StringVar(&org, "organization", "", "Organization ID for an organization SSO connection")
	cmd.Flags().StringVar(&signupOrg, "signup-organization", "", "Sign up new users into this organization (environment connections)")
	cmd.Flags().StringVar(&signupGroup, "signup-group", "", "Default group for signed-up users")
	cmd.Flags().BoolVar(&linkEmail, "link-email", false, "Link existing users by verified email (organization connections: members on its verified domains)")
	cmd.Flags().BoolVar(&updateProfile, "update-profile", false, "Refresh linked users' name and passwordless email from the provider at sign-in")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "GitLab self-managed or GitHub Enterprise Server URL")
	cmd.Flags().StringArrayVar(&mappingFlags, "group-mapping", nil, "Organization connections: map an IdP group value to a group of the organization, VALUE=GROUP_UUID (repeatable)")
	cmd.Flags().StringVar(&groupsClaim, "groups-claim", "", "OIDC (oidc, google, microsoft, gitlab): ID token claim with the user's groups (default groups)")
	cmd.Flags().BoolVar(&draft, "draft", false, "SAML: create an inactive draft without metadata and print the SP values (ACS URL, entity ID, metadata URL) to configure the identity provider; then `iam federation update` with the metadata and `iam federation enable`")
	o.register(cmd)
	sf.register(cmd)
	lf.register(cmd)
	cmd.MarkFlagRequired("name")
	return cmd
}

// addMappings sets group_mappings on body when --group-mapping was given.
func addMappings(body map[string]any, values []string) error {
	if len(values) == 0 {
		return nil
	}
	m, err := groupMappings(values)
	if err != nil {
		return err
	}
	body["group_mappings"] = m
	return nil
}

// groupMappings parses repeated --group-mapping value=GROUP_UUID flags.
func groupMappings(values []string) ([]map[string]string, error) {
	out := make([]map[string]string, 0, len(values))
	for _, v := range values {
		i := strings.LastIndex(v, "=")
		if i <= 0 || i == len(v)-1 {
			return nil, fmt.Errorf("--group-mapping %q must be VALUE=GROUP_UUID", v)
		}
		out = append(out, map[string]string{"value": v[:i], "group_id": v[i+1:]})
	}
	return out, nil
}

// samlFlags are the options of a SAML connection.
type samlFlags struct {
	metadataURL, metadataFile, nameIDFormat, subject, email, name, groups string
	idpClient                                                             string
	signRequests, singleLogout                                            bool
}

func (f *samlFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.metadataURL, "metadata-url", "", "SAML: identity provider metadata URL (HTTPS, fetched on save)")
	cmd.Flags().StringVar(&f.metadataFile, "metadata-file", "", "SAML: file with the identity provider metadata XML")
	cmd.Flags().StringVar(&f.nameIDFormat, "name-id-format", "", "SAML: unspecified, persistent, email or transient")
	cmd.Flags().StringVar(&f.subject, "attr-subject", "", "SAML/LDAP: attribute with the stable user ID (SAML default: the NameID; LDAP: objectGUID, entryUUID or the DN)")
	cmd.Flags().StringVar(&f.email, "attr-email", "", "SAML/LDAP: attribute with the email")
	cmd.Flags().StringVar(&f.name, "attr-name", "", "SAML/LDAP: attribute with the display name")
	cmd.Flags().StringVar(&f.groups, "groups-attribute", "", "SAML/LDAP: multi-valued attribute with the user's groups (SAML default: groups, memberOf or the Microsoft groups claim; LDAP: memberOf)")
	cmd.Flags().StringVar(&f.idpClient, "idp-initiated-client", "", "SAML: OAuth client (with an initiate_login_uri) that IdP-initiated logins are handed to; unset refuses IdP-initiated responses")
	cmd.Flags().BoolVar(&f.signRequests, "sign-requests", false, "SAML: sign AuthnRequests with the environment signing key")
	cmd.Flags().BoolVar(&f.singleLogout, "single-logout", false, "SAML: single logout (the identity provider's metadata must publish a SingleLogoutService; give the SP metadata back to it)")
}

func (f samlFlags) set() bool {
	return f.metadataURL != "" || f.metadataFile != "" || f.nameIDFormat != "" || f.attributes() != nil || f.signRequests || f.singleLogout || f.idpClient != ""
}

// attributes is the attribute mapping shared by SAML and LDAP, nil when
// no --attr-* flag is set.
func (f samlFlags) attributes() map[string]string {
	attributes := map[string]string{}
	for k, v := range map[string]string{"subject": f.subject, "email": f.email, "name": f.name, "groups": f.groups} {
		if v != "" {
			attributes[k] = v
		}
	}
	if len(attributes) == 0 {
		return nil
	}
	return attributes
}

// ldapFlags are the options of an LDAP / Active Directory connection.
type ldapFlags struct {
	url, bindDN, baseDN, filter, caFile string
	startTLS                            bool
}

func (f *ldapFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.url, "ldap-url", "", "LDAP: directory URL, ldaps://host[:636] or ldap://host[:389] with --start-tls")
	cmd.Flags().BoolVar(&f.startTLS, "start-tls", false, "LDAP: upgrade an ldap:// connection with StartTLS (required for ldap://)")
	cmd.Flags().StringVar(&f.bindDN, "bind-dn", "", "LDAP: service account DN that searches for users (its password via --client-secret-file); omit for anonymous search")
	cmd.Flags().StringVar(&f.baseDN, "user-base-dn", "", "LDAP: subtree searched for users")
	cmd.Flags().StringVar(&f.filter, "user-filter", "", "LDAP: user filter with {email} or {username} (default (|(mail={email})(userPrincipalName={email})))")
	cmd.Flags().StringVar(&f.caFile, "ca-file", "", "LDAP: PEM file with the CA certificates that sign the directory certificate (default: system roots)")
}

func (f ldapFlags) set() bool {
	return f.url != "" || f.bindDN != "" || f.baseDN != "" || f.filter != "" || f.caFile != "" || f.startTLS
}

func (f ldapFlags) options(sf samlFlags) (map[string]any, error) {
	if f.url == "" || f.baseDN == "" {
		return nil, fmt.Errorf("--ldap-url and --user-base-dn are required")
	}
	options := map[string]any{"url": f.url, "user_base_dn": f.baseDN}
	if f.startTLS {
		options["start_tls"] = true
	}
	if f.bindDN != "" {
		options["bind_dn"] = f.bindDN
	}
	if f.filter != "" {
		options["user_filter"] = f.filter
	}
	if f.caFile != "" {
		raw, err := os.ReadFile(f.caFile)
		if err != nil {
			return nil, err
		}
		options["ca_pem"] = string(raw)
	}
	if a := sf.attributes(); a != nil {
		options["attributes"] = a
	}
	return options, nil
}

// draftOptions are the SAML options a draft may already carry (no metadata);
// nil when none is set.
func (f samlFlags) draftOptions() map[string]any {
	options := map[string]any{}
	if f.nameIDFormat != "" {
		options["name_id_format"] = f.nameIDFormat
	}
	if a := f.attributes(); a != nil {
		options["attributes"] = a
	}
	if f.signRequests {
		options["sign_requests"] = true
	}
	if f.singleLogout {
		options["single_logout"] = true
	}
	if f.idpClient != "" {
		options["idp_initiated_client_id"] = f.idpClient
	}
	if len(options) == 0 {
		return nil
	}
	return options
}

// draftCreated prints a new SAML draft: the ID on stdout and the values to
// give the identity provider on stderr; JSON output is the connection.
func (p *printer) draftCreated(id string, detail json.RawMessage) {
	if p.wantJSON() {
		p.JSON(detail)
		return
	}
	var d struct {
		SAML struct {
			EntityID string `json:"entity_id"`
			ACS      string `json:"acs_url"`
			Metadata string `json:"metadata_url"`
		} `json:"saml"`
	}
	_ = json.Unmarshal(detail, &d)
	fmt.Fprintf(os.Stderr, "Created SAML draft connection: %s\n", id)
	fmt.Fprintf(os.Stderr, "  ACS URL:      %s\n  Entity ID:    %s\n  Metadata URL: %s\n", d.SAML.ACS, d.SAML.EntityID, d.SAML.Metadata)
	fmt.Fprintf(os.Stderr, "Give these to the identity provider, then: iam federation update %s --metadata-url URL  and  iam federation enable %s\n", id, id)
	fmt.Fprintln(p.out, id)
}

func (f samlFlags) options() (map[string]any, error) {
	options := map[string]any{}
	switch {
	case (f.metadataURL == "") == (f.metadataFile == ""):
		return nil, fmt.Errorf("provide exactly one of --metadata-url or --metadata-file")
	case f.metadataURL != "":
		options["metadata_url"] = f.metadataURL
	default:
		raw, err := os.ReadFile(f.metadataFile)
		if err != nil {
			return nil, err
		}
		options["metadata_xml"] = string(raw)
	}
	if f.nameIDFormat != "" {
		options["name_id_format"] = f.nameIDFormat
	}
	if a := f.attributes(); a != nil {
		options["attributes"] = a
	}
	if f.signRequests {
		options["sign_requests"] = true
	}
	if f.singleLogout {
		options["single_logout"] = true
	}
	if f.idpClient != "" {
		options["idp_initiated_client_id"] = f.idpClient
	}
	return options, nil
}

// oauth2Flags are the endpoint and claim-mapping flags of an oauth2
// connection.
type oauth2Flags struct {
	authorize, token, userinfo, subject, email, verified, name, groups string
	scopes                                                             []string
}

func (o *oauth2Flags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.authorize, "authorize-url", "", "OAuth 2.0: authorization endpoint")
	cmd.Flags().StringVar(&o.token, "token-url", "", "OAuth 2.0: token endpoint")
	cmd.Flags().StringVar(&o.userinfo, "userinfo-url", "", "OAuth 2.0: user info endpoint (JSON)")
	cmd.Flags().StringSliceVar(&o.scopes, "scopes", nil, "OAuth 2.0: scopes to request")
	cmd.Flags().StringVar(&o.subject, "claim-subject", "", "OAuth 2.0: user info member with the user ID (dots for nesting)")
	cmd.Flags().StringVar(&o.email, "claim-email", "", "OAuth 2.0: user info member with the email")
	cmd.Flags().StringVar(&o.verified, "claim-email-verified", "", "OAuth 2.0: boolean member saying the email is verified (without it emails are never trusted)")
	cmd.Flags().StringVar(&o.name, "claim-name", "", "OAuth 2.0: user info member with the display name")
	cmd.Flags().StringVar(&o.groups, "claim-groups", "", "OAuth 2.0: user info member with the user's groups (an array of strings)")
}

func (o oauth2Flags) apply(options map[string]any) {
	if o.authorize == "" && o.token == "" && o.userinfo == "" && o.subject == "" {
		return
	}
	options["authorize_url"], options["token_url"], options["userinfo_url"] = o.authorize, o.token, o.userinfo
	if len(o.scopes) > 0 {
		options["scopes"] = o.scopes
	}
	claims := map[string]string{"subject": o.subject}
	for k, v := range map[string]string{"email": o.email, "email_verified": o.verified, "name": o.name, "groups": o.groups} {
		if v != "" {
			claims[k] = v
		}
	}
	options["claims"] = claims
}

func fedUpdateCmd() *cobra.Command {
	var name, secretFile string
	var jit, linkEmail, updateProfile, signup bool
	var enforcement, groupsClaim string
	var mappingFlags []string
	var clearMappings bool
	var sf samlFlags
	var lf ldapFlags
	cmd := &cobra.Command{
		Use:   "update CONNECTION_ID",
		Short: "Update a federation connection",
		Example: `  iam federation update CONN_ID --update-profile
  iam federation update CONN_ID --link-email --jit=false
  iam federation update CONN_ID --client-secret-file new-secret.txt
  iam federation update CONN_ID --group-mapping "Engineering=GROUP_UUID" --group-mapping "Admins=OTHER_GROUP_UUID"
  iam federation update CONN_ID --clear-group-mappings
  iam federation update SAML_CONN_ID --metadata-url https://acme.okta.com/app/ID/sso/saml/metadata
  iam federation update LDAP_CONN_ID --ldap-url ldaps://dc1.acme.com --bind-dn "CN=iam,DC=acme,DC=com" \
    --user-base-dn "OU=People,DC=acme,DC=com" --user-filter "(sAMAccountName={username})"

SAML and LDAP options replace the stored ones as a whole: pass the metadata
source (SAML) or directory URL and base DN (LDAP) again with any change (a
metadata URL is refetched; an LDAP host and base DN cannot change). Likewise
--groups-claim and --claim-groups replace an OIDC or OAuth 2.0 connection's
options as a whole. --group-mapping replaces the whole list of group mappings.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			flags := cmd.Flags()
			if flags.Changed("name") {
				body["name"] = name
			}
			if secretFile != "" {
				secret, err := os.ReadFile(secretFile)
				if err != nil {
					return err
				}
				body["client_secret"] = strings.TrimSpace(string(secret))
			}
			for flag, field := range map[string]string{"jit": "jit_provisioning", "link-email": "link_email", "update-profile": "update_profile", "signup": "signup"} {
				if flags.Changed(flag) {
					v, _ := flags.GetBool(flag)
					body[field] = v
				}
			}
			if flags.Changed("enforcement") {
				body["enforcement"] = enforcement
			}
			if clearMappings && len(mappingFlags) > 0 {
				return fmt.Errorf("--group-mapping and --clear-group-mappings exclude each other")
			}
			if clearMappings {
				body["group_mappings"] = []map[string]string{}
			} else if err := addMappings(body, mappingFlags); err != nil {
				return err
			}
			if lf.set() {
				options, err := lf.options(sf)
				if err != nil {
					return err
				}
				body["options"] = options
			} else if sf.set() {
				options, err := sf.options()
				if err != nil {
					return err
				}
				body["options"] = options
			}
			if groupsClaim != "" {
				if _, ok := body["options"]; ok {
					return fmt.Errorf("--groups-claim applies to OIDC connections, not SAML or LDAP")
				}
				body["options"] = map[string]any{"groups_claim": groupsClaim}
			}
			if len(body) == 0 {
				return fmt.Errorf("nothing to update")
			}
			c := mustClient(cmd)
			if _, err := c.patch(envPath()+"/federation-connections/"+args[0], body); err != nil {
				return err
			}
			newPrinter().ok("Federation connection updated: " + args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Connection name")
	cmd.Flags().StringVar(&secretFile, "client-secret-file", "", "File with a new client secret (LDAP: bind password), stored encrypted")
	cmd.Flags().BoolVar(&jit, "jit", false, "Just-in-time provisioning (organization connections)")
	cmd.Flags().BoolVar(&linkEmail, "link-email", false, "Link existing users by verified email")
	cmd.Flags().BoolVar(&updateProfile, "update-profile", false, "Refresh linked users' profile at sign-in")
	cmd.Flags().BoolVar(&signup, "signup", false, "Create accounts for new users (environment connections)")
	cmd.Flags().StringVar(&enforcement, "enforcement", "", "optional or enforced (organization connections)")
	cmd.Flags().StringArrayVar(&mappingFlags, "group-mapping", nil, "Replace the group mappings: VALUE=GROUP_UUID (repeatable)")
	cmd.Flags().BoolVar(&clearMappings, "clear-group-mappings", false, "Remove every group mapping")
	cmd.Flags().StringVar(&groupsClaim, "groups-claim", "", "OIDC: ID token claim with the user's groups; replaces the connection's options")
	sf.register(cmd)
	lf.register(cmd)
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

func fedEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable CONNECTION_ID",
		Short: "Enable a disabled federation connection as it was (linked users keep their accounts)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.post(envPath()+"/federation-connections/"+args[0]+"/enable", nil); err != nil {
				return err
			}
			newPrinter().ok("Federation connection enabled: " + args[0])
			return nil
		},
	}
}
