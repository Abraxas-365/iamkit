package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// keyValueWarning goes to stderr after a key is created: the value is never
// shown again.
const keyValueWarning = "Warning: this is the only time the key value is shown. Store it now; it cannot be retrieved later."

var (
	apiKeyOwnerTypes = []string{"user", "organization", "machine"}
	apiKeyStates     = []string{"active", "revoked", "expired"}
)

func apiKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "api-keys",
		Aliases: []string{"api-key"},
		Short:   "Manage API keys of users, organizations and machine users",
		Long: `API keys (ik_key_) have three owners: a user, an organization or a machine
user. The value is shown once, when the key is created. Only machine keys
reach /api/v1; user and organization keys are validated by the services that
accept them (POST /identity/v1/introspect).

Operators create organization keys here; users create their own through the
identity API, and machine user keys with "iam machine-users api-keys".`,
	}
	cmd.AddCommand(apiKeysListCmd(), apiKeysGetCmd(), apiKeysCreateCmd(), apiKeysRevokeCmd(), apiKeyPolicyCmd())
	return cmd
}

// apiKeyFilters are the list filters shared by the environment-wide list.
type apiKeyFilters struct {
	OwnerType, Organization, User, Resource, State, Search string
	Limit, Offset                                          int
}

// query validates the filters and returns the query string ("" or "?…").
func (f apiKeyFilters) query() (string, error) {
	if f.OwnerType != "" && !contains(apiKeyOwnerTypes, f.OwnerType) {
		return "", fmt.Errorf("--owner-type must be one of %s", strings.Join(apiKeyOwnerTypes, ", "))
	}
	if f.State != "" && !contains(apiKeyStates, f.State) {
		return "", fmt.Errorf("--state must be one of %s", strings.Join(apiKeyStates, ", "))
	}
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("owner_type", f.OwnerType)
	set("organization_id", f.Organization)
	set("user_id", f.User)
	set("resource_id", f.Resource)
	set("state", f.State)
	set("search", f.Search)
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	if f.Offset > 0 {
		q.Set("offset", strconv.Itoa(f.Offset))
	}
	if len(q) == 0 {
		return "", nil
	}
	return "?" + q.Encode(), nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func apiKeyRow(m map[string]any) []string {
	owner, _ := m["owner"].(map[string]any)
	who := str(owner, "type")
	if id := str(owner, "user_id"); id != "" {
		who += ":" + truncateID(id)
	}
	org := str(m, "organization_name")
	if org == "" {
		org = truncateID(str(m, "organization_id"))
	}
	res := str(m, "resource_name")
	if res == "" {
		res = truncateID(str(m, "resource_id"))
	}
	expires := "never"
	if e, _ := m["expires"].(bool); e {
		expires = str(m, "expires_at")
	}
	last := str(m, "last_used_at")
	if last == "" {
		last = "—"
	}
	return []string{str(m, "id"), str(m, "name"), who, org, res, str(m, "obfuscated_value"), expires, last, str(m, "state")}
}

var apiKeyColumns = []string{"ID", "NAME", "OWNER", "ORGANIZATION", "RESOURCE", "KEY", "EXPIRES", "LAST USED", "STATE"}

func apiKeysListCmd() *cobra.Command {
	var f apiKeyFilters
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List API keys of every owner type (never their values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			query, err := f.query()
			if err != nil {
				return err
			}
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/api-keys" + query)
			if err != nil {
				return err
			}
			newPrinter().table(data, apiKeyColumns, apiKeyRow)
			return nil
		},
	}
	cmd.Flags().StringVar(&f.OwnerType, "owner-type", "", "Filter by owner: "+strings.Join(apiKeyOwnerTypes, ", "))
	cmd.Flags().StringVar(&f.Organization, "organization", "", "Filter by organization ID")
	cmd.Flags().StringVar(&f.User, "user", "", "Filter by user ID (user and machine keys)")
	cmd.Flags().StringVar(&f.Resource, "resource", "", "Filter by resource ID")
	cmd.Flags().StringVar(&f.State, "state", "", "Filter by state: "+strings.Join(apiKeyStates, ", "))
	cmd.Flags().StringVar(&f.Search, "search", "", "Search by name")
	cmd.Flags().IntVar(&f.Limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&f.Offset, "offset", 0, "Offset")
	return cmd
}

func apiKeysGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get KEY_ID",
		Short: "Get an API key (never its value)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/api-keys/" + url.PathEscape(args[0]))
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

// newKeyBody builds the creation body; unset fields are left out so the
// server defaults apply (expires_in omitted = never).
func newKeyBody(name, organization, application, resource string, permissions []string, expiresIn string) map[string]any {
	body := map[string]any{"name": name, "resource_id": resource}
	if organization != "" {
		body["organization_id"] = organization
	}
	if application != "" {
		body["application_id"] = application
	}
	if len(permissions) > 0 {
		body["permissions"] = permissions
	}
	if expiresIn != "" {
		body["expires_in"] = expiresIn
	}
	return body
}

// printIssuedKey prints a created key as JSON (the value must be captured)
// and warns on stderr that it is shown once.
func printIssuedKey(data json.RawMessage) {
	newPrinter().JSON(data)
	fmt.Fprintln(os.Stderr, keyValueWarning)
}

func apiKeysCreateCmd() *cobra.Command {
	var name, organization, resource, expiresIn string
	var permissions []string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an organization API key (value shown once)",
		Long: `Creates an API key owned by an organization for one resource, with the given
permissions (the resource's organization allowlist must allow them). The key
value is printed once as JSON, with a warning on stderr.

--expires-in is a duration from 1h to 8760h or "never" (the default). The
environment's policy may cap it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(permissions) == 0 {
				return fmt.Errorf("at least one --permission is required")
			}
			c := mustClient(cmd)
			data, err := c.post(envPath()+"/api-keys", newKeyBody(name, organization, "", resource, permissions, expiresIn))
			if err != nil {
				return err
			}
			printIssuedKey(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&organization, "organization", "", "Owner organization ID (required)")
	cmd.Flags().StringVar(&resource, "resource", "", "Resource ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "Key name (required)")
	cmd.Flags().StringSliceVar(&permissions, "permission", nil, "Permission the key carries; repeat or comma-separate (required)")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", `Expiration, 1h to 8760h or "never" (default never)`)
	for _, f := range []string{"organization", "resource", "name"} {
		cmd.MarkFlagRequired(f)
	}
	return cmd
}

func apiKeysRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke KEY_ID",
		Short: "Revoke an API key of any owner",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			if _, err := c.delete(envPath() + "/api-keys/" + url.PathEscape(args[0])); err != nil {
				return err
			}
			newPrinter().ok("API key revoked: " + args[0])
			return nil
		},
	}
}

// ── Policy ──

func apiKeyPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Show or change the environment's API key policy",
	}
	cmd.AddCommand(apiKeyPolicyGetCmd(), apiKeyPolicySetCmd())
	return cmd
}

func apiKeyPolicyGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Show the API key policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/api-key-policy")
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

// policyChange is what "policy set" was asked to change; nil = keep.
type policyChange struct {
	UserKeys, OrganizationKeys     *bool
	MaxTTLDays                     *int
	NoMaxTTL                       bool
	MaxPerUser, MaxPerOrganization *int
}

// apply merges the change into the current policy (PUT replaces it whole).
func (ch policyChange) apply(current map[string]any) (map[string]any, error) {
	if ch.MaxTTLDays != nil && ch.NoMaxTTL {
		return nil, fmt.Errorf("--max-ttl-days and --no-max-ttl are exclusive")
	}
	if ch.MaxTTLDays != nil && (*ch.MaxTTLDays < 1 || *ch.MaxTTLDays > 365) {
		return nil, fmt.Errorf("--max-ttl-days must be 1 to 365")
	}
	if ch.MaxPerUser != nil && (*ch.MaxPerUser < 1 || *ch.MaxPerUser > 100) {
		return nil, fmt.Errorf("--max-per-user must be 1 to 100")
	}
	if ch.MaxPerOrganization != nil && (*ch.MaxPerOrganization < 1 || *ch.MaxPerOrganization > 500) {
		return nil, fmt.Errorf("--max-per-organization must be 1 to 500")
	}
	body := map[string]any{}
	for _, k := range []string{"user_keys", "organization_keys", "max_ttl_days", "max_per_user", "max_per_organization"} {
		body[k] = current[k]
	}
	if ch.UserKeys != nil {
		body["user_keys"] = *ch.UserKeys
	}
	if ch.OrganizationKeys != nil {
		body["organization_keys"] = *ch.OrganizationKeys
	}
	if ch.MaxTTLDays != nil {
		body["max_ttl_days"] = *ch.MaxTTLDays
	}
	if ch.NoMaxTTL {
		body["max_ttl_days"] = nil
	}
	if ch.MaxPerUser != nil {
		body["max_per_user"] = *ch.MaxPerUser
	}
	if ch.MaxPerOrganization != nil {
		body["max_per_organization"] = *ch.MaxPerOrganization
	}
	return body, nil
}

func apiKeyPolicySetCmd() *cobra.Command {
	var userKeys, orgKeys, noMaxTTL bool
	var maxTTL, perUser, perOrg int
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Change the API key policy (flags not given keep their value)",
		Long: `Changes the environment's API key policy. Only the flags you give change;
the rest keep their current value.

  --user-keys=false          stop users creating keys (existing keys stop validating)
  --organization-keys=false  stop organization keys
  --max-ttl-days N | --no-max-ttl   cap key lifetime (1-365 days) or remove the cap
  --max-per-user N           1-100 live keys per user
  --max-per-organization N   1-500 live keys per organization`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fl := cmd.Flags()
			var ch policyChange
			ch.NoMaxTTL = noMaxTTL
			if fl.Changed("user-keys") {
				ch.UserKeys = &userKeys
			}
			if fl.Changed("organization-keys") {
				ch.OrganizationKeys = &orgKeys
			}
			if fl.Changed("max-ttl-days") {
				ch.MaxTTLDays = &maxTTL
			}
			if fl.Changed("max-per-user") {
				ch.MaxPerUser = &perUser
			}
			if fl.Changed("max-per-organization") {
				ch.MaxPerOrganization = &perOrg
			}
			if ch == (policyChange{}) {
				return fmt.Errorf("nothing to change: give at least one flag")
			}
			// Validate before touching the server.
			if _, err := ch.apply(map[string]any{}); err != nil {
				return err
			}
			c := mustClient(cmd)
			raw, err := c.get(envPath() + "/api-key-policy")
			if err != nil {
				return err
			}
			var current map[string]any
			if err := json.Unmarshal(raw, &current); err != nil {
				return fmt.Errorf("reading the current policy: %w", err)
			}
			body, _ := ch.apply(current)
			data, err := c.put(envPath()+"/api-key-policy", body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().BoolVar(&userKeys, "user-keys", true, "Whether users may create API keys")
	cmd.Flags().BoolVar(&orgKeys, "organization-keys", true, "Whether organizations may have API keys")
	cmd.Flags().IntVar(&maxTTL, "max-ttl-days", 0, "Longest key lifetime in days (1-365)")
	cmd.Flags().BoolVar(&noMaxTTL, "no-max-ttl", false, "Remove the lifetime cap")
	cmd.Flags().IntVar(&perUser, "max-per-user", 0, "Live keys per user (1-100)")
	cmd.Flags().IntVar(&perOrg, "max-per-organization", 0, "Live keys per organization (1-500)")
	return cmd
}

// ── Resource allowlists ──

func resourceAPIKeyPermissionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "api-key-permissions",
		Aliases: []string{"key-permissions"},
		Short:   "Which permissions API keys may carry on a resource",
		Long: `Each resource lists the permissions API keys of users and of organizations may
carry. Both lists are empty until an operator allows some, so no key can be
created for the resource. Machine keys are not limited by these lists.`,
	}
	cmd.AddCommand(resourceAPIKeyPermissionsGetCmd(), resourceAPIKeyPermissionsSetCmd())
	return cmd
}

func resourceAPIKeyPermissionsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get RESOURCE_ID",
		Short: "Show the permissions user and organization keys may carry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := mustClient(cmd)
			data, err := c.get(envPath() + "/resources/" + args[0])
			if err != nil {
				return err
			}
			current, err := allowlistOf(data)
			if err != nil {
				return err
			}
			out, _ := json.Marshal(current)
			newPrinter().detail(out)
			return nil
		},
	}
}

// allowlistOf reads api_key_permissions out of a resource, both lists always
// present.
func allowlistOf(resource json.RawMessage) (map[string][]string, error) {
	var r struct {
		Allowlist struct {
			User         []string `json:"user"`
			Organization []string `json:"organization"`
		} `json:"api_key_permissions"`
	}
	if err := json.Unmarshal(resource, &r); err != nil {
		return nil, fmt.Errorf("reading the resource: %w", err)
	}
	out := map[string][]string{"user": r.Allowlist.User, "organization": r.Allowlist.Organization}
	for k, v := range out {
		if v == nil {
			out[k] = []string{}
		}
	}
	return out, nil
}

func resourceAPIKeyPermissionsSetCmd() *cobra.Command {
	var user, organization []string
	cmd := &cobra.Command{
		Use:   "set RESOURCE_ID",
		Short: "Replace the permissions user and/or organization keys may carry",
		Long: `Replaces the allowlists. A list you do not give keeps its current value; give
an empty value (--user=) to clear one. Permissions must be in the resource's
catalog; the IAM resource keeps both lists empty.`,
		Example: `  iam resources api-key-permissions set RES --user orders:read --organization orders:read,orders:write`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fl := cmd.Flags()
			if !fl.Changed("user") && !fl.Changed("organization") {
				return fmt.Errorf("give --user and/or --organization")
			}
			c := mustClient(cmd)
			path := envPath() + "/resources/" + args[0]
			raw, err := c.get(path)
			if err != nil {
				return err
			}
			body, err := allowlistOf(raw)
			if err != nil {
				return err
			}
			if fl.Changed("user") {
				body["user"] = cleanList(user)
			}
			if fl.Changed("organization") {
				body["organization"] = cleanList(organization)
			}
			if _, err := c.put(path+"/api-key-permissions", body); err != nil {
				return err
			}
			newPrinter().ok("API key permissions updated: " + args[0])
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&user, "user", nil, "Permissions user keys may carry (repeat or comma-separate; empty clears)")
	cmd.Flags().StringSliceVar(&organization, "organization", nil, "Permissions organization keys may carry (repeat or comma-separate; empty clears)")
	return cmd
}

// cleanList drops empty entries (--user= gives one) and never returns nil.
func cleanList(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
