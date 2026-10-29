package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func protectedResourcesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "protected-resources",
		Aliases: []string{"protected-resource", "mcp-servers"},
		Short:   "Manage protected resources (MCP servers) and the clients that use them",
		Long: `Manage protected resources: resources of an application that OAuth clients
reach with RFC 8707 resource indicators (MCP servers). Clients named by a
metadata document (their client_id is an https URL) are admitted per server:
list them with "clients list", then approve or block them.`,
	}
	cmd.AddCommand(prListCmd(), prGetCmd(), prCreateCmd(), prUpdateCmd(), prDeleteCmd(), prImpactCmd(), prClientsCmd())
	return cmd
}

func prPath(id string) string { return envPath() + "/protected-resources/" + url.PathEscape(id) }

func prClientPath(id, client string) string {
	return prPath(id) + "/clients/" + url.PathEscape(client)
}

func prColumns(m map[string]any) []string {
	return []string{str(m, "id"), str(m, "name"), str(m, "uri"), activeStr(m, "active"), str(m, "allow_client_metadata"), str(m, "client_admission")}
}

func prListCmd() *cobra.Command {
	var limit, offset int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List protected resources",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/protected-resources" + listQuery(limit, offset, ""))
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "NAME", "URI", "STATUS", "CIMD", "ADMISSION"}, prColumns)
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 0, "Max results")
	cmd.Flags().IntVar(&offset, "offset", 0, "Offset")
	return cmd
}

func prGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get ID",
		Short: "Show a protected resource",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(prPath(args[0]))
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func prCreateCmd() *cobra.Command {
	var app, resource, name, scopes string
	var idle, max int
	cmd := &cobra.Command{
		Use:     "create",
		Short:   "Register a resource of an application as a protected resource",
		Example: `  iam protected-resources create --application APP_ID --resource RESOURCE_ID --name "Billing MCP" --scopes billing:read`,
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{"application_id": app, "resource_id": resource, "name": name}
			if cmd.Flags().Changed("scopes") {
				body["default_scopes"] = splitList(scopes)
			}
			if idle > 0 {
				body["idle_ttl_seconds"] = idle
			}
			if max > 0 {
				body["max_ttl_seconds"] = max
			}
			data, err := mustClient(cmd).post(envPath()+"/protected-resources", body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&app, "application", "", "Application ID")
	f.StringVar(&resource, "resource", "", "Resource ID")
	f.StringVar(&name, "name", "", "Name")
	f.StringVar(&scopes, "scopes", "", "Default scopes, comma-separated")
	f.IntVar(&idle, "idle-ttl-seconds", 0, "Refresh token idle lifetime (default 7 days)")
	f.IntVar(&max, "max-ttl-seconds", 0, "Authorization lifetime (default 30 days)")
	_ = cmd.MarkFlagRequired("application")
	_ = cmd.MarkFlagRequired("resource")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func prUpdateCmd() *cobra.Command {
	var name, scopes, admission string
	var idle, max int
	var active, metadata bool
	cmd := &cobra.Command{
		Use:   "update ID",
		Short: "Change a protected resource",
		Long: `Change a protected resource. --active=false ends every authorization.
--allow-client-metadata lets clients named by a metadata document ask for the
server; --client-admission allowlist reviews them unless allowlisted, open
admits any such client without review.`,
		Example: `  iam protected-resources update ID --allow-client-metadata
  iam protected-resources update ID --client-admission allowlist`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{}
			flags := cmd.Flags()
			if flags.Changed("name") {
				body["name"] = name
			}
			if flags.Changed("scopes") {
				body["default_scopes"] = splitList(scopes)
			}
			if flags.Changed("idle-ttl-seconds") {
				body["idle_ttl_seconds"] = idle
			}
			if flags.Changed("max-ttl-seconds") {
				body["max_ttl_seconds"] = max
			}
			if flags.Changed("active") {
				body["active"] = active
			}
			if flags.Changed("allow-client-metadata") {
				body["allow_client_metadata"] = metadata
			}
			if flags.Changed("client-admission") {
				if admission != "allowlist" && admission != "open" {
					return fmt.Errorf("--client-admission must be allowlist or open")
				}
				body["client_admission"] = admission
			}
			if len(body) == 0 {
				return fmt.Errorf("nothing to change")
			}
			data, err := mustClient(cmd).patch(prPath(args[0]), body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "Name")
	f.StringVar(&scopes, "scopes", "", "Default scopes, comma-separated")
	f.IntVar(&idle, "idle-ttl-seconds", 0, "Refresh token idle lifetime")
	f.IntVar(&max, "max-ttl-seconds", 0, "Authorization lifetime")
	f.BoolVar(&active, "active", true, "Active (false ends every authorization)")
	f.BoolVar(&metadata, "allow-client-metadata", false, "Allow clients named by a metadata document")
	f.StringVar(&admission, "client-admission", "", "allowlist or open (open admits any such client without review)")
	return cmd
}

func prDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete ID",
		Short: "Delete a protected resource (ends its authorizations and forgets its external clients)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(prPath(args[0])); err != nil {
				return err
			}
			newPrinter().ok("Protected resource deleted: " + args[0])
			return nil
		},
	}
}

func prImpactCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "impact ID",
		Short: "Show what deactivating or deleting the resource would end",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(prPath(args[0]) + "/impact")
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func prClientsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clients",
		Short: "Review the clients named by metadata documents (pending, approved, blocked)",
	}
	cmd.AddCommand(prClientsListCmd(), prClientsGetCmd(), prClientsImpactCmd(), prClientsRequestsCmd(), prClientsApproveCmd(),
		prClientsDecisionCmd("block", "Block a client and end its sessions and grants"),
		prClientsDecisionCmd("unblock", "Return a blocked client to pending"),
		prClientsForgetCmd(), prClientsFromTemplateCmd())
	return cmd
}

func prClientsListCmd() *cobra.Command {
	var admission string
	var limit, offset int
	cmd := &cobra.Command{
		Use:     "list RESOURCE_ID",
		Short:   "List a protected resource's external clients",
		Example: `  iam protected-resources clients list RESOURCE_ID --admission pending`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			if admission != "" {
				params.Set("admission", admission)
			}
			if limit > 0 {
				params.Set("limit", strconv.Itoa(limit))
			}
			if offset > 0 {
				params.Set("offset", strconv.Itoa(offset))
			}
			path := prPath(args[0]) + "/clients"
			if len(params) > 0 {
				path += "?" + params.Encode()
			}
			data, err := mustClient(cmd).get(path)
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "HOST", "NAME", "VERIFIED AS", "ADMISSION", "SOURCE", "REQUESTS", "LAST USED"}, func(m map[string]any) []string {
				return []string{str(m, "id"), str(m, "host"), str(m, "client_name"), str(m, "preset_name"), str(m, "admission"), str(m, "admission_source"), str(m, "access_requests"), str(m, "last_used_at")}
			})
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&admission, "admission", "", "pending, approved or blocked")
	f.IntVar(&limit, "limit", 0, "Max results")
	f.IntVar(&offset, "offset", 0, "Offset")
	return cmd
}

func prClientsGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get RESOURCE_ID CLIENT",
		Short: "Show an external client",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(prClientPath(args[0], args[1]))
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func prClientsImpactCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "impact RESOURCE_ID CLIENT",
		Short: "Count the live sessions (and people) blocking or forgetting a client would end",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(prClientPath(args[0], args[1]) + "/impact")
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func prClientsRequestsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "requests RESOURCE_ID CLIENT",
		Short: "Show who asked to use an external client",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(prClientPath(args[0], args[1]) + "/requests")
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"USER", "EMAIL", "NAME", "REQUESTED"}, func(m map[string]any) []string {
				return []string{str(m, "user_id"), str(m, "email"), str(m, "name"), str(m, "requested_at")}
			})
			return nil
		},
	}
}

func prClientsApproveCmd() *cobra.Command {
	var expires, hash string
	cmd := &cobra.Command{
		Use:   "approve RESOURCE_ID CLIENT",
		Short: "Approve a client, optionally until a date",
		Long: `Approves a client for the document IAMKit holds: its redirect URIs, jwks_uri
and authentication method. The approval names the document's metadata_hash;
if the document changed since, the server answers 409 CLIENT_METADATA_CHANGED
and nothing is approved. Pass the metadata_hash that "clients get" showed you
with --metadata-hash to approve exactly what you reviewed; without it the
command reads the client now, prints what it is approving to stderr and
approves that.`,
		Example: `  iam protected-resources clients get RESOURCE_ID CLIENT
  iam protected-resources clients approve RESOURCE_ID CLIENT --metadata-hash 3f1e…
  iam protected-resources clients approve RESOURCE_ID CLIENT --expires 2027-01-31`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if hash == "" {
				current, err := mustClient(cmd).get(prClientPath(args[0], args[1]))
				if err != nil {
					return err
				}
				var view map[string]any
				if err = json.Unmarshal(current, &view); err != nil {
					return err
				}
				hash = str(view, "metadata_hash")
				fmt.Fprintf(os.Stderr, "Approving %s (%s)\n  redirect_uris: %v\n  token_endpoint_auth_method: %s  jwks_uri: %s\n  metadata_hash: %s\n", str(view, "client_id"), str(view, "host"), view["redirect_uris"], str(view, "token_endpoint_auth_method"), str(view, "jwks_uri"), hash)
			}
			body := map[string]any{"metadata_hash": hash}
			if expires != "" {
				at, err := parseExpiry(expires)
				if err != nil {
					return err
				}
				body["expires_at"] = at
			}
			data, err := mustClient(cmd).post(prClientPath(args[0], args[1])+"/approve", body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&expires, "expires", "", "Approval ends at this date (YYYY-MM-DD) or time (RFC 3339)")
	cmd.Flags().StringVar(&hash, "metadata-hash", "", "The metadata_hash you reviewed (default: the client's current one, printed to stderr)")
	return cmd
}

// parseExpiry reads a date (end of that day, UTC) or an RFC 3339 time.
func parseExpiry(v string) (string, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t.Add(24*time.Hour - time.Second).UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("--expires must be YYYY-MM-DD or an RFC 3339 time")
}

func prClientsDecisionCmd(verb, short string) *cobra.Command {
	return &cobra.Command{
		Use:   verb + " RESOURCE_ID CLIENT",
		Short: short,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).post(prClientPath(args[0], args[1])+"/"+verb, map[string]any{})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

func prClientsForgetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "forget RESOURCE_ID CLIENT",
		Short: "Delete a client and its grants (it returns as pending when used again)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(prClientPath(args[0], args[1])); err != nil {
				return err
			}
			newPrinter().ok("Client forgotten: " + args[1])
			return nil
		},
	}
}

func prClientsFromTemplateCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "from-template RESOURCE_ID PRESET",
		Short:   "Create the fixed client of a template preset (cursor, antigravity, gemini_cli)",
		Example: `  iam protected-resources clients from-template RESOURCE_ID cursor`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).post(prPath(args[0])+"/client-templates", map[string]any{"preset": args[1]})
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
}

// ── environment-level: allowlist and presets ──

func clientAllowlistCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client-allowlist",
		Short: "Metadata documents admitted without review (origin + path prefix)",
	}
	cmd.AddCommand(allowlistListCmd(), allowlistAddCmd(), allowlistRemoveCmd())
	return cmd
}

func allowlistListCmd() *cobra.Command {
	var resource string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List allowlist entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := envPath() + "/oauth-client-allowlist"
			if resource != "" {
				path += "?" + url.Values{"protected_resource_id": {resource}}.Encode()
			}
			data, err := mustClient(cmd).get(path)
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"ID", "ORIGIN", "PATH PREFIX", "PRESET", "SERVER"}, func(m map[string]any) []string {
				scope := str(m, "protected_resource_id")
				if scope == "" {
					scope = "all"
				}
				return []string{str(m, "id"), str(m, "origin"), str(m, "path_prefix"), str(m, "preset"), scope}
			})
			return nil
		},
	}
	cmd.Flags().StringVar(&resource, "resource", "", "Only entries that apply to this protected resource")
	return cmd
}

func allowlistAddCmd() *cobra.Command {
	var origin, prefix, preset, resource string
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Admit documents without review: --origin and --path-prefix, or --preset",
		Example: `  iam client-allowlist add --origin https://tools.example.com --path-prefix /oauth/
  iam client-allowlist add --preset claude_code`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if (preset != "") == (origin != "" || prefix != "") {
				return fmt.Errorf("give --preset, or --origin with --path-prefix")
			}
			body := map[string]any{}
			if preset != "" {
				body["preset"] = preset
			} else {
				body["origin"] = origin
				body["path_prefix"] = prefix
			}
			if resource != "" {
				body["protected_resource_id"] = resource
			}
			data, err := mustClient(cmd).post(envPath()+"/oauth-client-allowlist", body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&origin, "origin", "", "https://host (no port or path)")
	f.StringVar(&prefix, "path-prefix", "", "Path prefix of the documents")
	f.StringVar(&preset, "preset", "", "A known client (see client-presets list)")
	f.StringVar(&resource, "resource", "", "Limit the entry to one protected resource (default: every server)")
	return cmd
}

func allowlistRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove ENTRY_ID",
		Short: "Remove an entry (clients it approved stay approved)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := mustClient(cmd).delete(envPath() + "/oauth-client-allowlist/" + url.PathEscape(args[0])); err != nil {
				return err
			}
			newPrinter().ok("Allowlist entry removed: " + args[0])
			return nil
		},
	}
}

func clientPresetsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client-presets",
		Short: "Known MCP clients (Claude, ChatGPT, Codex, Cursor, …) to enable in one step",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the preset catalog",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := mustClient(cmd).get(envPath() + "/oauth-client-presets")
			if err != nil {
				return err
			}
			newPrinter().table(data, []string{"KEY", "NAME", "MECHANISM", "NETWORK", "NOTES"}, func(m map[string]any) []string {
				network := str(m, "network")
				if network == "public" {
					network = "public (needs internet exposure)"
				}
				return []string{str(m, "key"), str(m, "name"), str(m, "mechanism"), network, strings.TrimSpace(str(m, "notes"))}
			})
			return nil
		},
	})
	var resource string
	apply := &cobra.Command{
		Use:   "apply PRESET",
		Short: "Enable a preset: an allowlist entry, or a client for a template (needs --resource)",
		Example: `  iam client-presets apply claude_code
  iam client-presets apply cursor --resource RESOURCE_ID`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]any{"preset": args[0]}
			if resource != "" {
				body["protected_resource_id"] = resource
			}
			data, err := mustClient(cmd).post(envPath()+"/oauth-client-presets", body)
			if err != nil {
				return err
			}
			newPrinter().detail(data)
			return nil
		},
	}
	apply.Flags().StringVar(&resource, "resource", "", "Protected resource (required by template presets)")
	cmd.AddCommand(apply)
	return cmd
}
