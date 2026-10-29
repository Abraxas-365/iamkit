package iamclient

import (
	"context"
	"net/url"
	"time"
)

// How a protected resource admits clients named by a metadata document the
// first time it sees them (ProtectedResource.ClientAdmission).
const (
	ClientAdmissionAllowlist = "allowlist"
	ClientAdmissionOpen      = "open"
)

// Admission of an external client.
const (
	AdmissionPending  = "pending"
	AdmissionApproved = "approved"
	AdmissionBlocked  = "blocked"
)

// Presets: mechanism and network exposure.
const (
	PresetMetadataDocument = "metadata_document"
	PresetTemplate         = "template"
	PresetNetworkPublic    = "public"
	PresetNetworkLocal     = "local"
)

// ExternalClient is a client named by a Client ID Metadata Document (its
// client_id is an https URL) as a protected resource sees it. Host and
// Preset are the only facts IAMKit vouches for; the name and logo are the
// document's own words.
type ExternalClient struct {
	// ID is the client's row id, used by Approve, Block and the like.
	ID                 string     `json:"id"`
	ClientID           string     `json:"client_id"`
	ProtectedResource  string     `json:"protected_resource_id"`
	Name               string     `json:"client_name"`
	ClientURI          string     `json:"client_uri"`
	LogoURI            string     `json:"logo_uri"`
	Host               string     `json:"host"`
	RedirectURIs       []string   `json:"redirect_uris"`
	AuthMethod         string     `json:"token_endpoint_auth_method"`
	JWKSURI            string     `json:"jwks_uri"`
	Admission          string     `json:"admission"`
	AdmissionExpiresAt *time.Time `json:"admission_expires_at"`
	// AdmissionSource is who approved it: manual, allowlist, preset or
	// open ("" while not approved).
	AdmissionSource string `json:"admission_source"`
	// Preset names the known client whose document this is ("" for any
	// other).
	Preset            string     `json:"preset"`
	PresetName        string     `json:"preset_name"`
	AccessRequests    int        `json:"access_requests"`
	MetadataFetchedAt *time.Time `json:"metadata_fetched_at"`
	// MetadataHash digests the redirect URIs, jwks_uri and authentication
	// method the client holds now: ClientApproval.MetadataHash must carry
	// the one you reviewed.
	MetadataHash string     `json:"metadata_hash"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

// ExternalClientList is one page of external clients, newest first.
type ExternalClientList struct {
	Items []ExternalClient `json:"items"`
	Page  Paging           `json:"page"`
}

// ExternalClientAccessRequest is a user who tried to use a pending client.
type ExternalClientAccessRequest struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	RequestedAt time.Time `json:"requested_at"`
}

// ExternalClientAccessRequestList is one page of access requests.
type ExternalClientAccessRequestList struct {
	Items []ExternalClientAccessRequest `json:"items"`
	Page  Paging                        `json:"page"`
}

// ClientApproval approves an external client, optionally until ExpiresAt
// (an approval past its expiry returns to pending). MetadataHash is the
// ExternalClient.MetadataHash you reviewed; if the document changed since,
// the call fails with 409 CLIENT_METADATA_CHANGED and approves nothing.
type ClientApproval struct {
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	MetadataHash string     `json:"metadata_hash"`
}

// AllowlistEntry admits metadata documents without review: those whose
// URL has exactly Origin and a path under PathPrefix.
type AllowlistEntry struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id"`
	// ProtectedResourceID is empty for an entry of the whole environment.
	ProtectedResourceID *string   `json:"protected_resource_id"`
	Origin              string    `json:"origin"`
	PathPrefix          string    `json:"path_prefix"`
	Preset              string    `json:"preset"`
	CreatedAt           time.Time `json:"created_at"`
}

// AllowlistEntryList is one page of allowlist entries.
type AllowlistEntryList struct {
	Items []AllowlistEntry `json:"items"`
	Page  Paging           `json:"page"`
}

// AllowlistEntryCreate adds an entry: a Preset, or an Origin
// (https://host) with a PathPrefix. ProtectedResourceID narrows it to one
// server; nil applies it to every server of the environment.
type AllowlistEntryCreate struct {
	ProtectedResourceID *string `json:"protected_resource_id,omitempty"`
	Origin              string  `json:"origin,omitempty"`
	PathPrefix          string  `json:"path_prefix,omitempty"`
	Preset              string  `json:"preset,omitempty"`
}

// ClientPreset is a known MCP client IT can enable in one click.
type ClientPreset struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// Mechanism is PresetMetadataDocument (adds an allowlist entry) or
	// PresetTemplate (creates a fixed client).
	Mechanism       string   `json:"mechanism"`
	MetadataURL     string   `json:"metadata_url"`
	RedirectURIs    []string `json:"redirect_uris"`
	LoopbackAnyPort bool     `json:"loopback_any_port"`
	// Network is PresetNetworkPublic (the client connects from its
	// vendor's cloud: the server must be reachable from the internet) or
	// PresetNetworkLocal.
	Network         string   `json:"network"`
	SourceRanges    []string `json:"source_ranges"`
	DevelopmentOnly bool     `json:"development_only"`
	Notes           string   `json:"notes"`
	Warnings        []string `json:"warnings"`
}

// PresetApply names a preset to apply. A metadata-document preset adds an
// allowlist entry (to ProtectedResourceID, or the whole environment when
// nil); a template preset creates a client at ProtectedResourceID, which
// it requires.
type PresetApply struct {
	Preset              string  `json:"preset"`
	ProtectedResourceID *string `json:"protected_resource_id,omitempty"`
}

// TemplateClient is the registered public client a template preset made:
// give ClientID to the MCP client in its configuration.
type TemplateClient struct {
	ClientID        string   `json:"client_id"`
	RedirectURIs    []string `json:"redirect_uris"`
	LoopbackAnyPort bool     `json:"loopback_any_port"`
	// Created is false when the preset had made the client already.
	Created bool `json:"created"`
}

// PresetResult is what applying a preset did.
type PresetResult struct {
	Preset    string          `json:"preset"`
	Name      string          `json:"name"`
	Mechanism string          `json:"mechanism"`
	Network   string          `json:"network"`
	Warnings  []string        `json:"warnings"`
	Allowlist *AllowlistEntry `json:"allowlist_entry"`
	Client    *TemplateClient `json:"client"`
}

// ExternalClients reads one page of the clients of a protected resource;
// admission ("" for all) is pending, approved or blocked.
func (e Environment) ExternalClients(ctx context.Context, protectedResource, admission string, page Page) (ExternalClientList, error) {
	var out ExternalClientList
	if err := safeSegment(protectedResource); err != nil {
		return out, err
	}
	q := url.Values{}
	if admission != "" {
		q.Set("admission", admission)
	}
	if err := e.client.do(ctx, "GET", e.path("protected-resources/"+protectedResource+"/clients"), page.Query(q), nil, &out); err != nil {
		return ExternalClientList{}, err
	}
	if out.Items == nil {
		out.Items = []ExternalClient{}
	}
	return out, nil
}

// ExternalClient reads one client of a protected resource.
func (e Environment) ExternalClient(ctx context.Context, protectedResource, client string) (ExternalClient, error) {
	var out ExternalClient
	err := e.operation(ctx, "GET", []string{"protected-resources", protectedResource, "clients", client}, nil, &out)
	return out, err
}

// ExternalClientImpact is what blocking or forgetting one external client
// would end on its server.
type ExternalClientImpact struct {
	// ActiveSessions are the client's live sessions with the server.
	ActiveSessions int `json:"active_sessions"`
	// Users are the people those sessions belong to.
	Users int `json:"users"`
}

// ExternalClientImpact counts what blocking or forgetting the client would
// end, so a confirmation can say how many.
func (e Environment) ExternalClientImpact(ctx context.Context, protectedResource, client string) (ExternalClientImpact, error) {
	var out ExternalClientImpact
	err := e.operation(ctx, "GET", []string{"protected-resources", protectedResource, "clients", client, "impact"}, nil, &out)
	return out, err
}

// ExternalClientAccessRequests reads who asked for a client, newest first.
func (e Environment) ExternalClientAccessRequests(ctx context.Context, protectedResource, client string, page Page) (ExternalClientAccessRequestList, error) {
	var out ExternalClientAccessRequestList
	if err := safeSegment(protectedResource); err != nil {
		return out, err
	}
	if err := safeSegment(client); err != nil {
		return out, err
	}
	if err := e.client.do(ctx, "GET", e.path("protected-resources/"+protectedResource+"/clients/"+client+"/requests"), page.Query(nil), nil, &out); err != nil {
		return ExternalClientAccessRequestList{}, err
	}
	if out.Items == nil {
		out.Items = []ExternalClientAccessRequest{}
	}
	return out, nil
}

// ApproveExternalClient approves a pending, blocked or expired client,
// optionally until input.ExpiresAt, and returns it as it stands.
func (e Environment) ApproveExternalClient(ctx context.Context, protectedResource, client string, input ClientApproval) (ExternalClient, error) {
	var out ExternalClient
	err := e.operation(ctx, "POST", []string{"protected-resources", protectedResource, "clients", client, "approve"}, input, &out)
	return out, err
}

// BlockExternalClient blocks a client and ends its sessions and grants.
func (e Environment) BlockExternalClient(ctx context.Context, protectedResource, client string) (ExternalClient, error) {
	var out ExternalClient
	err := e.operation(ctx, "POST", []string{"protected-resources", protectedResource, "clients", client, "block"}, map[string]any{}, &out)
	return out, err
}

// UnblockExternalClient returns a blocked client to pending.
func (e Environment) UnblockExternalClient(ctx context.Context, protectedResource, client string) (ExternalClient, error) {
	var out ExternalClient
	err := e.operation(ctx, "POST", []string{"protected-resources", protectedResource, "clients", client, "unblock"}, map[string]any{}, &out)
	return out, err
}

// ForgetExternalClient deletes a client and its grants; it is discovered
// again, as pending, the next time someone uses it.
func (e Environment) ForgetExternalClient(ctx context.Context, protectedResource, client string) error {
	return e.operation(ctx, "DELETE", []string{"protected-resources", protectedResource, "clients", client}, nil, nil)
}

// CreateClientFromTemplate creates (or returns, Created false) the fixed
// client of a template preset (Cursor, Antigravity, Gemini CLI) at the
// protected resource.
func (e Environment) CreateClientFromTemplate(ctx context.Context, protectedResource, preset string) (PresetResult, error) {
	var out PresetResult
	err := e.operation(ctx, "POST", []string{"protected-resources", protectedResource, "client-templates"}, map[string]string{"preset": preset}, &out)
	return out, err
}

// OAuthClientAllowlist reads one page of the allowlist; protectedResource
// ("" for all) narrows it to the entries that apply to that server.
func (e Environment) OAuthClientAllowlist(ctx context.Context, protectedResource string, page Page) (AllowlistEntryList, error) {
	var out AllowlistEntryList
	q := url.Values{}
	if protectedResource != "" {
		q.Set("protected_resource_id", protectedResource)
	}
	if err := e.client.do(ctx, "GET", e.path("oauth-client-allowlist"), page.Query(q), nil, &out); err != nil {
		return AllowlistEntryList{}, err
	}
	if out.Items == nil {
		out.Items = []AllowlistEntry{}
	}
	return out, nil
}

// CreateOAuthClientAllowlistEntry admits the documents under an origin and
// path prefix (or a preset's document) without review; pending clients it
// matches are approved.
func (e Environment) CreateOAuthClientAllowlistEntry(ctx context.Context, input AllowlistEntryCreate) (AllowlistEntry, error) {
	var out AllowlistEntry
	err := e.operation(ctx, "POST", []string{"oauth-client-allowlist"}, input, &out)
	return out, err
}

// DeleteOAuthClientAllowlistEntry removes an entry; clients it approved
// stay approved.
func (e Environment) DeleteOAuthClientAllowlistEntry(ctx context.Context, entry string) error {
	return e.operation(ctx, "DELETE", []string{"oauth-client-allowlist", entry}, nil, nil)
}

// OAuthClientPresets lists the catalog of known MCP clients the
// environment is offered (development presets need the development_clients
// feature).
func (e Environment) OAuthClientPresets(ctx context.Context) ([]ClientPreset, error) {
	var out struct {
		Items []ClientPreset `json:"items"`
	}
	if err := e.operation(ctx, "GET", []string{"oauth-client-presets"}, nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []ClientPreset{}, nil
	}
	return out.Items, nil
}

// ApplyOAuthClientPreset enables a preset: an allowlist entry for a
// metadata-document preset, a client for a template one (which needs
// input.ProtectedResourceID).
func (e Environment) ApplyOAuthClientPreset(ctx context.Context, input PresetApply) (PresetResult, error) {
	var out PresetResult
	err := e.operation(ctx, "POST", []string{"oauth-client-presets"}, input, &out)
	return out, err
}
