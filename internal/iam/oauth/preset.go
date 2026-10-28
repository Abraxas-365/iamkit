package oauth

import "slices"

// Client presets for MCP clients (D19, D20, D21): known clients IT enables
// in one click. A metadata-document preset adds the client's document URL
// to the allowlist; a template preset creates a fixed (registered) public
// client with the client's known redirect URIs.

// Preset mechanisms.
const (
	PresetMetadataDocument = "metadata_document"
	PresetTemplate         = "template"
)

// Network exposure a preset needs (D20).
const (
	// NetworkPublic: the client runs in its vendor's cloud, so the MCP
	// server and IAMKit must be reachable from the internet.
	NetworkPublic = "public"
	// NetworkLocal: the client runs on the user's machine, so a server
	// on-premises behind a VPN works.
	NetworkLocal = "local"
)

// Preset is one known MCP client.
type Preset struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Mechanism string `json:"mechanism"`
	// MetadataURL is the client's metadata document (metadata_document).
	MetadataURL string `json:"metadata_url,omitempty"`
	// Redirects are the template client's redirect URIs (template).
	Redirects []string `json:"redirect_uris,omitempty"`
	// LoopbackAnyPort: the template client listens on a random local port.
	LoopbackAnyPort bool `json:"loopback_any_port,omitempty"`
	// Network is public or local (D20).
	Network string `json:"network"`
	// SourceRanges are the addresses a public client connects from, when
	// its vendor publishes them.
	SourceRanges []string `json:"source_ranges,omitempty"`
	// DevelopmentOnly presets are offered with the development_clients
	// feature only (D21).
	DevelopmentOnly bool `json:"development_only"`
	// Notes are setup hints shown next to the preset.
	Notes string `json:"notes,omitempty"`
}

// claudeRanges is where Claude (web and desktop) connects from.
var claudeRanges = []string{"160.79.104.0/21"}

// presets is the catalog, in display order. Document URLs were checked
// against the live documents (plan §14.1).
var presets = []Preset{
	{Key: "claude_code", Name: "Claude Code", Mechanism: PresetMetadataDocument, MetadataURL: "https://claude.ai/oauth/claude-code-client-metadata", Network: NetworkLocal},
	{Key: "claude", Name: "Claude (web and desktop)", Mechanism: PresetMetadataDocument, MetadataURL: "https://claude.ai/oauth/mcp-oauth-client-metadata", Network: NetworkPublic, SourceRanges: claudeRanges},
	{Key: "chatgpt", Name: "ChatGPT", Mechanism: PresetMetadataDocument, MetadataURL: "https://chatgpt.com/oauth/client.json", Network: NetworkPublic, Notes: "Signs its token requests with private_key_jwt (keys at https://chatgpt.com/oauth/jwks.json)."},
	{Key: "codex", Name: "Codex", Mechanism: PresetMetadataDocument, MetadataURL: "https://chatgpt.com/oauth/codex/client.json", Network: NetworkLocal},
	{Key: "vscode", Name: "Visual Studio Code", Mechanism: PresetMetadataDocument, MetadataURL: "https://vscode.dev/oauth/client-metadata.json", Network: NetworkLocal},
	{Key: "cursor", Name: "Cursor", Mechanism: PresetTemplate, Redirects: []string{"http://localhost:8787/callback"}, Network: NetworkLocal, Notes: "Give Cursor the client_id in its MCP configuration (auth.CLIENT_ID)."},
	{Key: "antigravity", Name: "Antigravity", Mechanism: PresetTemplate, Redirects: []string{"https://antigravity.google/oauth-callback"}, Network: NetworkLocal},
	{Key: "gemini_cli", Name: "Gemini CLI", Mechanism: PresetTemplate, Redirects: []string{"http://localhost/oauth/callback"}, LoopbackAnyPort: true, Network: NetworkLocal, Notes: "Give Gemini CLI the client_id in its MCP server settings (oauth.clientId)."},
	{Key: "mcp_inspector", Name: "MCP Inspector", Mechanism: PresetTemplate, Redirects: []string{"http://localhost:6274/oauth/callback", "http://localhost:6274/oauth/callback/debug"}, Network: NetworkLocal, DevelopmentOnly: true},
}

// Presets lists the catalog; development presets only when development.
func Presets(development bool) []Preset {
	out := make([]Preset, 0, len(presets))
	for _, p := range presets {
		if p.DevelopmentOnly && !development {
			continue
		}
		p.Redirects = slices.Clone(p.Redirects)
		p.SourceRanges = slices.Clone(p.SourceRanges)
		out = append(out, p)
	}
	return out
}

// FindPreset returns the preset called key.
func FindPreset(key string) (Preset, bool) {
	for _, p := range presets {
		if p.Key == key {
			p.Redirects = slices.Clone(p.Redirects)
			p.SourceRanges = slices.Clone(p.SourceRanges)
			return p, true
		}
	}
	return Preset{}, false
}
