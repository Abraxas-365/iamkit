import { invalidArgument } from "./errors.js";
import { Transport, withQuery, type FetchLike } from "./http.js";

/**
 * A resource registered as an RFC 8707 protected resource (an MCP server):
 * clients ask for it with `resource=<uri>` and get tokens with `aud` = uri
 * and the resource's permissions as scopes.
 */
export interface ProtectedResource {
  id: string;
  environment_id: string;
  application_id: string;
  resource_id: string;
  /** The resource's audience, canonical (the tokens' `aud`). */
  uri: string;
  name: string;
  /** Granted when a client asks for no scope; publish them as `scopes_supported`. */
  default_scopes: string[];
  idle_ttl_seconds: number;
  max_ttl_seconds: number;
  active: boolean;
  /** Clients named by an https `client_id` URL (a Client ID Metadata Document) may ask for this server. */
  allow_client_metadata: boolean;
  /** How such clients are admitted the first time: reviewed unless allowlisted (`allowlist`) or any (`open`). */
  client_admission: ClientAdmissionMode;
  created_at: string;
}

export type ClientAdmissionMode = "allowlist" | "open";
export type Admission = "pending" | "approved" | "blocked";

/** What deactivating or deleting a protected resource would end. */
export interface ProtectedResourceImpact {
  active_sessions: number;
  /** Clients named by a metadata document the server knows; deleting it forgets them and their grants. */
  external_clients: number;
}

/**
 * A client named by a Client ID Metadata Document as a protected resource sees
 * it. `host` and `preset` are the only facts IAMKit vouches for; the name and
 * logo are the document's own words.
 */
export interface ExternalClient {
  /** The client's row id, used by approve, block and the like. */
  id: string;
  client_id: string;
  protected_resource_id: string;
  client_name: string;
  client_uri: string;
  logo_uri: string;
  host: string;
  redirect_uris: string[];
  token_endpoint_auth_method: string;
  jwks_uri: string;
  admission: Admission;
  admission_expires_at: string | null;
  /** Who approved it: manual, allowlist, preset or open ("" while not approved). */
  admission_source: string;
  /** The known client whose document this is ("" for any other). */
  preset: string;
  preset_name: string;
  access_requests: number;
  metadata_fetched_at: string | null;
  /** Digest of the redirect URIs, jwks_uri and auth method held now: approving must carry the one you reviewed. */
  metadata_hash: string;
  last_used_at: string | null;
  created_at: string;
}

export interface ExternalClientAccessRequest {
  user_id: string;
  email: string;
  name: string;
  requested_at: string;
}

/** An allowlist entry admits the documents whose URL has exactly `origin` and a path under `path_prefix`. */
export interface AllowlistEntry {
  id: string;
  environment_id: string;
  /** Null for an entry of the whole environment. */
  protected_resource_id: string | null;
  origin: string;
  path_prefix: string;
  preset: string;
  created_at: string;
}

export type AllowlistEntryCreate =
  | { preset: string; protected_resource_id?: string }
  | { origin: string; path_prefix: string; protected_resource_id?: string };

/** A known MCP client IT can enable in one click. */
export interface ClientPreset {
  key: string;
  name: string;
  /** `metadata_document` adds an allowlist entry; `template` creates a fixed client. */
  mechanism: "metadata_document" | "template";
  metadata_url?: string;
  redirect_uris?: string[];
  loopback_any_port?: boolean;
  /** `public`: the client connects from its vendor's cloud, so the server must be reachable from the internet. */
  network: "public" | "local";
  source_ranges?: string[];
  development_only: boolean;
  notes?: string;
  warnings: string[];
}

/** The fixed client a template preset made: give `client_id` to the MCP client. */
export interface TemplateClient {
  client_id: string;
  redirect_uris: string[];
  loopback_any_port: boolean;
  /** False when the preset had made the client already. */
  created: boolean;
}

export interface PresetResult {
  preset: string;
  name: string;
  mechanism: string;
  network: string;
  warnings: string[];
  allowlist_entry: AllowlistEntry | null;
  client: TemplateClient | null;
}

export interface ProtectedResourcePage<T> {
  items: T[];
  page: { total: number; limit: number; offset: number };
}

/** TTLs left out take the defaults (7 days idle, 30 days in all). */
export interface ProtectedResourceCreate {
  application_id: string;
  resource_id: string;
  name: string;
  default_scopes?: string[];
  idle_ttl_seconds?: number;
  max_ttl_seconds?: number;
}

/** Only the given fields change; `active: false` ends every authorization. */
export type ProtectedResourceUpdate = Partial<
  Pick<ProtectedResource, "name" | "default_scopes" | "idle_ttl_seconds" | "max_ttl_seconds" | "active" | "allow_client_metadata" | "client_admission">
>;

/** The environment's TTL ceilings for its protected resources. */
export interface ProtectedResourcePolicy {
  max_idle_ttl_seconds: number;
  max_lifetime_ttl_seconds: number;
}

export interface ProtectedResourceList {
  items: ProtectedResource[];
  page: { total: number; limit: number; offset: number };
}

export interface ProtectedResourcesClientOptions {
  baseUrl: string;
  /** An access token with iam:protected-resources:read / write; a function is called per request. */
  token: string | (() => string | undefined | Promise<string | undefined>);
  fetch?: FetchLike;
  timeoutMs?: number;
}

/**
 * Server-side helper for protected resources (`/api/v1`): register the
 * resources MCP clients authorize for, change their scopes and lifetimes,
 * and set the environment's ceilings. Failures throw IAMKitError.
 */
export class ProtectedResourcesClient {
  private readonly http: Transport;
  private readonly token: ProtectedResourcesClientOptions["token"];

  constructor(options: ProtectedResourcesClientOptions) {
    if (!options.token) {
      throw invalidArgument("token is required");
    }
    this.http = new Transport(options);
    this.token = options.token;
  }

  /** One page of protected resources (iam:protected-resources:read). */
  async list(environmentId: string, page: { limit?: number; offset?: number } = {}): Promise<ProtectedResourceList> {
    const number = (n: number | undefined) => (n === undefined ? undefined : String(n));
    const out = await this.call<ProtectedResourceList>("GET", withQuery(base(environmentId), { limit: number(page.limit), offset: number(page.offset) }));
    return { ...out, items: out.items ?? [] };
  }

  async get(environmentId: string, id: string): Promise<ProtectedResource> {
    return this.call("GET", `${base(environmentId)}/${segment(id)}`);
  }

  /** Registers a resource linked to the application; its audience must be canonical (iam:protected-resources:write). */
  async create(environmentId: string, input: ProtectedResourceCreate): Promise<ProtectedResource> {
    return this.call("POST", base(environmentId), input);
  }

  async update(environmentId: string, id: string, input: ProtectedResourceUpdate): Promise<ProtectedResource> {
    return this.call("PATCH", `${base(environmentId)}/${segment(id)}`, input);
  }

  /** Removes the registration and ends its authorizations; the resource stays. */
  async delete(environmentId: string, id: string): Promise<void> {
    await this.call("DELETE", `${base(environmentId)}/${segment(id)}`);
  }

  /** What deactivating or deleting the resource would end, to warn before either. */
  async impact(environmentId: string, id: string): Promise<ProtectedResourceImpact> {
    return this.call("GET", `${base(environmentId)}/${segment(id)}/impact`);
  }

  /** One page of the clients named by metadata documents; `admission` filters (default: all). */
  async clients(environmentId: string, id: string, options: { admission?: Admission } & PageOptions = {}): Promise<ProtectedResourcePage<ExternalClient>> {
    const path = withQuery(`${base(environmentId)}/${segment(id)}/clients`, { admission: options.admission, ...pageQuery(options) });
    return paged(await this.call<ProtectedResourcePage<ExternalClient>>("GET", path));
  }

  async client(environmentId: string, id: string, client: string): Promise<ExternalClient> {
    return this.call("GET", clientPath(environmentId, id, client));
  }

  /** Who asked for a client, newest first. */
  async clientRequests(environmentId: string, id: string, client: string, page: PageOptions = {}): Promise<ProtectedResourcePage<ExternalClientAccessRequest>> {
    const path = withQuery(`${clientPath(environmentId, id, client)}/requests`, pageQuery(page));
    return paged(await this.call<ProtectedResourcePage<ExternalClientAccessRequest>>("GET", path));
  }

  /**
   * Approves a pending, blocked or expired client, optionally until `expires_at` (RFC 3339).
   * `metadata_hash` is the one of the client you reviewed (`ExternalClient.metadata_hash`); if its
   * document changed since, the call fails with 409 `CLIENT_METADATA_CHANGED` and approves nothing.
   */
  async approveClient(environmentId: string, id: string, client: string, input: { metadata_hash: string; expires_at?: string }): Promise<ExternalClient> {
    return this.call("POST", `${clientPath(environmentId, id, client)}/approve`, input);
  }

  /** Blocks a client and ends its sessions and grants. */
  async blockClient(environmentId: string, id: string, client: string): Promise<ExternalClient> {
    return this.call("POST", `${clientPath(environmentId, id, client)}/block`, {});
  }

  /** Returns a blocked client to pending. */
  async unblockClient(environmentId: string, id: string, client: string): Promise<ExternalClient> {
    return this.call("POST", `${clientPath(environmentId, id, client)}/unblock`, {});
  }

  /** Deletes a client and its grants; it is discovered again, as pending, the next time someone uses it. */
  async forgetClient(environmentId: string, id: string, client: string): Promise<void> {
    await this.call("DELETE", clientPath(environmentId, id, client));
  }

  /** Creates (or returns, `client.created` false) the fixed client of a template preset (Cursor, Antigravity, Gemini CLI). */
  async createClientFromTemplate(environmentId: string, id: string, preset: string): Promise<PresetResult> {
    return this.call("POST", `${base(environmentId)}/${segment(id)}/client-templates`, { preset });
  }

  /** One page of the allowlist; `protectedResourceId` keeps the entries that apply to that server. */
  async allowlist(environmentId: string, options: { protectedResourceId?: string } & PageOptions = {}): Promise<ProtectedResourcePage<AllowlistEntry>> {
    const path = withQuery(allowlistPath(environmentId), { protected_resource_id: options.protectedResourceId, ...pageQuery(options) });
    return paged(await this.call<ProtectedResourcePage<AllowlistEntry>>("GET", path));
  }

  /** Admits documents without review (pending clients it matches are approved). */
  async createAllowlistEntry(environmentId: string, input: AllowlistEntryCreate): Promise<AllowlistEntry> {
    return this.call("POST", allowlistPath(environmentId), input);
  }

  /** Removes an entry; clients it approved stay approved. */
  async deleteAllowlistEntry(environmentId: string, entry: string): Promise<void> {
    await this.call("DELETE", `${allowlistPath(environmentId)}/${segment(entry)}`);
  }

  /** The catalog of known MCP clients (development presets need the `development_clients` feature). */
  async presets(environmentId: string): Promise<ClientPreset[]> {
    const out = await this.call<{ items: ClientPreset[] | null }>("GET", presetsPath(environmentId));
    return out.items ?? [];
  }

  /** Enables a preset: an allowlist entry (metadata document) or a client (template, needs `protected_resource_id`). */
  async applyPreset(environmentId: string, input: { preset: string; protected_resource_id?: string }): Promise<PresetResult> {
    return this.call("POST", presetsPath(environmentId), input);
  }

  async policy(environmentId: string): Promise<ProtectedResourcePolicy> {
    return this.call("GET", policyPath(environmentId));
  }

  /** Replaces the ceilings; resources above a lowered ceiling are trimmed to it. */
  async setPolicy(environmentId: string, policy: ProtectedResourcePolicy): Promise<ProtectedResourcePolicy> {
    return this.call("PUT", policyPath(environmentId), policy);
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const value = typeof this.token === "function" ? await this.token() : this.token;
    if (!value) {
      throw invalidArgument("token is required");
    }
    const headers: Record<string, string> = { Accept: "application/json", Authorization: `Bearer ${value}` };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    return this.http.send<T>(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  }
}

function segment(id: string): string {
  if (!id || id === "." || id === ".." || /[/\\?#]/.test(id)) {
    throw invalidArgument("invalid identifier");
  }
  return encodeURIComponent(id);
}

function base(environmentId: string): string {
  return `/api/v1/environments/${segment(environmentId)}/protected-resources`;
}

interface PageOptions {
  limit?: number;
  offset?: number;
}

function pageQuery(page: PageOptions): Record<string, string | undefined> {
  const number = (n: number | undefined) => (n === undefined ? undefined : String(n));
  return { limit: number(page.limit), offset: number(page.offset) };
}

function paged<T>(out: ProtectedResourcePage<T>): ProtectedResourcePage<T> {
  return { ...out, items: out.items ?? [] };
}

function clientPath(environmentId: string, id: string, client: string): string {
  return `${base(environmentId)}/${segment(id)}/clients/${segment(client)}`;
}

function allowlistPath(environmentId: string): string {
  return `/api/v1/environments/${segment(environmentId)}/oauth-client-allowlist`;
}

function presetsPath(environmentId: string): string {
  return `/api/v1/environments/${segment(environmentId)}/oauth-client-presets`;
}

function policyPath(environmentId: string): string {
  return `/api/v1/environments/${segment(environmentId)}/protected-resource-policy`;
}
