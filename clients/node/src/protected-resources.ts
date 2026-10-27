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
  created_at: string;
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
export type ProtectedResourceUpdate = Partial<Pick<ProtectedResource, "name" | "default_scopes" | "idle_ttl_seconds" | "max_ttl_seconds" | "active">>;

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

function policyPath(environmentId: string): string {
  return `/api/v1/environments/${segment(environmentId)}/protected-resource-policy`;
}
