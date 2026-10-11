import { IAMKitError, invalidArgument, unauthorized } from "./errors.js";
import { Transport, withQuery, type FetchLike } from "./http.js";

/** Every API key value starts with this prefix. */
export const APIKeyPrefix = "ik_key_";

/** Whether value looks like an API key (not that it is valid). */
export function isAPIKey(value: string): boolean {
  return value.startsWith(APIKeyPrefix);
}

/** Whose key it is: a person (`user`), an organization or a machine user (`machine`). */
export interface APIKeyOwner {
  type: "user" | "organization" | "machine" | (string & {});
  /** The user; absent on organization keys. */
  id?: string;
  organization_id?: string;
}

/** An API key IAMKit confirmed on a request (see validateAPIKey). */
export interface APIKey {
  id: string;
  name: string;
  owner: APIKeyOwner;
  organization_id: string;
  resource_id: string;
  /** Effective permissions right now: never empty on a valid key. */
  permissions: string[];
  /** Unix seconds when the key stops working; 0 = never. */
  expires_at: number;
}

/** Whether the key carries every one of permissions (exact strings). */
export function hasAPIKeyPermission(key: APIKey, ...permissions: string[]): boolean {
  return permissions.length > 0 && permissions.every((p) => p !== "" && key.permissions.includes(p));
}

export interface APIKeyValidatorOptions {
  /** The deployment origin the SDK calls. */
  baseUrl: string;
  environmentId: string;
  /** The audience of the resource this service serves; only its keys validate. */
  audience: string;
  fetch?: FetchLike;
  timeoutMs?: number;
}

/** Validates API key values; pass it to `authenticate(…, { allowApiKeys })`. */
export interface APIKeyValidator {
  validate(value: string): Promise<APIKey>;
}

/**
 * Validates an API key online with `POST /identity/v1/introspect`, sending
 * the environment and audience: revocation, expiry, the policy and the
 * owner's standing take effect at once. Non-`ik_key_` values are refused
 * locally; an inactive key rejects with 401 `UNAUTHORIZED`; an unreachable
 * IAMKit rejects with its own error — fail closed.
 */
export function createAPIKeyValidator(options: APIKeyValidatorOptions): APIKeyValidator {
  if (!options.environmentId || !options.audience) {
    throw invalidArgument("environmentId and audience are required");
  }
  const http = new Transport(options);
  return {
    async validate(value: string): Promise<APIKey> {
      if (!isAPIKey(value)) {
        throw unauthorized("invalid API key");
      }
      let answer: { active?: boolean; claims?: IntrospectedKey };
      try {
        answer = await http.json("/identity/v1/introspect", { environment_id: options.environmentId, audience: options.audience }, value);
      } catch (error) {
        if (error instanceof IAMKitError && error.status === 401) {
          throw unauthorized("inactive API key");
        }
        throw error;
      }
      const claims = answer.claims;
      const key = claims?.api_key;
      if (!answer.active || !claims || !key || claims.purpose !== "api_key" || claims.environment_id !== options.environmentId || !claims.aud?.includes(options.audience) || !key.id || !key.permissions?.length) {
        throw unauthorized("invalid or inactive API key");
      }
      const expiresAt = key.expires_at ?? 0;
      if (expiresAt > 0 && expiresAt * 1000 <= Date.now()) {
        throw unauthorized("invalid or inactive API key");
      }
      const organization = key.owner?.organization_id || claims.organization_id || "";
      return {
        id: key.id,
        name: key.name ?? "",
        owner: { type: key.owner?.type ?? "", ...(key.owner?.id ? { id: key.owner.id } : {}), organization_id: organization },
        organization_id: organization,
        resource_id: key.resource_id || claims.resource_id || "",
        permissions: key.permissions,
        expires_at: expiresAt,
      };
    },
  };
}

/** One-shot form of createAPIKeyValidator(options).validate(value). */
export function validateAPIKey(value: string, options: APIKeyValidatorOptions): Promise<APIKey> {
  return createAPIKeyValidator(options).validate(value);
}

interface IntrospectedKey {
  purpose?: string;
  environment_id?: string;
  organization_id?: string;
  resource_id?: string;
  aud?: string[];
  api_key?: { id?: string; name?: string; owner?: APIKeyOwner; resource_id?: string; permissions?: string[]; expires_at?: number };
}

// ── Management of keys ──

export type APIKeyState = "active" | "revoked" | "expired";

/** An API key without its value. */
export interface APIKeyRecord {
  id: string;
  environment_id: string;
  owner: { type: string; user_id?: string };
  organization_id: string;
  /** Machine keys only. */
  application_id?: string;
  resource_id: string;
  name: string;
  /** Null on a machine key = everything its machine user holds. */
  permissions: string[] | null;
  /** `ik_key_…` plus the last four characters. */
  obfuscated_value: string;
  expires_at: string;
  /** False for a key that never expires. */
  expires: boolean;
  last_used_at: string | null;
  revoked_at: string | null;
  created_by: { kind: string; id?: string };
  created_at: string;
  state: APIKeyState;
  user_name?: string;
  organization_name?: string;
  application_name?: string;
  resource_name?: string;
}

/** A new key; `value` (`ik_key_…`) is returned only here. */
export interface IssuedAPIKey extends APIKeyRecord {
  value: string;
}

/**
 * Body of an organization key (operator and organization admins) or of a
 * machine key (`applicationId` required, `permissions` optional). `expiresIn`
 * is a Go duration from `1h` to `8760h` or `"never"`; omitted = never.
 */
export interface NewAPIKey {
  organizationId?: string;
  applicationId?: string;
  resourceId: string;
  name: string;
  permissions?: string[];
  expiresIn?: string;
}

/** Filters of a key list; empty values do not filter. */
export interface APIKeyFilter {
  ownerType?: "user" | "organization" | "machine";
  organizationId?: string;
  userId?: string;
  resourceId?: string;
  state?: APIKeyState;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface APIKeyList {
  items: APIKeyRecord[];
  page: { total: number; limit: number; offset: number };
}

/** The environment's API key policy. */
export interface APIKeyPolicy {
  user_keys: boolean;
  organization_keys: boolean;
  /** 1–365, or null for no cap. */
  max_ttl_days: number | null;
  /** 1–100. */
  max_per_user: number;
  /** 1–500. */
  max_per_organization: number;
  updated_at?: string;
}

/** What a resource lets API keys of each owner type carry. */
export interface APIKeyPermissions {
  user: string[];
  organization: string[];
}

/** What the caller can create. */
export interface APIKeyOptions {
  enabled: boolean;
  max_ttl_days: number | null;
  resources: { id: string; name: string; audience: string; permissions: string[] }[];
}

export interface APIKeysClientOptions {
  baseUrl: string;
  /** An access token with the iam:api-keys:* / iam:users:* (operator) or iam:org:api-keys:* (organization admin) permissions; a function is called per request. */
  token: string | (() => string | undefined | Promise<string | undefined>);
  fetch?: FetchLike;
  timeoutMs?: number;
}

/**
 * Server-side helper for API key administration on `/api/v1`: the operator
 * view of the environment, machine user keys, the policy and resource
 * allowlists, and the organization administrator view
 * (`…Organization…`). Failures throw IAMKitError. Users manage their own
 * keys with IdentityClient.
 */
export class APIKeysClient {
  private readonly http: Transport;
  private readonly token: APIKeysClientOptions["token"];

  constructor(options: APIKeysClientOptions) {
    if (!options.token) {
      throw invalidArgument("token is required");
    }
    this.http = new Transport(options);
    this.token = options.token;
  }

  /** One page of the environment's keys of every owner type (iam:api-keys:read). */
  async list(environmentId: string, filter: APIKeyFilter = {}): Promise<APIKeyList> {
    return this.page(`${env(environmentId)}/api-keys`, filter);
  }

  /** One key (iam:api-keys:read). */
  async get(environmentId: string, id: string): Promise<APIKeyRecord> {
    return this.call("GET", `${env(environmentId)}/api-keys/${segment(id)}`);
  }

  /** Issues an organization key; the value is returned once (iam:api-keys:write). */
  async create(environmentId: string, key: NewAPIKey): Promise<IssuedAPIKey> {
    return this.call("POST", `${env(environmentId)}/api-keys`, newKey(key));
  }

  /** Revokes any key; idempotent (iam:api-keys:write). */
  async revoke(environmentId: string, id: string): Promise<void> {
    await this.call("DELETE", `${env(environmentId)}/api-keys/${segment(id)}`);
  }

  /** The environment's policy (iam:api-keys:read). */
  async policy(environmentId: string): Promise<APIKeyPolicy> {
    return this.call("GET", `${env(environmentId)}/api-key-policy`);
  }

  /** Replaces the policy (iam:api-keys:write); `max_ttl_days: null` removes the cap. */
  async savePolicy(environmentId: string, policy: Omit<APIKeyPolicy, "updated_at">): Promise<APIKeyPolicy> {
    return this.call("PUT", `${env(environmentId)}/api-key-policy`, policy);
  }

  /** Replaces a resource's allowlist (iam:resources:write); the IAM resource keeps both empty. */
  async setResourceAPIKeyPermissions(environmentId: string, resourceId: string, permissions: Partial<APIKeyPermissions>): Promise<void> {
    await this.call("PUT", `${env(environmentId)}/resources/${segment(resourceId)}/api-key-permissions`, { user: permissions.user ?? [], organization: permissions.organization ?? [] });
  }

  /** Every key of a user (iam:users:read). */
  async userKeys(environmentId: string, userId: string): Promise<APIKeyRecord[]> {
    return (await this.page(`${env(environmentId)}/users/${segment(userId)}/api-keys`, {})).items;
  }

  /** Issues a machine user's key (iam:users:write); needs `applicationId`. */
  async createMachineKey(environmentId: string, userId: string, key: NewAPIKey): Promise<IssuedAPIKey> {
    return this.call("POST", `${env(environmentId)}/users/${segment(userId)}/api-keys`, newKey(key));
  }

  /** Revokes a user's key (iam:users:write). */
  async revokeUserKey(environmentId: string, userId: string, id: string): Promise<void> {
    await this.call("DELETE", `${env(environmentId)}/users/${segment(userId)}/api-keys/${segment(id)}`);
  }

  /** The organization's keys and its members' user keys, never machine keys (iam:org:api-keys:read). */
  async listOrganization(environmentId: string, organizationId: string, filter: APIKeyFilter = {}): Promise<APIKeyList> {
    return this.page(`${admin(environmentId, organizationId)}/api-keys`, { ...filter, organizationId: undefined });
  }

  /** What the calling admin can give an organization key (iam:org:api-keys:write). */
  async organizationOptions(environmentId: string, organizationId: string): Promise<APIKeyOptions> {
    return this.call("GET", `${admin(environmentId, organizationId)}/api-keys/options`);
  }

  /** One key of the organization (iam:org:api-keys:read). */
  async getOrganizationKey(environmentId: string, organizationId: string, id: string): Promise<APIKeyRecord> {
    return this.call("GET", `${admin(environmentId, organizationId)}/api-keys/${segment(id)}`);
  }

  /** Issues an organization key for the administered organization (iam:org:api-keys:write; needs a signed-in admin). */
  async createOrganizationKey(environmentId: string, organizationId: string, key: NewAPIKey): Promise<IssuedAPIKey> {
    return this.call("POST", `${admin(environmentId, organizationId)}/api-keys`, newKey({ ...key, organizationId }));
  }

  /** Revokes a key of the organization or of one of its members (iam:org:api-keys:write). */
  async revokeOrganizationKey(environmentId: string, organizationId: string, id: string): Promise<void> {
    await this.call("DELETE", `${admin(environmentId, organizationId)}/api-keys/${segment(id)}`);
  }

  private async page(path: string, filter: APIKeyFilter): Promise<APIKeyList> {
    const out = await this.call<APIKeyList>("GET", withQuery(path, keyQuery(filter)));
    return { ...out, items: out.items ?? [] };
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

/** The JSON body of a key creation (snake_case, undefined fields dropped). */
export function newKey(key: NewAPIKey): Record<string, unknown> {
  const body: Record<string, unknown> = {
    organization_id: key.organizationId,
    application_id: key.applicationId,
    resource_id: key.resourceId,
    name: key.name,
    permissions: key.permissions,
    expires_in: key.expiresIn,
  };
  for (const name of Object.keys(body)) {
    if (body[name] === undefined || body[name] === "") {
      delete body[name];
    }
  }
  return body;
}

/** The query string fields of a key filter. */
export function keyQuery(filter: APIKeyFilter): Record<string, string | undefined> {
  return {
    owner_type: filter.ownerType,
    organization_id: filter.organizationId,
    user_id: filter.userId,
    resource_id: filter.resourceId,
    state: filter.state,
    search: filter.search,
    limit: filter.limit ? String(filter.limit) : undefined,
    offset: filter.offset ? String(filter.offset) : undefined,
  };
}

function segment(id: string): string {
  if (!id || id === "." || id === ".." || /[/\\?#]/.test(id)) {
    throw invalidArgument("invalid identifier");
  }
  return encodeURIComponent(id);
}

function env(environmentId: string): string {
  return `/api/v1/environments/${segment(environmentId)}`;
}

function admin(environmentId: string, organizationId: string): string {
  return `${env(environmentId)}/organizations/${segment(organizationId)}/admin`;
}

/**
 * A user's own API keys on `/identity/v1/me/api-keys` (see IdentityClient.me).
 * Creating needs a fresh sign-in; the keys can only validate — they never
 * call `/api/v1`.
 */
export class MeAPIKeys {
  constructor(
    private readonly http: Transport,
    private readonly accessToken: string,
    private readonly environmentId: string,
    private readonly audience: string,
  ) {
    if (!accessToken) {
      throw invalidArgument("accessToken is required");
    }
  }

  /** One page of the user's keys (`filter.limit`, `filter.offset`). */
  async list(filter: Pick<APIKeyFilter, "limit" | "offset"> = {}): Promise<APIKeyList> {
    const out = await this.http.get<APIKeyList>(withQuery("/identity/v1/me/api-keys", { ...this.scope(), ...keyQuery(filter) }), this.accessToken);
    return { ...out, items: out.items ?? [] };
  }

  /** What the user may create: enabled, the TTL cap and the resources with allowed permissions. */
  async options(): Promise<APIKeyOptions> {
    return this.http.get(withQuery("/identity/v1/me/api-keys/options", this.scope()), this.accessToken);
  }

  /** Issues a key for the user; the value is returned once. `organizationId` and `applicationId` do not apply. */
  async create(key: Pick<NewAPIKey, "resourceId" | "name" | "permissions" | "expiresIn">): Promise<IssuedAPIKey> {
    return this.http.json(withQuery("/identity/v1/me/api-keys", this.scope()), newKey(key), this.accessToken);
  }

  /** Revokes one of the user's keys; idempotent. */
  async revoke(id: string): Promise<void> {
    await this.http.send(withQuery(`/identity/v1/me/api-keys/${segment(id)}`, this.scope()), { method: "DELETE", headers: { Accept: "application/json", Authorization: `Bearer ${this.accessToken}` } });
  }

  private scope(): Record<string, string> {
    return { environment_id: this.environmentId, audience: this.audience };
  }
}
