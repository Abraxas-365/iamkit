import { invalidArgument } from "./errors.js";
import { Transport, type FetchLike } from "./http.js";

/**
 * How people read one permission of a resource: a short name and a
 * sentence, in one language. `locale` is "" for the default text, otherwise
 * an available language code (`es`, `pt-BR`). Names are at most 80
 * characters and sentences 300, plain text on one line. The permission must
 * be in the resource's catalog; removing it from the catalog deletes its
 * descriptions.
 */
export interface PermissionDescription {
  permission: string;
  locale?: string;
  display_name?: string;
  description?: string;
}

export interface PermissionDescriptionsClientOptions {
  baseUrl: string;
  /** An access token with iam:resources:read (get) / iam:resources:write (set); a function is called per request. */
  token: string | (() => string | undefined | Promise<string | undefined>);
  fetch?: FetchLike;
  timeoutMs?: number;
}

/**
 * Server-side helper for a resource's permission descriptions (`/api/v1`).
 * The hosted consent page, the consent ticket and connected apps word a
 * server's scopes with them (falling back to the permission's name).
 * Failures throw IAMKitError.
 */
export class PermissionDescriptionsClient {
  private readonly http: Transport;
  private readonly token: PermissionDescriptionsClientOptions["token"];

  constructor(options: PermissionDescriptionsClientOptions) {
    if (!options.token) {
      throw invalidArgument("token is required");
    }
    this.http = new Transport(options);
    this.token = options.token;
  }

  /** The stored descriptions, every language (iam:resources:read). */
  async get(environmentId: string, resourceId: string): Promise<PermissionDescription[]> {
    const out = await this.call<{ items: PermissionDescription[] | null }>("GET", environmentId, resourceId);
    return out.items ?? [];
  }

  /** Replaces the whole set; `[]` clears it (iam:resources:write). */
  async set(environmentId: string, resourceId: string, descriptions: PermissionDescription[]): Promise<void> {
    await this.call("PUT", environmentId, resourceId, {
      items: descriptions.map((d) => ({ permission: d.permission, locale: d.locale ?? "", display_name: d.display_name ?? "", description: d.description ?? "" })),
    });
  }

  private async call<T>(method: string, environmentId: string, resourceId: string, body?: unknown): Promise<T> {
    const value = typeof this.token === "function" ? await this.token() : this.token;
    if (!value) {
      throw invalidArgument("token is required");
    }
    const headers: Record<string, string> = { Accept: "application/json", Authorization: `Bearer ${value}` };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    return this.http.send<T>(`/api/v1/environments/${segment(environmentId)}/resources/${segment(resourceId)}/permission-descriptions`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }
}

function segment(id: string): string {
  if (!id || id === "." || id === ".." || /[/\\?#]/.test(id)) {
    throw invalidArgument("invalid identifier");
  }
  return encodeURIComponent(id);
}
