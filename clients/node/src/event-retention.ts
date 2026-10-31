import { invalidArgument } from "./errors.js";
import { Transport, type FetchLike } from "./http.js";

/** Seconds per retention class. */
export interface RetentionSeconds {
  security: number;
  default: number;
}

/**
 * How long an environment keeps its events. The deployment sets a ceiling per
 * class (`IAMKIT_SECURITY_EVENT_RETENTION`, `IAMKIT_EVENT_RETENTION`); the
 * environment's own values can only shorten them. `security_retention_seconds`
 * and `default_retention_seconds` are the environment's own values (`null`:
 * the ceiling); `effective` is what events are pruned by.
 */
export interface EventRetention {
  security_retention_seconds: number | null;
  default_retention_seconds: number | null;
  ceilings: RetentionSeconds;
  effective: RetentionSeconds;
}

/** Replaces the environment's values: `null` (or absent) keeps the ceiling; at least 86400 and at most the ceiling, otherwise 422 `RETENTION_OUT_OF_RANGE`. */
export interface EventRetentionInput {
  security_retention_seconds?: number | null;
  default_retention_seconds?: number | null;
}

export interface EventRetentionClientOptions {
  baseUrl: string;
  /** An access token with iam:events:read; a function is called per request. */
  token: string | (() => string | undefined | Promise<string | undefined>);
  fetch?: FetchLike;
  timeoutMs?: number;
}

export interface EventRetentionManagementOptions {
  baseUrl: string;
  /** A management key (`ik_mgmt_…`); keep it server-side. */
  key: string;
  fetch?: FetchLike;
  timeoutMs?: number;
}

/**
 * Reads an environment's event retention with an access token
 * (`/api/v1`, iam:events:read). Changing it deletes events, so it is a
 * workspace owner's call: use {@link EventRetentionManagement}.
 */
export class EventRetentionClient {
  private readonly http: Transport;
  private readonly token: EventRetentionClientOptions["token"];

  constructor(options: EventRetentionClientOptions) {
    if (!options.token) {
      throw invalidArgument("token is required");
    }
    this.http = new Transport(options);
    this.token = options.token;
  }

  /** The effective retention, the ceilings and the environment's own values. */
  async get(environmentId: string): Promise<EventRetention> {
    const value = typeof this.token === "function" ? await this.token() : this.token;
    if (!value) {
      throw invalidArgument("token is required");
    }
    return this.http.send<EventRetention>(`/api/v1/environments/${segment(environmentId)}/event-retention`, {
      method: "GET",
      headers: { Accept: "application/json", Authorization: `Bearer ${value}` },
    });
  }
}

/**
 * Reads and replaces an environment's event retention with a management key
 * (`/management/v1`); only workspace owners may replace it (403 otherwise).
 * Audited as `event_retention.updated`.
 */
export class EventRetentionManagement {
  private readonly http: Transport;
  private readonly key: string;

  constructor(options: EventRetentionManagementOptions) {
    if (!options.key) {
      throw invalidArgument("key is required");
    }
    this.http = new Transport(options);
    this.key = options.key;
  }

  async get(environmentId: string): Promise<EventRetention> {
    return this.call("GET", environmentId);
  }

  /** Replaces both values: the ones left out go back to the ceiling. */
  async set(environmentId: string, input: EventRetentionInput): Promise<EventRetention> {
    return this.call("PUT", environmentId, {
      security_retention_seconds: input.security_retention_seconds ?? null,
      default_retention_seconds: input.default_retention_seconds ?? null,
    });
  }

  private async call(method: string, environmentId: string, body?: unknown): Promise<EventRetention> {
    const headers: Record<string, string> = { Accept: "application/json", "X-API-Key": this.key };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    return this.http.send<EventRetention>(`/management/v1/environments/${segment(environmentId)}/event-retention`, {
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
