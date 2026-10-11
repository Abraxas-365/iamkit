import { invalidArgument } from "./errors.js";
import { Transport, withQuery, type FetchLike } from "./http.js";

/** A party of an audit log event: the actor or a target. */
export interface AuditLogParty {
  type: string;
  id: string;
  name?: string;
  metadata?: Record<string, string | number | boolean>;
}

/** An event as an application emits it. */
export interface AuditLogInput {
  organization_id: string;
  /** A registered action, e.g. `invoice.paid`. */
  action: string;
  /** RFC 3339. */
  occurred_at: string;
  /** Optional; when given it must be the action's current version. */
  version?: number;
  actor: AuditLogParty;
  targets: AuditLogParty[];
  context?: { location?: string; user_agent?: string };
  metadata?: Record<string, string | number | boolean>;
}

/** A stored event; `seq` orders the log and is the paging cursor. */
export interface AuditLogEvent {
  seq: number;
  id: string;
  environment_id: string;
  organization_id: string;
  action: string;
  version: number;
  occurred_at: string;
  actor: AuditLogParty;
  targets: AuditLogParty[];
  context: { location?: string; user_agent?: string };
  metadata: Record<string, unknown> | null;
  created_at: string;
}

/**
 * One page of events. With `after`, pass `next` as the next `after`;
 * without it, pass `next` as `before` (0 = no older events).
 */
export interface AuditLogPage {
  items: AuditLogEvent[];
  next: number;
}

export interface AuditLogReceipt {
  id: string;
  created_at: string;
}

/** Filters of the audit log; `after` reads oldest first, else newest first below `before`. */
export interface AuditLogFilter {
  /** Exact action names. */
  action?: string[];
  actorId?: string;
  actorType?: string;
  targetId?: string;
  targetType?: string;
  /** Environment-wide reads only; organization reads always use their own. */
  organizationId?: string;
  /** RFC 3339. */
  occurredAfter?: string;
  occurredBefore?: string;
  after?: number;
  before?: number;
  /** Page size of a list (at most 200); exports ignore it. */
  limit?: number;
}

export type AuditLogFormat = "ndjson" | "csv";

export interface AuditLogsClientOptions {
  baseUrl: string;
  /** An access token with the iam:audit-logs:* (or, for organization reads, iam:org:audit:read) permissions; a function is called per request. */
  token: string | (() => string | undefined | Promise<string | undefined>);
  fetch?: FetchLike;
  timeoutMs?: number;
}

/**
 * Server-side helper for the app audit log (`/api/v1`): emit events with an
 * idempotency key, read them with filters and a cursor, export them as a
 * stream. Organization administrators read their own organization's log
 * through the `…Organization…` methods. Failures throw IAMKitError.
 */
export class AuditLogsClient {
  private readonly http: Transport;
  private readonly token: AuditLogsClientOptions["token"];

  constructor(options: AuditLogsClientOptions) {
    if (!options.token) {
      throw invalidArgument("token is required");
    }
    this.http = new Transport(options);
    this.token = options.token;
  }

  /**
   * Emits one event (iam:audit-logs:write). With `idempotencyKey` (at most
   * 255 characters) a retry answers the first receipt; the same key with
   * another event is 409 `IDEMPOTENCY_KEY_REUSED`.
   */
  async createEvent(environmentId: string, event: AuditLogInput, options: { idempotencyKey?: string } = {}): Promise<AuditLogReceipt> {
    const headers = await this.headers({ "Content-Type": "application/json" });
    if (options.idempotencyKey) {
      headers["Idempotency-Key"] = options.idempotencyKey;
    }
    return this.http.send<AuditLogReceipt>(`${environment(environmentId)}/audit-logs/events`, { method: "POST", headers, body: JSON.stringify(event) });
  }

  /** Reads one page (iam:audit-logs:read). */
  async listEvents(environmentId: string, filter: AuditLogFilter = {}): Promise<AuditLogPage> {
    return this.page(`${environment(environmentId)}/audit-logs/events`, filter);
  }

  /** Reads one event by its public id. */
  async getEvent(environmentId: string, id: string): Promise<AuditLogEvent> {
    return this.http.send<AuditLogEvent>(`${environment(environmentId)}/audit-logs/events/${encodeURIComponent(id)}`, { method: "GET", headers: await this.headers() });
  }

  /**
   * Streams the matching events oldest first (iam:audit-logs:read) as NDJSON
   * (default; read it with decodeAuditLogEvents) or CSV.
   */
  async exportEvents(environmentId: string, filter: AuditLogFilter = {}, options: { format?: AuditLogFormat; signal?: AbortSignal } = {}): Promise<ReadableStream<Uint8Array>> {
    return this.http.stream(exportPath(`${environment(environmentId)}/audit-logs/events/export`, filter, options.format), { headers: await this.headers(), signal: options.signal });
  }

  /** Reads one page of an organization's own log (iam:org:audit:read). */
  async listOrganizationEvents(environmentId: string, organizationId: string, filter: AuditLogFilter = {}): Promise<AuditLogPage> {
    return this.page(`${admin(environmentId, organizationId)}/audit-logs`, { ...filter, organizationId: undefined });
  }

  /** Streams an organization's own events oldest first (iam:org:audit:read). */
  async exportOrganizationEvents(environmentId: string, organizationId: string, filter: AuditLogFilter = {}, options: { format?: AuditLogFormat; signal?: AbortSignal } = {}): Promise<ReadableStream<Uint8Array>> {
    return this.http.stream(exportPath(`${admin(environmentId, organizationId)}/audit-logs/export`, { ...filter, organizationId: undefined }, options.format), { headers: await this.headers(), signal: options.signal });
  }

  private async page(path: string, filter: AuditLogFilter): Promise<AuditLogPage> {
    const out = await this.http.send<AuditLogPage>(withQuery(path, query(filter)), { method: "GET", headers: await this.headers() });
    return { ...out, items: out.items ?? [] };
  }

  private async headers(extra: Record<string, string> = {}): Promise<Record<string, string>> {
    const value = typeof this.token === "function" ? await this.token() : this.token;
    if (!value) {
      throw invalidArgument("token is required");
    }
    return { Accept: "application/json", ...extra, Authorization: `Bearer ${value}` };
  }
}

/** Reads the events of an NDJSON export stream, one at a time. */
export async function* decodeAuditLogEvents(stream: ReadableStream<Uint8Array>): AsyncGenerator<AuditLogEvent> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let pending = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      pending += decoder.decode(value, { stream: !done });
      let newline = pending.indexOf("\n");
      while (newline >= 0) {
        const line = pending.slice(0, newline).trim();
        pending = pending.slice(newline + 1);
        if (line) {
          yield JSON.parse(line) as AuditLogEvent;
        }
        newline = pending.indexOf("\n");
      }
      if (done) {
        break;
      }
    }
    if (pending.trim()) {
      yield JSON.parse(pending) as AuditLogEvent;
    }
  } finally {
    reader.releaseLock();
  }
}

function environment(id: string): string {
  if (!id || /[/?#\\.%]/.test(id)) {
    throw invalidArgument("invalid environment id");
  }
  return `/api/v1/environments/${id}`;
}

function admin(environmentId: string, organizationId: string): string {
  if (!organizationId || /[/?#\\.%]/.test(organizationId)) {
    throw invalidArgument("invalid organization id");
  }
  return `${environment(environmentId)}/organizations/${organizationId}/admin`;
}

function query(filter: AuditLogFilter, extra: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  const number = (n: number | undefined) => (n === undefined ? undefined : String(n));
  return {
    action: filter.action?.join(","),
    actor_id: filter.actorId,
    actor_type: filter.actorType,
    target_id: filter.targetId,
    target_type: filter.targetType,
    organization_id: filter.organizationId,
    occurred_after: filter.occurredAfter,
    occurred_before: filter.occurredBefore,
    after: number(filter.after),
    before: filter.before ? String(filter.before) : undefined,
    limit: number(filter.limit),
    ...extra,
  };
}

function exportPath(path: string, filter: AuditLogFilter, format?: AuditLogFormat): string {
  return withQuery(path, query({ ...filter, limit: undefined }, { format }));
}
