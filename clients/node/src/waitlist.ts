import { invalidArgument } from "./errors.js";
import { Transport, withQuery, type FetchLike } from "./http.js";

export type WaitlistStatus = "pending" | "approved" | "rejected" | "completed";

/** A person waiting to sign up. */
export interface WaitlistEntry {
  id: string;
  environment_id: string;
  email: string;
  name: string;
  locale: string;
  status: WaitlistStatus;
  created_at: string;
  decided_at: string | null;
  decided_by: string;
  /** When the approval link stops working. */
  expires_at: string | null;
  /** The account created from the approval. */
  completed_user_id: string;
}

export interface WaitlistFilter {
  status?: WaitlistStatus;
  /** Email prefix. */
  email?: string;
  limit?: number;
  offset?: number;
}

export interface WaitlistList {
  items: WaitlistEntry[];
  page: { total: number; limit: number; offset: number };
}

/** The outcome of a bulk approval; with `more`, call again to continue. */
export interface WaitlistApproved {
  approved: number;
  skipped: number;
  more: boolean;
}

export interface WaitlistClientOptions {
  baseUrl: string;
  /** An access token with iam:waitlist:read / iam:waitlist:write; a function is called per request. */
  token: string | (() => string | undefined | Promise<string | undefined>);
  fetch?: FetchLike;
  timeoutMs?: number;
}

/**
 * Server-side helper for the sign-up waitlist (`/api/v1`, enabled with the
 * sign-in policy's `waitlist`): list and read entries, approve (which emails
 * the person a single-use sign-up link), reject and delete. Failures throw
 * IAMKitError; deciding an entry that is rejected or completed is 409
 * `WAITLIST_ENTRY_NOT_PENDING`.
 */
export class WaitlistClient {
  private readonly http: Transport;
  private readonly token: WaitlistClientOptions["token"];

  constructor(options: WaitlistClientOptions) {
    if (!options.token) {
      throw invalidArgument("token is required");
    }
    this.http = new Transport(options);
    this.token = options.token;
  }

  /** One page of entries, newest first (iam:waitlist:read). */
  async list(environmentId: string, filter: WaitlistFilter = {}): Promise<WaitlistList> {
    const number = (n: number | undefined) => (n === undefined ? undefined : String(n));
    const query = { status: filter.status, email: filter.email, limit: number(filter.limit), offset: number(filter.offset) };
    const out = await this.call<WaitlistList>("GET", withQuery(base(environmentId), query));
    return { ...out, items: out.items ?? [] };
  }

  /** One entry (iam:waitlist:read). */
  async get(environmentId: string, id: string): Promise<WaitlistEntry> {
    return this.call("GET", `${base(environmentId)}/${segment(id)}`);
  }

  /** Approves a pending entry (or sends an approved one a new link) and emails the person (iam:waitlist:write). */
  async approve(environmentId: string, id: string): Promise<WaitlistEntry> {
    return this.call("POST", `${base(environmentId)}/${segment(id)}/approve`, {});
  }

  /** Approves the listed entries, or every pending one with `allPending` (at most 500 per call; repeat while `more`). */
  async approveMany(environmentId: string, selection: { ids?: string[]; allPending?: boolean }): Promise<WaitlistApproved> {
    return this.call("POST", `${base(environmentId)}/approve`, { ids: selection.ids, all_pending: selection.allPending });
  }

  /** Approves every pending entry, repeating while IAMKit reports more. Returns the totals. */
  async approveAllPending(environmentId: string): Promise<{ approved: number; skipped: number }> {
    let approved = 0;
    let skipped = 0;
    for (;;) {
      const out = await this.approveMany(environmentId, { allPending: true });
      approved += out.approved;
      skipped += out.skipped;
      // Stop when nothing moved, or a stuck batch would loop forever.
      if (!out.more || out.approved === 0) {
        return { approved, skipped };
      }
    }
  }

  /** Rejects an entry; silent unless `notify` (iam:waitlist:write). */
  async reject(environmentId: string, id: string, options: { notify?: boolean } = {}): Promise<WaitlistEntry> {
    return this.call("POST", `${base(environmentId)}/${segment(id)}/reject`, { notify: options.notify ?? false });
  }

  /** Deletes an entry, so its email can join again (iam:waitlist:write). */
  async delete(environmentId: string, id: string): Promise<void> {
    await this.call("DELETE", `${base(environmentId)}/${segment(id)}`);
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
  return `/api/v1/environments/${segment(environmentId)}/waitlist`;
}
