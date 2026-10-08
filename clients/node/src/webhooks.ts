import { createHmac, timingSafeEqual } from "node:crypto";
import { IAMKitError } from "./errors.js";

/**
 * IAMKit signs event webhooks and action calls per Standard Webhooks
 * (https://www.standardwebhooks.com): headers `webhook-id`,
 * `webhook-timestamp` and `webhook-signature` (`v1,<base64 HMAC-SHA256>` of
 * `id.timestamp.body`, several space-separated while a secret rotation
 * overlaps). Verify against the raw body bytes, before any JSON parsing.
 */

/** How far `webhook-timestamp` may be from now (5 minutes). */
export const ToleranceSec = 5 * 60;

/** Bodies larger than this are refused (1 MiB). */
export const MaxBody = 1 << 20;

/** Request headers as Node exposes them (`req.headers`) or a fetch Headers. */
export type HeaderSource = Headers | Record<string, string | string[] | undefined>;

/** Signature failures: `SIGNATURE`, `TIMESTAMP` or `SECRET` codes, status 401. */
export class WebhookError extends IAMKitError {
  constructor(code: "SIGNATURE" | "TIMESTAMP" | "SECRET" | "BODY", message: string) {
    super(code === "BODY" ? 400 : 401, code, message);
    this.name = "WebhookError";
  }
}

/** An event delivered to a webhook subscription (an entry of the event log). */
export interface WebhookEvent {
  id: number;
  environment_id: string;
  /** `<subject>.<verb>`, e.g. `user.created`; test deliveries are `webhook.test`. */
  type: string;
  actor: { kind: string; id?: string };
  subject: { kind: string; id?: string };
  organization_id?: string;
  /** `{"truncated": true}` past 64 KiB: read the event log for it. */
  data?: unknown;
  occurred_at: string;
}

export interface VerifyOptions {
  /** The time to check the timestamp against (default now). */
  now?: Date;
  toleranceSec?: number;
}

/**
 * Checks the signature headers of body (the raw bytes or string) with
 * secret (`whsec_…`). Throws WebhookError when it does not verify.
 */
export function verifySignature(secret: string, headers: HeaderSource, body: string | Uint8Array, options: VerifyOptions = {}): void {
  const raw = secret.startsWith("whsec_") ? secret.slice(6) : secret;
  const key = Buffer.from(raw, "base64");
  if (!raw || key.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) {
    throw new WebhookError("SECRET", "malformed webhook secret");
  }
  const bytes = typeof body === "string" ? Buffer.from(body) : Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (bytes.length > MaxBody) {
    throw new WebhookError("BODY", "webhook body too large");
  }
  const id = header(headers, "webhook-id");
  const timestamp = header(headers, "webhook-timestamp");
  const now = (options.now ?? new Date()).getTime() / 1000;
  const unix = /^\d+$/.test(timestamp) ? Number(timestamp) : NaN;
  if (!Number.isFinite(unix) || Math.abs(now - unix) > (options.toleranceSec ?? ToleranceSec)) {
    throw new WebhookError("TIMESTAMP", "webhook timestamp outside tolerance");
  }
  const want = createHmac("sha256", key).update(`${id}.${timestamp}.`).update(bytes).digest();
  for (const signature of header(headers, "webhook-signature").split(/\s+/)) {
    const [version, value] = signature.split(",", 2);
    if (version !== "v1" || !value) {
      continue;
    }
    const got = Buffer.from(value, "base64");
    if (got.length === want.length && timingSafeEqual(got, want)) {
      return;
    }
  }
  throw new WebhookError("SIGNATURE", "webhook signature mismatch");
}

/**
 * Verifies an event webhook and decodes the event. Deliveries are at least
 * once: dedupe on the `webhook-id` header or `event.id`. Answer 2xx quickly.
 */
export function verifyWebhook(secret: string, headers: HeaderSource, body: string | Uint8Array, options?: VerifyOptions): WebhookEvent {
  verifySignature(secret, headers, body, options);
  return decode<WebhookEvent>(body);
}

/** Action conditions. */
export const Conditions = {
  PreSignIn: "function:pre_sign_in",
  PreRegistration: "function:pre_registration",
  PostFederation: "function:post_federation",
  PreAccessToken: "function:pre_access_token",
  PreIDToken: "function:pre_id_token",
  PreUserInfo: "function:pre_userinfo",
  UserCreate: "request:user.create",
  UserUpdate: "request:user.update",
  MembershipCreate: "request:membership.create",
} as const;

/** What an action target receives; fields a condition does not have are absent. */
export interface ActionInput {
  condition: (typeof Conditions)[keyof typeof Conditions] | (string & {});
  environment_id: string;
  organization_id?: string;
  application_id?: string;
  client_id?: string;
  /** The user the flow is about; `id` is absent before registration. */
  user?: { id?: string; email?: string; name?: string; username?: string };
  /** How the user signed in. */
  amr?: string[];
  scopes?: string[];
  /** The external identity of post_federation and federated pre_registration. */
  identity?: { connection_id: string; provider: string; subject: string; email?: string; name?: string };
  /** The request body of a `request:*` condition (passwords left out). */
  request?: unknown;
}

/**
 * A call target's answer: answer 204 (or `{}`) to allow unchanged. Claims
 * are added to tokens/UserInfo (reserved claims refused); patch replaces
 * fields the condition lets targets change.
 */
export interface ActionResponse {
  deny?: boolean;
  /** Shown to the user when denying. */
  message?: string;
  claims?: Record<string, unknown>;
  patch?: Record<string, unknown>;
}

/** Verifies an action call (either secret verifies during a rotation) and decodes its input. */
export function verifyAction(secret: string, headers: HeaderSource, body: string | Uint8Array, options?: VerifyOptions): ActionInput {
  verifySignature(secret, headers, body, options);
  return decode<ActionInput>(body);
}

/** A response refusing the flow with message. */
export function deny(message: string): ActionResponse {
  return { deny: true, message };
}

function decode<T>(body: string | Uint8Array): T {
  try {
    return JSON.parse(typeof body === "string" ? body : Buffer.from(body).toString("utf8")) as T;
  } catch {
    throw new WebhookError("BODY", "webhook body is not JSON");
  }
}

function header(headers: HeaderSource, name: string): string {
  if (typeof (headers as Headers).get === "function") {
    return (headers as Headers).get(name) ?? "";
  }
  const record = headers as Record<string, string | string[] | undefined>;
  const value = record[name] ?? record[Object.keys(record).find((k) => k.toLowerCase() === name) ?? ""];
  return Array.isArray(value) ? value.join(" ") : (value ?? "");
}
