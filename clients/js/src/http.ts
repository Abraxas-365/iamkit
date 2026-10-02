import { createIAMKitClient, type IAMKitClient } from "@iamkit/api";
import { toError } from "./errors.js";

export interface TransportOptions {
  /** IAMKit deployment origin, e.g. `https://id.example.com`. */
  baseUrl: string;
  /** Custom fetch (tests, server runtimes). Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
}

/**
 * The generated client configured for browser sign-in: every request
 * carries cookies (`credentials: "include"`) because the authorize ticket
 * and federation starts are bound to the browser with IAMKit cookies.
 * Tokens are never stored by the SDK; callers pass them explicitly.
 */
export function transport(options: TransportOptions): IAMKitClient {
  const custom = options.fetch;
  return createIAMKitClient({
    baseUrl: options.baseUrl,
    credentials: "include",
    ...(custom ? { fetch: (request: Request) => custom(request) } : {}),
  });
}

/** The `{data, error, response}` result of an openapi-fetch call. */
export interface Outcome<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/** Unwraps a call: its data, or an IAMKitError for a failed status. */
export async function unwrap<T>(call: Promise<Outcome<T>>): Promise<T> {
  const { data, error, response } = await call;
  if (!response.ok) {
    throw toError(response.status, error);
  }
  return data as T;
}

/** Unwraps a call that answers without a body (204). */
export async function done(call: Promise<Outcome<unknown>>): Promise<void> {
  const { error, response } = await call;
  if (!response.ok) {
    throw toError(response.status, error);
  }
}
