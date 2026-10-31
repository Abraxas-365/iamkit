/**
 * RFC 7662 introspection for the resource server (D37): a token that passed
 * the signature checks is also asked about at IAMKit, so a revoked consent,
 * a disconnected application, a blocked client or an ended session stops it
 * at once. Fails closed: when IAMKit cannot answer the request gets 503
 * without a challenge and the token is never admitted unchecked.
 */
import { createHash } from "node:crypto";
import type { FetchLike } from "./http.js";
import { OAuthClient } from "./oauth.js";

export interface IntrospectionOptions {
  /** A confidential OAuth client of the resource's environment. */
  clientId: string;
  clientSecret: string;
  /**
   * Keep an active answer for at most this many seconds (never past the
   * token's exp). 0, the default, asks on every request; a cached answer
   * admits a revoked token for up to cacheTtlSec.
   */
  cacheTtlSec?: number;
  /** Cache bound (default 10 000 entries). */
  maxCacheEntries?: number;
  /** IAMKit origin when it differs from the issuer (default the issuer). */
  baseUrl?: string;
  fetch?: FetchLike;
  timeoutMs?: number;
}

/** What check compares an answer against: the verified token's claims. */
export interface IntrospectedToken {
  sub: string;
  sessionId: string;
  /** The token's client_id claim (RFC 9068). */
  clientId: string;
  /** The token's granted scopes. */
  scopes: string[];
  exp: number;
}

/** Two scope lists hold the same scopes (order and repeats aside). */
function sameScopes(a: string[], b: string[]): boolean {
  const x = new Set(a);
  const y = new Set(b);
  return x.size === y.size && [...x].every((s) => y.has(s));
}

export type IntrospectionResult = "active" | "inactive" | "unavailable";

export interface Introspector {
  check(raw: string, token: IntrospectedToken, isResource: (aud: string) => boolean): Promise<IntrospectionResult>;
}

export function createIntrospector(issuer: string, options: IntrospectionOptions, now: () => number = () => Date.now() / 1000): Introspector {
  if (!options.clientId || !options.clientSecret) throw new TypeError("introspection needs clientId and clientSecret");
  const ttl = options.cacheTtlSec ?? 0;
  if (!(ttl >= 0)) throw new TypeError("introspection cacheTtlSec cannot be negative");
  const max = options.maxCacheEntries && options.maxCacheEntries > 0 ? options.maxCacheEntries : 10_000;
  const client = new OAuthClient({
    baseUrl: options.baseUrl ?? issuer,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    fetch: options.fetch,
    timeoutMs: options.timeoutMs,
  });
  // Keyed by the token's hash: the cache never holds tokens.
  const cache = new Map<string, number>();

  function store(key: string, until: number, at: number): void {
    if (cache.size >= max) {
      for (const [k, v] of cache) if (v <= at) cache.delete(k);
      // Map iterates in insertion order: the oldest go first.
      for (const k of cache.keys()) {
        if (cache.size < max) break;
        cache.delete(k);
      }
    }
    cache.set(key, until);
  }

  return {
    async check(raw, token, isResource) {
      const key = createHash("sha256").update(raw).digest("base64url");
      const at = now();
      if (ttl > 0) {
        const until = cache.get(key);
        if (until !== undefined && at < until) return "active";
        cache.delete(key);
      }
      let answer;
      try {
        answer = await client.introspect(raw);
      } catch {
        return "unavailable";
      }
      // The answer must describe this token: active, an access token of the
      // same subject, session and client, with the same granted scopes and
      // the resource in its audience; anything else is another token (or a
      // grant that changed).
      if (
        !answer.active ||
        answer.token_use !== "access_token" ||
        answer.sub !== token.sub ||
        answer.sid !== token.sessionId ||
        !token.clientId ||
        answer.client_id !== token.clientId ||
        !sameScopes((answer.scope ?? "").split(" ").filter(Boolean), token.scopes) ||
        !(answer.aud ?? []).some(isResource)
      ) {
        return "inactive";
      }
      if (ttl > 0) store(key, Math.min(at + ttl, token.exp), at);
      return "active";
    },
  };
}
