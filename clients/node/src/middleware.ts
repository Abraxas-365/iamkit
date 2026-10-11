import type { IncomingMessage, ServerResponse } from "node:http";
import { IAMKitError } from "./errors.js";
import { hasAPIKeyPermission, isAPIKey, type APIKey, type APIKeyValidator } from "./apikeys.js";
import { hasPermission, type AccessClaims, type TokenVerifier } from "./tokens.js";

/**
 * A request after authenticate(): `req.iamkit` holds the verified claims of
 * an access token, or `req.iamkitKey` the API key (only with `allowApiKeys`);
 * never both.
 */
export interface AuthenticatedRequest extends IncomingMessage {
  iamkit?: AccessClaims;
  iamkitKey?: APIKey;
}

export interface AuthenticateOptions {
  /**
   * Opt in to `ik_key_` API keys of any owner type, validated online by
   * this validator (createAPIKeyValidator). Off by default: an API key is
   * then refused with 401. Keys carry no session, so requireMFA refuses them.
   */
  allowApiKeys?: APIKeyValidator;
}

/** Who made the request: an access token's claims or an API key. */
export type Principal = { claims: AccessClaims; apiKey?: undefined } | { apiKey: APIKey; claims?: undefined };

/** Connect/Express middleware signature (no framework dependency). */
export type Middleware = (req: IncomingMessage, res: ServerResponse, next: (error?: unknown) => void) => void;

/**
 * Reads the bearer token, verifies it and stores the claims on
 * `req.iamkit`. Missing or invalid tokens answer 401 and stop the chain;
 * an unreachable IAMKit (introspection, JWKS) answers 503 — never let a
 * request through without verified claims.
 */
export function authenticate(verifier: TokenVerifier, options: AuthenticateOptions = {}): Middleware {
  const rejected = (res: ServerResponse) => (error: unknown) => {
    if (error instanceof IAMKitError && error.status >= 500) {
      fail(res, 503, "UNAVAILABLE", "token verification unavailable");
    } else {
      fail(res, 401, "UNAUTHORIZED", "invalid or expired token");
    }
  };
  return (req, res, next) => {
    const token = bearer(req.headers.authorization);
    if (!token) {
      fail(res, 401, "UNAUTHORIZED", "missing or invalid bearer token");
      return;
    }
    const request = req as AuthenticatedRequest;
    if (isAPIKey(token)) {
      // API keys never reach the JWT verifier.
      if (!options.allowApiKeys) {
        fail(res, 401, "UNAUTHORIZED", "invalid or expired token");
        return;
      }
      options.allowApiKeys.validate(token).then((key) => {
        request.iamkitKey = key;
        next();
      }, rejected(res));
      return;
    }
    verifier.verify(token).then((claims) => {
      request.iamkit = claims;
      next();
    }, rejected(res));
  };
}

/** The access token claims authenticate() stored, or undefined (also for an API key request). */
export function claimsOf(req: IncomingMessage): AccessClaims | undefined {
  return (req as AuthenticatedRequest).iamkit;
}

/** The API key authenticate() stored with `allowApiKeys`, or undefined. */
export function apiKeyOf(req: IncomingMessage): APIKey | undefined {
  return (req as AuthenticatedRequest).iamkitKey;
}

/** The authenticated principal (access token or API key), or undefined. */
export function principalOf(req: IncomingMessage): Principal | undefined {
  const claims = claimsOf(req);
  if (claims) {
    return { claims };
  }
  const apiKey = apiKeyOf(req);
  return apiKey ? { apiKey } : undefined;
}

/** Requires every listed permission of the token or API key (403 otherwise). It does not imply a tenant check. */
export function requirePermissions(...permissions: string[]): Middleware {
  return (req, res, next) => {
    const principal = principalOf(req);
    if (!principal) {
      fail(res, 401, "UNAUTHORIZED", "missing or invalid bearer token");
      return;
    }
    const allowed = principal.apiKey ? hasAPIKeyPermission(principal.apiKey, ...permissions) : hasPermission(principal.claims, ...permissions);
    if (!allowed) {
      fail(res, 403, "FORBIDDEN", "missing permission");
      return;
    }
    next();
  };
}

/**
 * Requires an `application` token (or an API key) of the organization: a fixed ID from
 * trusted configuration, or a function reading the requested organization
 * (e.g. `(req) => req.params.organization`), which is then compared with
 * the token — the route parameter is never authority on its own. Machine
 * tokens have no organization and are refused; an API key matches by its
 * organization.
 */
export function requireOrganization(organization: string | ((req: IncomingMessage) => string | undefined)): Middleware {
  return (req, res, next) => {
    const principal = principalOf(req);
    if (!principal) {
      fail(res, 401, "UNAUTHORIZED", "missing or invalid bearer token");
      return;
    }
    const id = typeof organization === "function" ? organization(req) : organization;
    const bound = principal.apiKey ? principal.apiKey.organization_id : principal.claims.purpose === "application" ? principal.claims.organization_id : undefined;
    if (!id || !bound || bound !== id) {
      fail(res, 403, "FORBIDDEN", "organization mismatch");
      return;
    }
    next();
  };
}

/** Requires a session that passed a second factor, optionally signed in within maxAgeSec. */
export function requireMFA(options: { maxAgeSec?: number } = {}): Middleware {
  return (req, res, next) => {
    const claims = claimsOf(req);
    if (!claims) {
      fail(res, principalOf(req) ? 403 : 401, principalOf(req) ? "STEP_UP_REQUIRED" : "UNAUTHORIZED", principalOf(req) ? "a recent second factor is required" : "missing or invalid bearer token");
      return;
    }
    const fresh = options.maxAgeSec === undefined || (claims.auth_time !== undefined && Date.now() / 1000 - claims.auth_time <= options.maxAgeSec);
    if (!claims.amr?.includes("mfa") || !fresh) {
      fail(res, 403, "STEP_UP_REQUIRED", "a recent second factor is required");
      return;
    }
    next();
  };
}

function bearer(value: string | undefined): string | undefined {
  const parts = value?.trim().split(/\s+/) ?? [];
  return parts.length === 2 && parts[0].toLowerCase() === "bearer" ? parts[1] : undefined;
}

function fail(res: ServerResponse, status: number, code: string, message: string): void {
  if (res.headersSent) {
    return;
  }
  res.statusCode = status;
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json");
  if (status === 401) {
    res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
  }
  res.end(JSON.stringify({ error: { code, message } }));
}
