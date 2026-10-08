import type { IncomingMessage, ServerResponse } from "node:http";
import { IAMKitError } from "./errors.js";
import { hasPermission, type AccessClaims, type TokenVerifier } from "./tokens.js";

/** A request after authenticate(): `req.iamkit` holds the verified claims. */
export interface AuthenticatedRequest extends IncomingMessage {
  iamkit?: AccessClaims;
}

/** Connect/Express middleware signature (no framework dependency). */
export type Middleware = (req: IncomingMessage, res: ServerResponse, next: (error?: unknown) => void) => void;

/**
 * Reads the bearer token, verifies it and stores the claims on
 * `req.iamkit`. Missing or invalid tokens answer 401 and stop the chain;
 * an unreachable IAMKit (introspection, JWKS) answers 503 — never let a
 * request through without verified claims.
 */
export function authenticate(verifier: TokenVerifier): Middleware {
  return (req, res, next) => {
    const token = bearer(req.headers.authorization);
    if (!token) {
      fail(res, 401, "UNAUTHORIZED", "missing or invalid bearer token");
      return;
    }
    verifier.verify(token).then(
      (claims) => {
        (req as AuthenticatedRequest).iamkit = claims;
        next();
      },
      (error: unknown) => {
        if (error instanceof IAMKitError && error.status >= 500) {
          fail(res, 503, "UNAVAILABLE", "token verification unavailable");
        } else {
          fail(res, 401, "UNAUTHORIZED", "invalid or expired token");
        }
      },
    );
  };
}

/** The claims authenticate() stored, or undefined. */
export function claimsOf(req: IncomingMessage): AccessClaims | undefined {
  return (req as AuthenticatedRequest).iamkit;
}

/** Requires every listed permission (403 otherwise). It does not imply a tenant check. */
export function requirePermissions(...permissions: string[]): Middleware {
  return (req, res, next) => {
    const claims = claimsOf(req);
    if (!claims) {
      fail(res, 401, "UNAUTHORIZED", "missing or invalid bearer token");
      return;
    }
    if (!hasPermission(claims, ...permissions)) {
      fail(res, 403, "FORBIDDEN", "missing permission");
      return;
    }
    next();
  };
}

/**
 * Requires an `application` token of the organization: a fixed ID from
 * trusted configuration, or a function reading the requested organization
 * (e.g. `(req) => req.params.organization`), which is then compared with
 * the token — the route parameter is never authority on its own. Machine
 * tokens have no organization and are refused.
 */
export function requireOrganization(organization: string | ((req: IncomingMessage) => string | undefined)): Middleware {
  return (req, res, next) => {
    const claims = claimsOf(req);
    if (!claims) {
      fail(res, 401, "UNAUTHORIZED", "missing or invalid bearer token");
      return;
    }
    const id = typeof organization === "function" ? organization(req) : organization;
    if (!id || claims.purpose !== "application" || claims.organization_id !== id) {
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
      fail(res, 401, "UNAUTHORIZED", "missing or invalid bearer token");
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
