/**
 * A failed IAMKit call or a refused credential: `code` is IAMKit's error
 * code (`UNAUTHORIZED`, `VALIDATION`, `ACTION_DENIED`, …) or, on `/oauth/*`
 * endpoints, the OAuth error (`invalid_grant`, `authorization_pending`, …).
 * `status` is the HTTP status (401 for tokens this SDK refuses locally).
 * Network failures reject with the fetch error instead.
 */
export class IAMKitError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details?: Record<string, unknown>;

  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "IAMKitError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

/** Builds an IAMKitError from a failed response body (any shape). */
export function toError(status: number, body: unknown): IAMKitError {
  if (typeof body === "object" && body !== null && "error" in body) {
    const e = (body as { error: unknown }).error;
    if (typeof e === "object" && e !== null) {
      const detail = e as { code?: unknown; message?: unknown; details?: unknown };
      return new IAMKitError(
        status,
        typeof detail.code === "string" ? detail.code : "ERROR",
        typeof detail.message === "string" ? detail.message : "request failed",
        typeof detail.details === "object" && detail.details !== null ? (detail.details as Record<string, unknown>) : undefined,
      );
    }
    if (typeof e === "string") {
      const description = (body as { error_description?: unknown }).error_description;
      return new IAMKitError(status, e, typeof description === "string" && description ? description : e);
    }
  }
  if (status === 429) {
    return new IAMKitError(status, "TOO_MANY_REQUESTS", "too many requests");
  }
  return new IAMKitError(status, "http_error", "request failed");
}

/** Well-known codes a server reacts to. */
export const ErrorCodes = {
  Unauthorized: "UNAUTHORIZED",
  Forbidden: "FORBIDDEN",
  Validation: "VALIDATION",
  JWKSUnavailable: "JWKS_UNAVAILABLE",
  ActionDenied: "ACTION_DENIED",
  ActionFailed: "ACTION_FAILED",
  QuotaExceeded: "QUOTA_EXCEEDED",
  PasswordChangeRequired: "PASSWORD_CHANGE_REQUIRED",
  PasswordPolicy: "PASSWORD_POLICY",
  // OAuth
  InvalidGrant: "invalid_grant",
  InvalidClient: "invalid_client",
  AuthorizationPending: "authorization_pending",
  SlowDown: "slow_down",
  ExpiredToken: "expired_token",
  AccessDenied: "access_denied",
} as const;

export function unauthorized(message: string): IAMKitError {
  return new IAMKitError(401, ErrorCodes.Unauthorized, message);
}

export function invalidArgument(message: string): IAMKitError {
  return new IAMKitError(400, ErrorCodes.Validation, message);
}
