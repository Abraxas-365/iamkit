import type { Schema } from "@iamkit/api";

/**
 * A failed IAMKit call: the `{"error": {...}}` envelope's code, message and
 * public details, with the HTTP status. Network failures reject with the
 * fetch error instead.
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
    const e = (body as { error: unknown; error_description?: unknown }).error;
    if (typeof e === "object" && e !== null) {
      const detail = e as Partial<Schema<"ErrorDetail">>;
      return new IAMKitError(status, detail.code ?? "ERROR", detail.message ?? "request failed", detail.details as Record<string, unknown> | undefined);
    }
    if (typeof e === "string") {
      // OAuth-style {error, error_description}.
      const description = (body as { error_description?: unknown }).error_description;
      return new IAMKitError(status, e, typeof description === "string" ? description : e);
    }
  }
  return new IAMKitError(status, status === 429 ? "TOO_MANY_REQUESTS" : "ERROR", "request failed");
}

/** Well-known error codes a sign-in UI reacts to. */
export const ErrorCodes = {
  PasswordChangeRequired: "PASSWORD_CHANGE_REQUIRED",
  PasswordPolicy: "PASSWORD_POLICY",
  MethodNotAllowed: "METHOD_NOT_ALLOWED",
  SSORequired: "SSO_REQUIRED",
  MFALocked: "MFA_LOCKED",
  AccountExists: "ACCOUNT_EXISTS",
  TermsRequired: "TERMS_REQUIRED",
  SignupDisabled: "SIGNUP_DISABLED",
  PasswordResetDisabled: "PASSWORD_RESET_DISABLED",
  ActionDenied: "ACTION_DENIED",
} as const;
