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
  /** The waitlist approval link is unknown, expired, used or for another email: ask to join again. */
  WaitlistTokenInvalid: "WAITLIST_TOKEN_INVALID",
  PasswordResetDisabled: "PASSWORD_RESET_DISABLED",
  ActionDenied: "ACTION_DENIED",
  /** The environment asks for a (new) `captchaToken`; `details.provider` names the provider. */
  CaptchaRequired: "CAPTCHA_REQUIRED",
  /** A restriction or risk rule refused the sign-in: do not retry. */
  SignInBlocked: "SIGN_IN_BLOCKED",
  /** A risk challenge was needed where none can be parked. */
  RiskChallenge: "RISK_CHALLENGE",
  /** A risk challenge was needed but the user has no verified email. */
  ChallengeUnavailable: "CHALLENGE_UNAVAILABLE",
} as const;

function codeOf(error: unknown, code: string): error is IAMKitError {
  return error instanceof IAMKitError && error.code === code;
}

/** The sign-in needs a `captchaToken` (solve the widget, then retry). */
export function isCaptchaRequired(error: unknown): error is IAMKitError {
  return codeOf(error, ErrorCodes.CaptchaRequired);
}

/** A restriction or risk rule refused the sign-in (retrying will not help). */
export function isSignInBlocked(error: unknown): error is IAMKitError {
  return codeOf(error, ErrorCodes.SignInBlocked);
}

/** A risk challenge was needed where none can be parked (`RISK_CHALLENGE`). */
export function isRiskChallenge(error: unknown): error is IAMKitError {
  return codeOf(error, ErrorCodes.RiskChallenge);
}

/** A risk challenge was needed but the user has no verified email. */
export function isChallengeUnavailable(error: unknown): error is IAMKitError {
  return codeOf(error, ErrorCodes.ChallengeUnavailable);
}

/** The provider a `CAPTCHA_REQUIRED` error names (`turnstile`, `hcaptcha`), or undefined. */
export function captchaProvider(error: unknown): string | undefined {
  if (!isCaptchaRequired(error)) {
    return undefined;
  }
  const provider = error.details?.provider;
  return typeof provider === "string" ? provider : undefined;
}
