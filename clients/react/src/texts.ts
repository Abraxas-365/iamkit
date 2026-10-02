import type { Authorization } from "@iamkit/js";

/**
 * English defaults for the hosted catalog keys the components use. The
 * operator's custom texts for the ticket's locale (`authorization.texts`,
 * set per environment, client or organization) win over them, so a custom
 * UI words its steps like the hosted pages; pass `texts` to the components
 * to translate the rest.
 */
export const defaultTexts: Record<string, string> = {
  "hosted.title.sign_in": "Sign in",
  "hosted.title.check_email": "Check your email",
  "hosted.title.reset": "Reset your password",
  "hosted.title.mfa": "Two-step verification",
  "hosted.subtitle.mfa": "Enter the 6-digit code from your authenticator app, or a recovery code.",
  "hosted.title.enroll": "Set up two-step verification",
  "hosted.subtitle.enroll": "Your organization requires an authenticator app. Scan the code, then enter the 6-digit code it shows.",
  "hosted.title.recovery": "Save your recovery codes",
  "hosted.subtitle.recovery": "Each code signs you in once if you lose your authenticator. They will not be shown again.",
  "hosted.title.password_expired": "Choose a new password",
  "hosted.subtitle.password_expired": "Your password has expired. Choose a new one to continue.",
  "hosted.title.expired": "Sign-in expired",
  "hosted.expired": "This sign-in link has expired. Go back to the application and try again.",
  "hosted.title.signup": "Create your account",
  "hosted.title.redirecting": "Signing you in",
  "hosted.notice.code_sent": "If the account can sign in with a code, we sent an 8-digit code to %s.",
  "hosted.notice.signup_sent": "Enter the 8-digit code we sent to %s. If this email already has an account, sign in instead.",
  "hosted.notice.reset_sent": "If the account exists, we sent an 8-digit code to %s.",
  "hosted.notice.factor_sent_email": "We sent a 6-digit code to %s.",
  "hosted.form.login": "Email or username",
  "hosted.form.email": "Email",
  "hosted.form.continue": "Continue",
  "hosted.form.or": "or",
  "hosted.form.continue_with": "Continue with %s",
  "hosted.form.password": "Password",
  "hosted.form.sign_in": "Sign in",
  "hosted.form.email_code": "Email me a code",
  "hosted.form.forgot_password": "Forgot password?",
  "hosted.directory.hint": "Enter the password of your organization's directory account.",
  "hosted.form.passkey": "Sign in with a passkey",
  "hosted.form.security_key": "Use your security key",
  "hosted.form.other_email": "Use another email",
  "hosted.form.code": "Code",
  "hosted.form.verify": "Verify",
  "hosted.form.new_password": "New password",
  "hosted.form.set_password": "Set password",
  "hosted.form.cant_scan": "Can't scan? Enter this key in the app:",
  "hosted.form.six_digit_code": "6-digit code",
  "hosted.form.verify_continue": "Verify and continue",
  "hosted.form.codes_saved": "I saved my codes — continue",
  "hosted.form.factor_email": "Email me a code instead",
  "hosted.form.factor_sms": "Text me a code instead",
  "hosted.form.name": "Name",
  "hosted.form.create_account": "Create account",
  "hosted.form.have_account": "Already have an account? Sign in",
  "hosted.form.accept_terms": "I accept the terms of service",
  "hosted.form.optional": "(optional — without one, we email you a code to sign in)",
  "hosted.error.generic": "Something went wrong. Please try again.",
};

export type Translate = (key: string, ...args: string[]) => string;

/** Looks a key up: caller texts › the ticket's custom texts › English. */
export function translator(authorization?: Pick<Authorization, "texts">, texts?: Record<string, string>): Translate {
  return (key, ...args) => {
    let s = texts?.[key] ?? authorization?.texts?.[key] ?? defaultTexts[key] ?? key;
    for (const a of args) s = s.replace("%s", a);
    return s;
  };
}
