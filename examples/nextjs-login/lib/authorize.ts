import { challengeOf, createVerifier } from "@iamkit/js";
import { cookies } from "next/headers";
import { config, redirectUri } from "./config";
import { REQUEST_COOKIE, type PendingRequest } from "./session";

export interface AuthorizeOptions {
  /** Sign in to this organization (the authorize `organization_id` hint). */
  organization?: string;
  login_hint?: string;
  /** Sign in again even if the user just did (OIDC `max_age=0`): for changes that need a fresh sign-in. */
  fresh?: boolean;
  /** Where the callback sends the user afterwards (a path of this app). */
  next?: string;
}

/**
 * Keeps the pending request (state, nonce, PKCE verifier) in a cookie and
 * returns the app's own sign-in page URL carrying the authorize query.
 */
export async function authorizeUrl(options: AuthorizeOptions = {}): Promise<string> {
  const c = config();
  const request: PendingRequest = {
    state: createVerifier(43),
    nonce: createVerifier(43),
    verifier: createVerifier(),
    next: options.next?.startsWith("/") && !options.next.startsWith("//") ? options.next : undefined,
  };
  (await cookies()).set(REQUEST_COOKIE, JSON.stringify(request), { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 600 });
  const query = new URLSearchParams({
    client_id: c.clientId,
    redirect_uri: redirectUri(c),
    response_type: "code",
    scope: "openid email profile",
    state: request.state,
    nonce: request.nonce,
    code_challenge: await challengeOf(request.verifier),
    code_challenge_method: "S256",
  });
  if (options.organization) query.set("organization_id", options.organization);
  if (options.login_hint) query.set("login_hint", options.login_hint);
  if (options.fresh) query.set("max_age", "0");
  return `/sign-in?${query}`;
}
