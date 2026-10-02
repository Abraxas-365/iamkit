"use server";

import { challengeOf, createVerifier } from "@iamkit/js";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { config, redirectUri } from "@/lib/config";
import { REQUEST_COOKIE, SESSION_COOKIE, type PendingRequest } from "@/lib/session";

/**
 * Starts the OAuth authorization (code + PKCE). The client is not a
 * hosted_login client, so the browser goes to this app's own sign-in page
 * with the authorize query; that page calls IAMKit's /oauth/authorize and
 * receives the ticket.
 */
export async function signIn(form: FormData) {
  const c = config();
  const request: PendingRequest = { state: createVerifier(43), nonce: createVerifier(43), verifier: createVerifier() };
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
  const organization = String(form.get("organization") ?? "");
  if (organization) query.set("organization_id", organization);
  const hint = String(form.get("login_hint") ?? "");
  if (hint) query.set("login_hint", hint);
  redirect(`/sign-in?${query}`);
}

export async function signOut() {
  (await cookies()).delete(SESSION_COOKIE);
  redirect("/");
}
