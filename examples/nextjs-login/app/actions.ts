"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { authorizeUrl } from "@/lib/authorize";
import { ACCESS_COOKIE, SESSION_COOKIE } from "@/lib/session";

/**
 * Starts the OAuth authorization (code + PKCE). The client is not a
 * hosted_login client, so the browser goes to this app's own sign-in page
 * with the authorize query; that page calls IAMKit's /oauth/authorize and
 * receives the ticket.
 */
export async function signIn(form: FormData) {
  redirect(
    await authorizeUrl({
      organization: String(form.get("organization") ?? "") || undefined,
      login_hint: String(form.get("login_hint") ?? "") || undefined,
    }),
  );
}

export async function signOut() {
  const jar = await cookies();
  jar.delete(SESSION_COOKIE);
  jar.delete(ACCESS_COOKIE);
  redirect("/");
}

/**
 * The account widgets ask for a recent sign-in (REAUTHENTICATION_REQUIRED):
 * sign in again with max_age=0 and come back to /account.
 */
export async function reauthenticate() {
  redirect(await authorizeUrl({ fresh: true, next: "/account" }));
}

/**
 * Sessions issued through OAuth (code + PKCE) cannot switch organization in
 * place, so the switcher starts a new authorization pinned to the chosen
 * organization (a user already signed in to IAMKit's SSO/MFA rules meets
 * them here, like at any sign-in).
 */
export async function selectOrganization(organization: string) {
  redirect(await authorizeUrl({ organization, next: "/account" }));
}
