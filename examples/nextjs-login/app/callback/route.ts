import { NextResponse, type NextRequest } from "next/server";
import { config, redirectUri } from "@/lib/config";
import { ACCESS_COOKIE, REQUEST_COOKIE, SESSION_COOKIE, verifyIDToken, type PendingRequest } from "@/lib/session";

/**
 * The OAuth redirect URI: checks state, exchanges the code with the PKCE
 * verifier, verifies the ID token and starts the app's own session.
 */
export async function GET(req: NextRequest) {
  const c = config();
  const home = (error?: string, next?: string) => {
    const res = NextResponse.redirect(new URL(error ? `/?error=${encodeURIComponent(error)}` : (next ?? "/"), c.appUrl), 303);
    res.cookies.delete(REQUEST_COOKIE);
    return res;
  };
  const raw = req.cookies.get(REQUEST_COOKIE)?.value;
  const params = req.nextUrl.searchParams;
  if (!raw) return home("no pending sign-in");
  const pending = JSON.parse(raw) as PendingRequest;
  if (params.get("state") !== pending.state) return home("state mismatch");
  if (params.get("error")) return home(params.get("error")!);

  const response = await fetch(`${c.internalUrl}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: params.get("code") ?? "",
      redirect_uri: redirectUri(c),
      client_id: c.clientId,
      code_verifier: pending.verifier,
    }),
  });
  if (!response.ok) return home(`token exchange failed (${response.status})`);
  const tokens = (await response.json()) as { id_token?: string; access_token?: string; expires_in?: number };
  if (!tokens.id_token) return home("no id_token");
  let claims;
  try {
    claims = await verifyIDToken(tokens.id_token, pending.nonce);
  } catch {
    return home("invalid id_token");
  }
  // The verified identity is the app's session. The access token is kept
  // (httpOnly) only for /account, whose widgets call IAMKit's self-service
  // API with it; there is no refresh token, so it ends with the token's
  // lifetime and the user signs in again.
  const res = home(undefined, pending.next);
  res.cookies.set(SESSION_COOKIE, tokens.id_token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: Math.max(60, (claims.exp ?? 0) - Math.floor(Date.now() / 1000)),
  });
  if (tokens.access_token) {
    res.cookies.set(ACCESS_COOKIE, tokens.access_token, { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: Math.max(60, tokens.expires_in ?? 900) });
  }
  return res;
}
