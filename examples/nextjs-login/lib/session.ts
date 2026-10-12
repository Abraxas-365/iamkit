import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { cookies } from "next/headers";
import { config, type Config } from "./config";

/** The app's own session: the verified ID token, in an httpOnly cookie. */
export const SESSION_COOKIE = "app_session";
/**
 * The user's access token for IAMKit's self-service API (/account), in an
 * httpOnly cookie: the browser widgets get it through /account/token.
 */
export const ACCESS_COOKIE = "app_access";
/** The pending authorization request (state, nonce, PKCE verifier). */
export const REQUEST_COOKIE = "app_oidc";

const keySets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function keys(c: Config) {
  let set = keySets.get(c.internalUrl);
  if (!set) {
    set = createRemoteJWKSet(new URL(`${c.internalUrl}/.well-known/jwks.json`));
    keySets.set(c.internalUrl, set);
  }
  return set;
}

/** Verifies an ID token issued to this client. */
export async function verifyIDToken(token: string, nonce?: string): Promise<JWTPayload> {
  const c = config();
  const { payload } = await jwtVerify(token, keys(c), { issuer: c.issuer, audience: c.clientId });
  if (nonce !== undefined && payload.nonce !== nonce) {
    throw new Error("nonce mismatch");
  }
  return payload;
}

/** The signed-in user, or null. */
export async function session(): Promise<JWTPayload | null> {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token) return null;
  try {
    return await verifyIDToken(token);
  } catch {
    return null;
  }
}

/** The access token for IAMKit's self-service API and the scope its calls need. */
export interface AccessToken {
  raw: string;
  environmentId: string;
  audience: string;
}

/** The user's verified access token (from the httpOnly cookie), or null. */
export async function accessToken(): Promise<AccessToken | null> {
  const raw = (await cookies()).get(ACCESS_COOKIE)?.value;
  if (!raw) return null;
  try {
    // The audience is the application's resource, not this client: only
    // the issuer and signature are checked here; IAMKit checks the rest.
    const { payload } = await jwtVerify(raw, keys(config()), { issuer: config().issuer });
    const audience = Array.isArray(payload.aud) ? payload.aud[0] : payload.aud;
    if (!audience || typeof payload.environment_id !== "string") return null;
    return { raw, environmentId: payload.environment_id, audience };
  } catch {
    return null;
  }
}

export interface PendingRequest {
  state: string;
  nonce: string;
  verifier: string;
  /** A path of this app to go to after signing in. */
  next?: string;
}
