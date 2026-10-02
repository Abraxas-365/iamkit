import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { cookies } from "next/headers";
import { config, type Config } from "./config";

/** The app's own session: the verified ID token, in an httpOnly cookie. */
export const SESSION_COOKIE = "app_session";
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

export interface PendingRequest {
  state: string;
  nonce: string;
  verifier: string;
}
