// Configuration of the example, read on the server at request time (so one
// build serves any deployment). Nothing here is secret: the client is a
// public OAuth client (code + PKCE).

export interface Config {
  /** IAMKit's public URL (its issuer): the browser talks to it. */
  issuer: string;
  /** Where this server reaches IAMKit (token exchange, JWKS); defaults to the issuer. */
  internalUrl: string;
  /** The OAuth client: public, not hosted_login, this app's origin in allowed_origins. */
  clientId: string;
  /** This app's public URL; the redirect URI is `${appUrl}/callback`. */
  appUrl: string;
  /** Organization used when the authorize request names none. */
  organizationId?: string;
}

export function config(): Config {
  const need = (name: string) => {
    const value = process.env[name];
    if (!value) throw new Error(`${name} is required`);
    return value.replace(/\/$/, "");
  };
  const issuer = need("IAMKIT_ISSUER");
  return {
    issuer,
    internalUrl: (process.env.IAMKIT_INTERNAL_URL || issuer).replace(/\/$/, ""),
    clientId: need("IAMKIT_CLIENT_ID"),
    appUrl: need("APP_URL"),
    organizationId: process.env.IAMKIT_ORGANIZATION_ID || undefined,
  };
}

export const redirectUri = (c: Config) => `${c.appUrl}/callback`;
