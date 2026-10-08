import { createRemoteJWKSet, customFetch, errors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import { IAMKitError, invalidArgument, unauthorized } from "./errors.js";
import { Transport, type FetchLike } from "./http.js";

/**
 * The claims of an IAMKit access token (JWT from `/oauth/token` or
 * `/identity/v1`, or the `claims` of `/identity/v1/introspect`).
 */
export interface AccessClaims {
  /** The user (purpose `application`) or service account (`machine`). */
  sub: string;
  iss: string;
  aud: string[];
  exp: number;
  iat: number;
  nbf?: number;
  jti: string;
  environment_id: string;
  /** The tenant; empty for machine tokens. */
  organization_id?: string;
  application_id: string;
  resource_id: string;
  /** Exact permission strings on the resource. */
  permissions: string[];
  purpose: "application" | "machine" | (string & {});
  /** Session id; absent on machine tokens. */
  sid?: string;
  /** Operator impersonating the user. */
  actor_id?: string;
  /** RFC 8693 actor: the service account impersonating the user. */
  act?: { sub: string };
  oauth_client_id?: string;
  /** How the session signed in: pwd, email, fed, hwk, swk, plus otp/mfa. */
  amr?: string[];
  /** When the user signed in (unix seconds, kept across refreshes). */
  auth_time?: number;
  /** OAuth scopes granted to an OAuth access token. */
  scp?: string[];
}

/** Whether claims carry every one of permissions (exact strings). */
export function hasPermission(claims: AccessClaims, ...permissions: string[]): boolean {
  return permissions.length > 0 && permissions.every((p) => p !== "" && claims.permissions.includes(p));
}

/** Whether the session passed a second factor (amr `mfa`): require it for step-up. */
export function hasMFA(claims: AccessClaims): boolean {
  return claims.amr?.includes("mfa") ?? false;
}

/** Whether an operator (`actor_id`) or a service account (`act`) acts as the user. */
export function isImpersonated(claims: AccessClaims): boolean {
  return Boolean(claims.actor_id) || claims.act !== undefined;
}

/**
 * The boundaries every accepted token must match. Take them from trusted
 * configuration, never from the token or the request.
 */
export interface ExpectedToken {
  /** The deployment's issuer (`JWT_ISSUER`), e.g. `https://iam.example.com`. */
  issuer: string;
  /** The resource's audience. */
  audience: string;
  environmentId: string;
  applicationId: string;
  resourceId: string;
}

/** Resolves a bearer token to trusted claims or throws an IAMKitError (401). */
export interface TokenVerifier {
  verify(token: string): Promise<AccessClaims>;
}

export interface KeySetOptions {
  /** Defaults to `<issuer>/.well-known/jwks.json`. */
  jwksUrl?: string;
  /** The issuer, used for the default jwksUrl. */
  issuer?: string;
  fetch?: FetchLike;
  /** Keys are refetched after this many milliseconds (default 10 minutes). */
  maxAgeMs?: number;
  /** At most one refetch per this many milliseconds on an unknown kid (default 30 s). */
  cooldownMs?: number;
  /** Fetch timeout in milliseconds (default 10 000). */
  timeoutMs?: number;
}

/**
 * IAMKit's published signing keys, cached by kid. Environments rotate keys
 * by publishing the next one before it signs, so a set refreshed on an
 * unknown kid always holds it. Share one key set per process.
 */
export function createKeySet(options: KeySetOptions): JWTVerifyGetKey {
  const url = options.jwksUrl ?? (options.issuer ? `${options.issuer.replace(/\/+$/, "")}/.well-known/jwks.json` : undefined);
  if (!url) {
    throw invalidArgument("jwksUrl or issuer is required");
  }
  const fetcher = options.fetch;
  return createRemoteJWKSet(new URL(url), {
    cacheMaxAge: options.maxAgeMs ?? 10 * 60_000,
    cooldownDuration: options.cooldownMs ?? 30_000,
    timeoutDuration: options.timeoutMs ?? 10_000,
    ...(fetcher ? { [customFetch]: (input: string, init: RequestInit) => fetcher(input, init) } : {}),
  });
}

export interface JwtVerifierOptions extends ExpectedToken {
  /** A shared key set; by default one is created for the issuer. */
  keys?: JWTVerifyGetKey;
  /** Options of the default key set. */
  keySet?: Omit<KeySetOptions, "issuer">;
  /** Allowed clock skew in seconds (default 0). */
  clockToleranceSec?: number;
}

/**
 * Verifies access tokens offline: RS256 signature from the issuer's JWKS,
 * issuer, audience, expiry, environment, application, resource and purpose
 * (`application` tokens need an organization and session, `machine`
 * tokens have neither).
 *
 * Offline verification cannot observe revocation before expiry; use
 * createIntrospectionVerifier where logout, suspension or a permission
 * removal must take effect immediately. Personal access tokens (`ik_pat_`)
 * are not JWTs: exchange them first or introspect them.
 *
 * You still must compare `organization_id` with the tenant a request
 * touches (see requireOrganization).
 */
export function createJwtVerifier(options: JwtVerifierOptions): TokenVerifier {
  requireExpected(options);
  const keys = options.keys ?? createKeySet({ ...options.keySet, issuer: options.issuer });
  return {
    async verify(token: string): Promise<AccessClaims> {
      let payload: JWTPayload;
      try {
        ({ payload } = await jwtVerify(token, keys, {
          algorithms: ["RS256"],
          issuer: options.issuer,
          audience: options.audience,
          requiredClaims: ["exp", "sub"],
          clockTolerance: options.clockToleranceSec ?? 0,
        }));
      } catch (error) {
        throw keyError(error) ?? unauthorized("invalid or expired token");
      }
      const claims = normalize(payload);
      if (claims.environment_id !== options.environmentId || claims.application_id !== options.applicationId || claims.resource_id !== options.resourceId) {
        throw unauthorized("token boundary mismatch");
      }
      switch (claims.purpose) {
        case "application":
          if (!claims.organization_id || !claims.sid) {
            throw unauthorized("missing user session context");
          }
          break;
        case "machine":
          if (claims.organization_id || claims.sid) {
            throw unauthorized("invalid machine context");
          }
          break;
        default:
          throw unauthorized("unsupported token purpose");
      }
      return claims;
    },
  };
}

export interface IntrospectionVerifierOptions extends ExpectedToken {
  /** The deployment origin the SDK calls (may differ from the public issuer). */
  baseUrl: string;
  fetch?: FetchLike;
  timeoutMs?: number;
}

/**
 * Verifies access tokens online with `POST /identity/v1/introspect`: the
 * session, account and grants are checked now, so revocation takes effect
 * at once. If IAMKit is unreachable the call rejects — fail closed, never
 * fall back to decoding the token.
 */
export function createIntrospectionVerifier(options: IntrospectionVerifierOptions): TokenVerifier {
  requireExpected(options);
  const http = new Transport(options);
  return {
    async verify(token: string): Promise<AccessClaims> {
      if (!token) {
        throw unauthorized("missing token");
      }
      let answer: { active: boolean; claims?: Partial<AccessClaims> };
      try {
        answer = await http.json("/identity/v1/introspect", { environment_id: options.environmentId, audience: options.audience }, token);
      } catch (error) {
        if (error instanceof IAMKitError && error.status === 401) {
          throw unauthorized("inactive token");
        }
        throw error;
      }
      const claims = answer.claims ? normalize(answer.claims as JWTPayload) : undefined;
      if (
        !answer.active ||
        !claims ||
        claims.iss !== options.issuer ||
        !claims.aud.includes(options.audience) ||
        claims.environment_id !== options.environmentId ||
        claims.application_id !== options.applicationId ||
        claims.resource_id !== options.resourceId ||
        !claims.sub
      ) {
        throw unauthorized("inactive token or boundary mismatch");
      }
      if (claims.purpose !== "application" && claims.purpose !== "machine") {
        throw unauthorized("invalid token purpose");
      }
      return claims;
    },
  };
}

/** The back-channel logout event every logout token carries. */
export const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

/** A verified OpenID Connect Back-Channel Logout token. */
export interface LogoutToken {
  /** The user whose session ended. */
  sub: string;
  /** The ended session: end your application's session for it. */
  sid: string;
  environment_id?: string;
  jti: string;
  iss: string;
  aud: string[];
  iat: number;
  exp: number;
}

export interface LogoutTokenOptions {
  issuer: string;
  /** The OAuth client the token is addressed to. */
  clientId: string;
  keys: JWTVerifyGetKey;
}

/**
 * Verifies the `logout_token` form field IAMKit POSTs to a client's
 * `backchannel_logout_uri`: RS256 signature, issuer, audience = client,
 * not expired, the back-channel logout event, a `sid` and no `nonce`.
 * Answer 200 when it verifies, 400 otherwise. Replay protection
 * (remembering `jti` until `exp`) is up to the caller.
 */
export async function verifyLogoutToken(token: string, options: LogoutTokenOptions): Promise<LogoutToken> {
  if (!options.issuer || !options.clientId || !options.keys) {
    throw invalidArgument("issuer, clientId and keys are required");
  }
  const invalid = new IAMKitError(400, "UNAUTHORIZED", "invalid logout token");
  let payload: JWTPayload;
  let typ: string | undefined;
  try {
    const verified = await jwtVerify(token, options.keys, {
      algorithms: ["RS256"],
      issuer: options.issuer,
      audience: options.clientId,
      requiredClaims: ["exp", "iat", "sub", "sid", "jti"],
    });
    payload = verified.payload;
    typ = verified.protectedHeader.typ;
  } catch (error) {
    throw keyError(error) ?? invalid;
  }
  const events = payload.events as Record<string, unknown> | undefined;
  const event = events?.[BackchannelLogoutEvent];
  if (typeof event !== "object" || event === null || "nonce" in payload || (typ && typ !== "logout+jwt" && typ !== "JWT")) {
    throw invalid;
  }
  return {
    sub: String(payload.sub),
    sid: String(payload.sid),
    environment_id: typeof payload.environment_id === "string" ? payload.environment_id : undefined,
    jti: String(payload.jti),
    iss: String(payload.iss),
    aud: toList(payload.aud),
    iat: Number(payload.iat),
    exp: Number(payload.exp),
  };
}

/** The claims of a verified ID token. */
export interface IDTokenClaims extends JWTPayload {
  sub: string;
  sid?: string;
  nonce?: string;
  amr?: string[];
  auth_time?: number;
  name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  preferred_username?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  environment_id?: string;
  organization_id?: string;
}

export interface IDTokenOptions {
  issuer: string;
  clientId: string;
  keys: JWTVerifyGetKey;
  /** The nonce of the authorization request (required: IAMKit always sends one). */
  nonce: string;
  clockToleranceSec?: number;
}

/**
 * Verifies an ID token from the authorization code flow: RS256 signature,
 * issuer, audience = client, expiry and the request's nonce. ID tokens
 * identify the user to the client; never accept one as an API access token.
 */
export async function verifyIdToken(token: string, options: IDTokenOptions): Promise<IDTokenClaims> {
  if (!options.issuer || !options.clientId || !options.keys || !options.nonce) {
    throw invalidArgument("issuer, clientId, keys and nonce are required");
  }
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, options.keys, {
      algorithms: ["RS256"],
      issuer: options.issuer,
      audience: options.clientId,
      requiredClaims: ["exp", "iat", "sub"],
      clockTolerance: options.clockToleranceSec ?? 0,
    }));
  } catch (error) {
    throw keyError(error) ?? unauthorized("invalid ID token");
  }
  if (payload.nonce !== options.nonce) {
    throw unauthorized("ID token nonce mismatch");
  }
  return payload as IDTokenClaims;
}

function requireExpected(e: ExpectedToken): void {
  if (!e.issuer || !e.audience || !e.environmentId || !e.applicationId || !e.resourceId) {
    throw invalidArgument("issuer, audience, environmentId, applicationId and resourceId are required");
  }
}

/** A JWKS fetch failure is an outage (503), not a bad token. */
function keyError(error: unknown): IAMKitError | undefined {
  if (error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid || (error instanceof errors.JOSEError && error.code === "ERR_JOSE_GENERIC")) {
    return new IAMKitError(503, "JWKS_UNAVAILABLE", "signing keys could not be fetched");
  }
  if (error instanceof TypeError || (error instanceof Error && error.name === "AbortError")) {
    return new IAMKitError(503, "JWKS_UNAVAILABLE", "signing keys could not be fetched");
  }
  return undefined;
}

function normalize(payload: JWTPayload): AccessClaims {
  const p = payload as Record<string, unknown>;
  const text = (key: string) => (typeof p[key] === "string" && p[key] !== "" ? (p[key] as string) : undefined);
  const list = (key: string) => (Array.isArray(p[key]) ? (p[key] as unknown[]).filter((v): v is string => typeof v === "string") : undefined);
  const act = p.act as { sub?: unknown } | undefined;
  const actorAccount = text("actor_account_id");
  return {
    sub: text("sub") ?? "",
    iss: text("iss") ?? "",
    aud: toList(p.aud),
    exp: Number(p.exp ?? 0),
    iat: Number(p.iat ?? 0),
    nbf: typeof p.nbf === "number" ? p.nbf : undefined,
    jti: text("jti") ?? "",
    environment_id: text("environment_id") ?? "",
    organization_id: text("organization_id"),
    application_id: text("application_id") ?? "",
    resource_id: text("resource_id") ?? "",
    permissions: list("permissions") ?? [],
    purpose: text("purpose") ?? "",
    sid: text("sid"),
    actor_id: text("actor_id"),
    act: act && typeof act.sub === "string" ? { sub: act.sub } : actorAccount ? { sub: actorAccount } : undefined,
    oauth_client_id: text("oauth_client_id"),
    amr: list("amr"),
    auth_time: typeof p.auth_time === "number" && p.auth_time > 0 ? p.auth_time : undefined,
    scp: list("scp"),
  };
}

function toList(aud: unknown): string[] {
  if (typeof aud === "string") {
    return [aud];
  }
  return Array.isArray(aud) ? aud.filter((v): v is string => typeof v === "string") : [];
}
