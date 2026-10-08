import { createHash, createPrivateKey, randomBytes, type KeyObject } from "node:crypto";
import { SignJWT } from "jose";
import { IAMKitError, invalidArgument } from "./errors.js";
import { Transport, type FetchLike } from "./http.js";

/** Grant and token types IAMKit's `/oauth/token` understands. */
export const GrantTypes = {
  AuthorizationCode: "authorization_code",
  RefreshToken: "refresh_token",
  ClientCredentials: "client_credentials",
  DeviceCode: "urn:ietf:params:oauth:grant-type:device_code",
  TokenExchange: "urn:ietf:params:oauth:grant-type:token-exchange",
  JWTBearer: "urn:ietf:params:oauth:grant-type:jwt-bearer",
} as const;

export const TokenTypes = {
  /** Subject type of exchangeToken and type of every issued token. */
  AccessToken: "urn:ietf:params:oauth:token-type:access_token",
  /** Subject type of impersonate. */
  UserId: "urn:iamkit:params:oauth:token-type:user_id",
} as const;

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** A token endpoint answer. */
export interface OAuthTokens {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

/** A token exchange answer: an access token only. */
export interface ExchangedToken {
  access_token: string;
  issued_token_type: string;
  token_type: string;
  expires_in: number;
}

/** OIDC UserInfo; fields beyond `sub`/`environment_id` depend on the granted scopes. */
export interface UserInfo {
  sub: string;
  environment_id: string;
  organization_id?: string;
  name?: string;
  picture?: string;
  preferred_username?: string;
  email?: string;
  email_verified?: boolean;
  phone_number?: string;
  phone_number_verified?: boolean;
  [claim: string]: unknown;
}

/** RFC 7662 answer; inactive tokens only set `active`. */
export interface Introspection {
  active: boolean;
  sub?: string;
  client_id?: string;
  scope?: string;
  token_type?: string;
  token_use?: "access_token" | "refresh_token";
  aud?: string[];
  iss?: string;
  exp?: number;
  iat?: number;
  environment_id?: string;
  organization_id?: string;
  application_id?: string;
  resource_id?: string;
  permissions?: string[];
  sid?: string;
  amr?: string[];
  auth_time?: number;
}

/** RFC 8628 device authorization: show `user_code` and `verification_uri`, then wait. */
export interface DeviceAuthorization {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

/** A PKCE pair (RFC 7636, S256). Keep the verifier server-side until the callback. */
export interface PKCE {
  verifier: string;
  challenge: string;
}

/** A private key: PEM (PKCS #8, PKCS #1 or SEC 1) or a Node KeyObject. */
export type PrivateKeyInput = string | KeyObject;

/** Client authentication at the token endpoint. */
export type ClientAuth =
  | { method: "none" }
  | { method: "client_secret_basic"; secret: string }
  | { method: "client_secret_post"; secret: string }
  | {
      method: "private_key_jwt";
      key: PrivateKeyInput;
      /** The key's id in the client's registered key set. */
      kid: string;
      /** The registered signing algorithm (default: RS256, or the curve's ES algorithm). */
      alg?: string;
    };

export interface OAuthClientOptions {
  /** The deployment origin, e.g. `https://iam.example.com`. */
  baseUrl: string;
  /** OAuth client ID, or a service account ID for client_credentials. */
  clientId: string;
  /** Shorthand for `{ method: "client_secret_basic", secret }`. */
  clientSecret?: string;
  /** Overrides clientSecret; default `none` (public client with PKCE). */
  auth?: ClientAuth;
  /**
   * The issuer whose `/oauth/token` assertions are addressed to (default
   * baseUrl). Set it when the SDK reaches IAMKit at another origin than
   * the public one.
   */
  issuer?: string;
  fetch?: FetchLike;
  timeoutMs?: number;
}

export interface AuthorizeOptions {
  redirectUri: string;
  /** At least 8 characters; compare it on the callback. */
  state: string;
  nonce: string;
  /** The PKCE challenge (S256). */
  codeChallenge: string;
  /** Default `openid`; `openid` is always included. */
  scopes?: string[];
  /** Organization hint: brands the hosted pages and limits the sign-in to it. */
  organizationId?: string;
  /** Extra query parameters (e.g. `ui_locales`). */
  extra?: Record<string, string>;
}

/** Creates a PKCE verifier (43 characters) and its S256 challenge. */
export function createPKCE(): PKCE {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

/** A random URL-safe value for `state` or `nonce`. */
export function randomToken(bytes = 24): string {
  return randomBytes(bytes).toString("base64url");
}

/**
 * The OAuth 2.0 / OIDC endpoints for a server-side client: authorization
 * code + PKCE, refresh, revocation, UserInfo, introspection,
 * client_credentials, device authorization, token exchange and
 * impersonation. Failures throw IAMKitError with the OAuth `error` as code.
 */
export class OAuthClient {
  readonly clientId: string;
  private readonly http: Transport;
  private readonly auth: ClientAuth;
  private readonly tokenAudience: string;
  private signer?: Promise<{ key: KeyObject; alg: string }>;

  constructor(options: OAuthClientOptions) {
    if (!options.clientId) {
      throw invalidArgument("clientId is required");
    }
    this.http = new Transport(options);
    this.clientId = options.clientId;
    this.auth = options.auth ?? (options.clientSecret ? { method: "client_secret_basic", secret: options.clientSecret } : { method: "none" });
    this.tokenAudience = `${(options.issuer ?? options.baseUrl).replace(/\/+$/, "")}/oauth/token`;
  }

  /** The `/oauth/authorize` URL to redirect the browser to. */
  authorizationUrl(options: AuthorizeOptions): string {
    if (!options.state || options.state.length < 8) {
      throw invalidArgument("state must have at least 8 characters");
    }
    if (!options.nonce || !options.codeChallenge || !options.redirectUri) {
      throw invalidArgument("redirectUri, nonce and codeChallenge are required");
    }
    const scopes = new Set(["openid", ...(options.scopes ?? [])]);
    const query = new URLSearchParams({
      ...options.extra,
      client_id: this.clientId,
      response_type: "code",
      redirect_uri: options.redirectUri,
      scope: [...scopes].join(" "),
      state: options.state,
      nonce: options.nonce,
      code_challenge: options.codeChallenge,
      code_challenge_method: "S256",
    });
    if (options.organizationId) {
      query.set("organization_id", options.organizationId);
    }
    return `${this.http.baseUrl}/oauth/authorize?${query}`;
  }

  /** Trades the callback's code for tokens. */
  exchangeCode(code: string, redirectUri: string, codeVerifier: string): Promise<OAuthTokens> {
    return this.token({ grant_type: GrantTypes.AuthorizationCode, code, redirect_uri: redirectUri, code_verifier: codeVerifier });
  }

  /** Exchanges a refresh token (rotated: store the new one). */
  refresh(refreshToken: string): Promise<OAuthTokens> {
    return this.token({ grant_type: GrantTypes.RefreshToken, refresh_token: refreshToken });
  }

  /** A service account's access token (clientId = account ID, secret `ik_svc_…` or private_key_jwt). */
  clientCredentials(): Promise<OAuthTokens> {
    return this.token({ grant_type: GrantTypes.ClientCredentials });
  }

  /** Revokes an access or refresh token. */
  async revoke(token: string): Promise<void> {
    await this.post("/oauth/revoke", { token });
  }

  /** Reads the signed-in user's claims with an OAuth access token (`openid` scope). */
  userInfo(accessToken: string): Promise<UserInfo> {
    return this.http.get<UserInfo>("/oauth/userinfo", accessToken);
  }

  /**
   * RFC 7662 introspection of an access or refresh token of this client's
   * environment (also opaque `ory_at_` tokens). Needs a confidential
   * client with a secret (HTTP Basic).
   */
  introspect(token: string): Promise<Introspection> {
    if (this.auth.method !== "client_secret_basic" && this.auth.method !== "client_secret_post") {
      return Promise.reject(new IAMKitError(401, "invalid_client", "introspection needs a confidential client with a secret"));
    }
    const basic = { Authorization: basicAuth(this.clientId, this.auth.secret) };
    return this.http.form<Introspection>("/oauth/introspect", new URLSearchParams({ token }), basic);
  }

  /** Starts a device authorization (client grant_types must include the device code grant). */
  authorizeDevice(scopes: string[] = []): Promise<DeviceAuthorization> {
    return this.post<DeviceAuthorization>("/oauth/device_authorization", scopes.length ? { scope: scopes.join(" ") } : {});
  }

  /** Polls once; until the user decides it throws `authorization_pending` or `slow_down`. */
  pollDevice(deviceCode: string): Promise<OAuthTokens> {
    return this.token({ grant_type: GrantTypes.DeviceCode, device_code: deviceCode });
  }

  /**
   * Polls at the authorization's interval (five seconds more after each
   * `slow_down`) until the user approves, denies (`access_denied`), the code
   * expires (`expired_token`) or signal aborts.
   */
  async waitForDevice(authorization: DeviceAuthorization, options: { signal?: AbortSignal; stepMs?: number } = {}): Promise<OAuthTokens> {
    const step = options.stepMs ?? 1000;
    let interval = (authorization.interval > 0 ? authorization.interval : 5) * step;
    for (;;) {
      await sleep(interval, options.signal);
      try {
        return await this.pollDevice(authorization.device_code);
      } catch (error) {
        if (!(error instanceof IAMKitError)) {
          throw error;
        }
        if (error.code === "slow_down") {
          interval += 5 * step;
        } else if (error.code !== "authorization_pending") {
          throw error;
        }
      }
    }
  }

  /**
   * RFC 8693: turns a user's access token into one for another resource
   * (audience) of the same application. The client must be confidential
   * with the token exchange grant; permissions narrow the new token.
   */
  exchangeToken(subjectToken: string, audience: string, permissions: string[] = []): Promise<ExchangedToken> {
    const form: Record<string, string> = {
      grant_type: GrantTypes.TokenExchange,
      subject_token: subjectToken,
      subject_token_type: TokenTypes.AccessToken,
      audience,
    };
    if (permissions.length) {
      form.scope = permissions.join(" ");
    }
    return this.token(form);
  }

  /**
   * A service account allowed to impersonate (`can_impersonate`) gets a
   * token acting as user in organization; its `act` claim names the
   * account. The reason is audited.
   */
  impersonate(user: string, organization: string, reason: string): Promise<ExchangedToken> {
    return this.token({
      grant_type: GrantTypes.TokenExchange,
      subject_token: user,
      subject_token_type: TokenTypes.UserId,
      organization_id: organization,
      reason,
    });
  }

  /**
   * The RP-initiated logout URL. postLogoutRedirectUri must be registered
   * on the client; without it IAMKit shows its "Signed out" page.
   */
  endSessionUrl(options: { idTokenHint?: string; postLogoutRedirectUri?: string; state?: string } = {}): string {
    const query = new URLSearchParams({ client_id: this.clientId });
    if (options.idTokenHint) query.set("id_token_hint", options.idTokenHint);
    if (options.postLogoutRedirectUri) query.set("post_logout_redirect_uri", options.postLogoutRedirectUri);
    if (options.state) query.set("state", options.state);
    return `${this.http.baseUrl}/oauth/end_session?${query}`;
  }

  private token<T = OAuthTokens>(form: Record<string, string>): Promise<T> {
    return this.post<T>("/oauth/token", form);
  }

  private async post<T = void>(path: string, fields: Record<string, string>): Promise<T> {
    const form = new URLSearchParams({ ...fields, client_id: this.clientId });
    const headers: Record<string, string> = {};
    switch (this.auth.method) {
      case "client_secret_basic":
        headers.Authorization = basicAuth(this.clientId, this.auth.secret);
        break;
      case "client_secret_post":
        form.set("client_secret", this.auth.secret);
        break;
      case "private_key_jwt":
        form.set("client_assertion_type", clientAssertionType);
        form.set("client_assertion", await this.assertion());
        break;
    }
    return this.http.form<T>(path, form, headers);
  }

  private async assertion(): Promise<string> {
    const auth = this.auth as Extract<ClientAuth, { method: "private_key_jwt" }>;
    this.signer ??= loadKey(auth.key, auth.alg);
    const { key, alg } = await this.signer;
    return signAssertion(key, alg, auth.kid, this.clientId, this.tokenAudience);
  }
}

export interface KeyLoginOptions {
  baseUrl: string;
  /** The machine user's ID. */
  userId: string;
  /** The key's ID (from `POST …/users/:id/keys`). */
  kid: string;
  /** The private half: the PEM IAMKit returned when it generated the pair, or your own. */
  privateKey: PrivateKeyInput;
  /** Where the assertion is addressed (default baseUrl). */
  issuer?: string;
  fetch?: FetchLike;
  timeoutMs?: number;
}

/** Where a key login's session opens; environmentId defaults to the key's. */
export interface KeyBoundary {
  organizationId: string;
  applicationId: string;
  resourceId: string;
  environmentId?: string;
}

/**
 * Signs a machine user in with one of its keys (RFC 7523 JWT-bearer grant,
 * no OAuth client): each call signs a fresh one-minute assertion. There is
 * no refresh token; sign in again when the access token expires.
 */
export class KeyLogin {
  private readonly http: Transport;
  private readonly options: KeyLoginOptions;
  private readonly audience: string;
  private signer?: Promise<{ key: KeyObject; alg: string }>;

  constructor(options: KeyLoginOptions) {
    if (!options.userId || !options.kid || !options.privateKey) {
      throw invalidArgument("userId, kid and privateKey are required");
    }
    this.http = new Transport(options);
    this.options = options;
    this.audience = `${(options.issuer ?? options.baseUrl).replace(/\/+$/, "")}/oauth/token`;
  }

  /** A fresh signed assertion. */
  async assertion(): Promise<string> {
    this.signer ??= loadKey(this.options.privateKey);
    const { key, alg } = await this.signer;
    return signAssertion(key, alg, this.options.kid, this.options.userId, this.audience);
  }

  /** Trades a fresh assertion for an application access token in boundary. */
  async token(boundary: KeyBoundary): Promise<OAuthTokens> {
    const form = new URLSearchParams({
      grant_type: GrantTypes.JWTBearer,
      assertion: await this.assertion(),
      organization_id: boundary.organizationId,
      application_id: boundary.applicationId,
      resource_id: boundary.resourceId,
    });
    if (boundary.environmentId) {
      form.set("environment_id", boundary.environmentId);
    }
    return this.http.form<OAuthTokens>("/oauth/token", form);
  }
}

const assertionAlgorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];

async function loadKey(input: PrivateKeyInput, alg?: string): Promise<{ key: KeyObject; alg: string }> {
  let key: KeyObject;
  try {
    key = typeof input === "string" ? createPrivateKey(input) : input;
  } catch {
    throw invalidArgument("not a PEM RSA or EC private key");
  }
  if (key.type !== "private") {
    throw invalidArgument("a private key is required");
  }
  const chosen = alg ?? defaultAlg(key);
  if (!chosen || !assertionAlgorithms.includes(chosen)) {
    throw invalidArgument("key must be an RSA or EC (P-256, P-384, P-521) private key");
  }
  return { key, alg: chosen };
}

function defaultAlg(key: KeyObject): string | undefined {
  if (key.asymmetricKeyType === "rsa") {
    return "RS256";
  }
  if (key.asymmetricKeyType === "ec") {
    const curve = key.asymmetricKeyDetails?.namedCurve;
    return curve === "prime256v1" ? "ES256" : curve === "secp384r1" ? "ES384" : curve === "secp521r1" ? "ES512" : undefined;
  }
  return undefined;
}

function signAssertion(key: KeyObject, alg: string, kid: string, subject: string, audience: string): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg, kid, typ: "JWT" })
    .setIssuer(subject)
    .setSubject(subject)
    .setAudience(audience)
    .setJti(randomBytes(16).toString("base64url"))
    .setIssuedAt()
    .setExpirationTime("1m")
    .sign(key);
}

function basicAuth(id: string, secret: string): string {
  // RFC 6749 §2.3.1: form-encode both parts before base64.
  const encode = (v: string) => encodeURIComponent(v).replace(/%20/g, "+");
  return `Basic ${Buffer.from(`${encode(id)}:${encode(secret)}`).toString("base64")}`;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, ms);
    const abort = () => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    signal?.addEventListener("abort", abort, { once: true });
  });
}
