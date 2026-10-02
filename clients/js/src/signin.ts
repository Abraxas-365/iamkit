import type { IAMKitClient, operations, Schema } from "@iamkit/api";
import { IAMKitError, toError } from "./errors.js";
import { done, transport, unwrap, type TransportOptions } from "./http.js";
import { challengeOf, createVerifier } from "./pkce.js";
import { getAssertion } from "./webauthn.js";

type Json<Op extends keyof operations, Status extends number> = operations[Op]["responses"] extends Record<Status, { content: { "application/json": infer T } }> ? T : never;
type SignInAnswer = Json<"postIdentityLogin", 200>;

/** What `GET /identity/v1/authorize/:ticket` describes: client, methods, branding, texts. */
export type Authorization = Schema<"Authorization">;
/** The sign-in methods a ticket offers. */
export type Methods = Schema<"Methods">;
export type Branding = Schema<"Branding">;
export type Connection = Schema<"ConnectionSummary">;
export type Discovery = Schema<"FederationDiscovery">;
export type InvitationPreview = Schema<"InvitationPreview">;
export type InvitationAccepted = Schema<"Accepted">;
export type CodeSent = Schema<"CodeSent">;
export type Enrollment = Schema<"AuthenticationEnrollment">;
export type SignedUp = Schema<"SignedUp">;
export type Organization = Schema<"AuthenticationOrganization">;

/** An access/refresh token pair (+ recovery codes after a first enrollment). */
export type Tokens = Extract<SignInAnswer, { access_token: string }>;
/** A pending second factor: answer it with the `mfa` calls. */
export type MFAPending = Extract<SignInAnswer, { mfa_token: string }>;

/** The result of every sign-in step. */
export type SignInResult = { status: "signed_in"; tokens: Tokens } | { status: "mfa_required"; mfa: MFAPending };

/** What `GET /oauth/authorize` answers a client without hosted login. */
export type AuthorizationStart = Json<"getOauthAuthorize", 200>;

/**
 * Where a session is issued: the environment, organization, application
 * and resource. Every sign-in call carries it.
 */
export interface Boundary {
  environmentId: string;
  organizationId: string;
  applicationId: string;
  resourceId: string;
}

interface ContextBody {
  environment_id: string;
  organization_id: string;
  application_id: string;
  resource_id: string;
}

function context(b: Boundary): ContextBody {
  return { environment_id: b.environmentId, organization_id: b.organizationId, application_id: b.applicationId, resource_id: b.resourceId };
}

/** Builds the boundary of an authorization for an organization. */
export function boundaryOf(authorization: Pick<Authorization, "environment_id" | "application_id" | "resource_id">, organizationId: string): Boundary {
  return { environmentId: authorization.environment_id, organizationId, applicationId: authorization.application_id, resourceId: authorization.resource_id };
}

/** Normalizes the anyOf sign-in answer. */
export function signInResult(answer: SignInAnswer): SignInResult {
  if ("mfa_token" in answer && answer.mfa_token) {
    return { status: "mfa_required", mfa: answer as MFAPending };
  }
  return { status: "signed_in", tokens: answer as Tokens };
}

/** Where the federation start keeps its verifier until the UI comes back. */
export interface VerifierStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface SignInOptions extends TransportOptions {
  /**
   * Keeps the PKCE verifier of a federation start across the provider
   * round trip. Defaults to `sessionStorage` in browsers.
   */
  storage?: VerifierStore;
}

const verifierKey = "iamkit.federation.verifier";

/**
 * Browser sign-in flows of the IAMKit identity API for custom sign-in UIs,
 * mirroring the hosted pages: describe the authorize ticket, sign in with a
 * password, an emailed code, a passkey or single sign-on, answer the second
 * factor, then complete the OAuth authorization with the user token.
 *
 * Nothing is persisted except the federation verifier: tokens are returned
 * to the caller, who passes the access token to `complete`.
 */
export class SignIn {
  readonly client: IAMKitClient;
  private readonly baseUrl: string;
  private readonly fetcher: typeof fetch;
  private readonly storage?: VerifierStore;

  constructor(options: SignInOptions) {
    this.client = transport(options);
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.fetcher = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.storage = options.storage ?? (typeof sessionStorage !== "undefined" ? sessionStorage : undefined);
  }

  /**
   * Starts an OAuth authorization from the browser with the relying
   * application's query (`client_id`, `redirect_uri`, `code_challenge`, …).
   * IAMKit answers the ticket and binds it to this browser with a cookie;
   * hosted-login clients are refused (they redirect to IAMKit's pages).
   */
  async authorize(query: string | URLSearchParams | Record<string, string>): Promise<AuthorizationStart> {
    const search = new URLSearchParams(query as Record<string, string>).toString();
    const response = await this.fetcher(`${this.baseUrl}/oauth/authorize?${search}`, {
      credentials: "include",
      redirect: "manual",
      headers: { Accept: "application/json" },
    });
    if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
      throw new IAMKitError(response.status || 303, "HOSTED_LOGIN", "this client signs in on IAMKit's hosted pages");
    }
    const body = await response.json().catch(() => undefined);
    if (!response.ok) {
      throw toError(response.status, body);
    }
    return body as AuthorizationStart;
  }

  /** Describes a ticket (needs the browser binding cookie from `authorize`). */
  authorization(ticket: string): Promise<Authorization> {
    return unwrap(this.client.GET("/identity/v1/authorize/{ticket}", { params: { path: { ticket } } }));
  }

  /**
   * Single sign-on routing by email domain: `method: "sso"` names the
   * organization and connection; `provider: "ldap"` signs in with a
   * password through `ldap`.
   */
  discover(environmentId: string, email: string): Promise<Discovery> {
    return unwrap(this.client.POST("/identity/v1/discover", { body: { environment_id: environmentId, email } }));
  }

  /**
   * Password sign-in with an email or username. Pass `newPassword` after a
   * `PASSWORD_CHANGE_REQUIRED` error to replace an expired password.
   */
  async login(boundary: Boundary, input: { login: string; password: string; newPassword?: string }): Promise<SignInResult> {
    const answer = await unwrap(this.client.POST("/identity/v1/login", { body: { ...context(boundary), login: input.login, password: input.password, new_password: input.newPassword } }));
    return signInResult(answer);
  }

  /**
   * Emails a one-time code: `login` signs in (`verifyCode`), `password_reset`
   * resets the password (`resetPassword`). The answer is the same whether
   * or not the account exists.
   */
  async sendCode(input: { environmentId: string; login: string; purpose: "login" | "password_reset"; locale?: string }): Promise<{ challengeId: string; expiresIn: number }> {
    const out = await unwrap(this.client.POST("/identity/v1/challenges", { body: { environment_id: input.environmentId, login: input.login, purpose: input.purpose, locale: input.locale } }));
    return { challengeId: out.challenge_id, expiresIn: out.expires_in };
  }

  /** Signs in with an emailed code. */
  async verifyCode(boundary: Boundary, input: { challengeId: string; code: string }): Promise<SignInResult> {
    const { data, error, response } = await this.client.POST("/identity/v1/challenges/verify", { body: { ...context(boundary), challenge_id: input.challengeId, code: input.code, purpose: "login" } });
    if (!response.ok || !data) {
      throw toError(response.status, error);
    }
    return signInResult(data);
  }

  /** Sets a new password with a `password_reset` code. */
  resetPassword(input: { environmentId: string; challengeId: string; code: string; password: string }): Promise<void> {
    return done(this.client.POST("/identity/v1/challenges/verify", { body: { environment_id: input.environmentId, challenge_id: input.challengeId, code: input.code, password: input.password, purpose: "password_reset" } }));
  }

  /**
   * Signs in with a passkey: the browser prompts (or, with
   * `mediation: "conditional"`, offers passkeys in the username autofill).
   * Resolves null when the user dismissed the prompt.
   */
  async passkey(boundary: Boundary, init: { signal?: AbortSignal; mediation?: CredentialMediationRequirement } = {}): Promise<SignInResult | null> {
    const begin = await unwrap(this.client.POST("/identity/v1/passkeys/login/begin", { body: { environment_id: boundary.environmentId } }));
    const credential = await getAssertion(begin.options, init);
    if (!credential) {
      return null;
    }
    const answer = await unwrap(this.client.POST("/identity/v1/passkeys/login/finish", { body: { ...context(boundary), webauthn_session: begin.webauthn_session, credential } }));
    return signInResult(answer);
  }

  /** Second-factor steps of a pending sign-in. */
  readonly mfa = {
    /** Answers with an authenticator, emailed or texted code, or a recovery code. */
    verify: async (mfaToken: string, code: string): Promise<Tokens> => unwrap(this.client.POST("/identity/v1/mfa/verify", { body: { mfa_token: mfaToken, code } })),
    /** Sends a code to the user's email or phone factor. */
    send: async (mfaToken: string, factor: "email" | "sms"): Promise<CodeSent> => unwrap(this.client.POST("/identity/v1/mfa/challenge", { body: { mfa_token: mfaToken, factor } })),
    /** Starts authenticator enrollment (`enrollment_required`): show the URI as a QR code, then `verify`. */
    enroll: async (mfaToken: string): Promise<Enrollment> => unwrap(this.client.POST("/identity/v1/mfa/enroll", { body: { mfa_token: mfaToken } })),
    /** Answers with a security key; null when the user dismissed the prompt. */
    securityKey: async (mfaToken: string, init: { signal?: AbortSignal } = {}): Promise<Tokens | null> => {
      const begin = await unwrap(this.client.POST("/identity/v1/mfa/webauthn", { body: { mfa_token: mfaToken } }));
      const credential = await getAssertion(begin.options, init);
      if (!credential) {
        return null;
      }
      return unwrap(this.client.POST("/identity/v1/mfa/verify", { body: { mfa_token: mfaToken, webauthn_session: begin.webauthn_session, credential } }));
    },
  };

  /** Single sign-on that returns to this UI. */
  readonly federation = {
    /**
     * Starts single sign-on and returns the provider URL to navigate to.
     * The verifier stays in `storage`; IAMKit only sees its S256 challenge.
     * `returnTo` must be on an origin of an OAuth client of the application
     * (`allowed_origins`).
     */
    start: async (boundary: Boundary, input: { connectionId: string; returnTo: string }): Promise<string> => {
      const verifier = createVerifier();
      const store = this.requireStorage();
      store.setItem(verifierKey, verifier);
      const out = await unwrap(this.client.POST("/identity/v1/federation/start", { body: { ...context(boundary), connection_id: input.connectionId, return_to: input.returnTo, code_challenge: await challengeOf(verifier) } }));
      return out.authorization_url;
    },
    /**
     * Finishes single sign-on on the `returnTo` page: redeems
     * `federation_result` with the stored verifier, or throws the
     * provider/IAMKit error. Resolves null when the URL carries neither.
     */
    finish: async (location: string | URL | URLSearchParams): Promise<SignInResult | null> => {
      const query = location instanceof URLSearchParams ? location : new URL(location.toString()).searchParams;
      const error = query.get("error");
      const result = query.get("federation_result");
      if (!error && !result) {
        return null;
      }
      const store = this.requireStorage();
      const verifier = store.getItem(verifierKey);
      store.removeItem(verifierKey);
      if (error) {
        throw new IAMKitError(400, error, query.get("error_description") ?? error);
      }
      if (!verifier) {
        throw new IAMKitError(401, "FEDERATION_VERIFIER_MISSING", "single sign-on was started in another browser tab or session");
      }
      const answer = await unwrap(this.client.POST("/identity/v1/federation/result", { body: { federation_result: result!, code_verifier: verifier } }));
      return signInResult(answer);
    },
    /** Signs in with an organization's LDAP directory (discovery `provider: "ldap"`). */
    ldap: async (boundary: Boundary, input: { connectionId: string; email: string; password: string }): Promise<SignInResult> => {
      const answer = await unwrap(this.client.POST("/identity/v1/federation/ldap/login", { body: { ...context(boundary), connection_id: input.connectionId, email: input.email, password: input.password } }));
      return signInResult(answer);
    },
  };

  /** Self-service sign-up (when the sign-in policy allows it). */
  readonly signup = {
    /** Emails a verification code; the same answer for existing accounts. */
    start: async (input: { environmentId: string; email: string; name: string; password?: string; locale?: string; acceptTerms?: boolean }): Promise<{ challengeId: string; expiresIn: number }> => {
      const out = await unwrap(this.client.POST("/identity/v1/signup", { body: { environment_id: input.environmentId, email: input.email, name: input.name, password: input.password, locale: input.locale, accept_terms: input.acceptTerms } }));
      return { challengeId: out.challenge_id, expiresIn: out.expires_in };
    },
    /** Creates the account (no session: sign in next). */
    verify: async (input: { environmentId: string; challengeId: string; code: string }): Promise<SignedUp> =>
      unwrap(this.client.POST("/identity/v1/signup/verify", { body: { environment_id: input.environmentId, challenge_id: input.challengeId, code: input.code } })),
  };

  /** Organization invitations (the token from the invitation link). */
  readonly invitation = {
    preview: async (token: string): Promise<InvitationPreview> => unwrap(this.client.POST("/identity/v1/invitations/preview", { body: { token } })),
    /** Accepts; new users choose a name and (unless SSO is required) a password. No session. */
    accept: async (input: { token: string; name?: string; password?: string }): Promise<InvitationAccepted> => unwrap(this.client.POST("/identity/v1/invitations/accept", { body: input })),
  };

  /** Organizations the token's user may sign in to for its application. */
  organizations(accessToken: string, input: { environmentId: string; audience: string }): Promise<Organization[]> {
    return unwrap(
      this.client.GET("/identity/v1/organizations", { params: { query: { environment_id: input.environmentId, audience: input.audience } }, headers: { Authorization: `Bearer ${accessToken}` } }),
    ).then((list) => list ?? []);
  }

  /**
   * Completes the authorization with the signed-in user's access token and
   * returns the URL to navigate to (the client's redirect URI with the
   * code, or with `error=access_denied` when `approve` is false). Runs in
   * the browser that called `authorize`: the ticket is bound to it.
   */
  async complete(ticket: string, accessToken: string, approve = true): Promise<string> {
    const out = await unwrap(
      this.client.POST("/oauth/authorize/complete", {
        body: { authorization_ticket: ticket, approve },
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      }),
    );
    return (out as Schema<"Completion">).redirect_to;
  }

  private requireStorage(): VerifierStore {
    if (!this.storage) {
      throw new Error("no storage for the federation verifier: pass `storage`");
    }
    return this.storage;
  }
}

/** Creates the sign-in flows for an IAMKit deployment. */
export function createSignIn(options: SignInOptions): SignIn {
  return new SignIn(options);
}
