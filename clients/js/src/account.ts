import type { IAMKitClient, Schema } from "@iamkit/api";
import { IAMKitError, toError } from "./errors.js";
import { transport, type TransportOptions } from "./http.js";
import { base64url, fromBase64url } from "./pkce.js";
import type { Boundary, Organization, Tokens } from "./signin.js";
import { getAssertion } from "./webauthn.js";

/** The signed-in user (`GET /identity/v1/me`). */
export type Profile = Schema<"Profile">;
/** One of the user's live sessions; `current` marks the one of the token that asked. */
export type Session = Schema<"UserSession">;
/** A second factor, security key or passkey of the user. */
export type Factor = Schema<"Factor">;
/** The user's factors with the recovery codes left and, when locked, until when. */
export type FactorSummary = Omit<Schema<"MfaSummary">, "factors"> & { factors: Factor[] };
/** A user API key (the secret is only in `IssuedApiKey.value`). */
export type ApiKey = Schema<"APIKey">;
/** A freshly created API key: `value` is shown once. */
export type IssuedApiKey = Schema<"Issued">;
/** What the user may create (`enabled`, `max_ttl_days`, resources and their permissions). */
export type ApiKeyOptions = Schema<"Options">;
export type NewApiKey = Schema<"NewAPIKeyInput">;
/** Where a code was sent (masked) and when it expires. */
export type CodeSent = Schema<"CodeSent">;
/** The pending authenticator of `mfa.totp.start`. */
export type TotpEnrollment = Schema<"Enrollment">;
/** Paging info of a list. */
export type Page = Schema<"Page">;
export type { Organization };

/** A page of the user's sessions. */
export interface SessionPage {
  items: Session[];
  page: Page;
}

/** A page of the user's API keys. */
export interface ApiKeyPage {
  items: ApiKey[];
  page: Page;
}

/** Filters of `apiKeys.list`. */
export interface ApiKeyFilter {
  limit?: number;
  offset?: number;
  search?: string;
  state?: string;
  resourceId?: string;
}

/** The result of `changePassword`. */
export interface PasswordChanged {
  /** How many of the user's other sessions ended; the current one stays. */
  sessions_revoked: number;
}

/** A WebAuthn ceremony started by the server (`options` go to the browser). */
export interface WebAuthnCeremony {
  webauthn_session: string;
  options: unknown;
  expires_at: string;
}

/** A security key or passkey that was registered, with the recovery codes of a first factor. */
export interface WebAuthnRegistration {
  factor: Factor;
  recovery_codes: string[] | null;
}

/** Proof of possession for removals: a code (any active factor or a recovery code), or a key assertion. */
export type Proof = { code: string } | { webauthnSession: string; credential: unknown };

export interface AccountOptions extends TransportOptions {
  /** The environment the user signed in to. */
  environmentId: string;
  /** The audience of the user's access token (the application's resource). */
  audience: string;
  /**
   * The user's current access token. Called before every request, so a
   * refreshing implementation always hands over a live token.
   */
  getAccessToken: () => string | Promise<string>;
}

/** `details.reason` of the 403 that refuses an organization switch. */
export type SwitchReason = "sso" | "mfa" | "method" | (string & {});

/** Whether the error asks the user to sign in again (`REAUTHENTICATION_REQUIRED`). */
export function isReauthenticationRequired(error: unknown): error is IAMKitError {
  return error instanceof IAMKitError && error.code === "REAUTHENTICATION_REQUIRED";
}

/**
 * The organization of a refused switch (`details.organization_id`) and why
 * (`details.reason`), or undefined when the error is something else.
 */
export function switchRefusal(error: unknown): { organizationId: string; reason: SwitchReason } | undefined {
  if (!isReauthenticationRequired(error) || typeof error.details?.organization_id !== "string") {
    return undefined;
  }
  return { organizationId: error.details.organization_id, reason: String(error.details.reason ?? "") };
}

type Query = Record<string, string | number | undefined>;
type Method = "GET" | "POST" | "PATCH" | "DELETE";

function claimsOf(token: string): Record<string, unknown> {
  const part = token.split(".")[1];
  try {
    if (part) {
      return JSON.parse(new TextDecoder().decode(fromBase64url(part))) as Record<string, unknown>;
    }
  } catch {
    // fall through
  }
  throw new IAMKitError(400, "VALIDATION", "the access token is not a readable JWT: pass `boundary` to switchOrganization");
}

function parse(text: string): unknown {
  try {
    return text ? JSON.parse(text) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Self-service calls of the signed-in user: profile, phone, sessions,
 * password, API keys, second factors, passkeys and organizations, over
 * `/identity/v1`. Every call reads the token from `getAccessToken`;
 * nothing is stored. Failures throw `IAMKitError` (`code`, `status`,
 * `details`): password, phone, API key and factor changes need a recent
 * sign-in and throw `REAUTHENTICATION_REQUIRED` (`isReauthenticationRequired`)
 * otherwise.
 */
export class Account {
  /** The generated client, for routes this class does not wrap. */
  readonly client: IAMKitClient;
  private readonly environmentId: string;
  private readonly audience: string;
  private readonly baseUrl: string;
  private readonly token: AccountOptions["getAccessToken"];
  private readonly fetcher: typeof fetch;

  constructor(options: AccountOptions) {
    this.client = transport(options);
    this.environmentId = options.environmentId;
    this.audience = options.audience;
    this.token = options.getAccessToken;
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.fetcher = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  }

  private scope(): { environment_id: string; audience: string } {
    return { environment_id: this.environmentId, audience: this.audience };
  }

  /**
   * One request. The scope (`environment_id`, `audience`) travels in the
   * query, or in the JSON body when `scopeInBody` (the factor, profile and
   * PATCH routes read it there).
   */
  private async call<T>(method: Method, path: string, options: { query?: Query; body?: Record<string, unknown>; scopeInBody?: boolean } = {}): Promise<T> {
    const query = new URLSearchParams();
    const params: Query = { ...(options.scopeInBody ? {} : this.scope()), ...options.query };
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== "") {
        query.set(key, String(value));
      }
    }
    const headers: Record<string, string> = { Accept: "application/json", Authorization: `Bearer ${await this.token()}` };
    let body: string | undefined;
    if (options.scopeInBody || options.body) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify({ ...(options.scopeInBody ? this.scope() : {}), ...options.body });
    }
    const search = query.toString();
    // Bearer-authenticated: no cookies (an app's own cookies on the same
    // host would ride along otherwise and bloat every request).
    const response = await this.fetcher(`${this.baseUrl}${path}${search ? `?${search}` : ""}`, { method, headers, body, credentials: "omit" });
    const parsed = parse(await response.text());
    if (!response.ok) {
      throw toError(response.status, parsed);
    }
    return parsed as T;
  }

  // ── Profile ──

  /** The signed-in user. */
  me(): Promise<Profile> {
    return this.call("GET", "/identity/v1/me");
  }

  /** Changes the display name and/or avatar (an https URL; `null` clears the avatar). */
  async updateMe(changes: { name?: string; avatarUrl?: string | null }): Promise<void> {
    await this.call("PATCH", "/identity/v1/me", {
      scopeInBody: true,
      body: { ...(changes.name !== undefined ? { name: changes.name } : {}), ...(changes.avatarUrl !== undefined ? { avatar_url: changes.avatarUrl } : {}) },
    });
  }

  /** The user's self-service profile properties (the environment's user schema, `x-iamkit-self`). */
  async properties(): Promise<Record<string, unknown>> {
    const out = await this.call<{ profile: Record<string, unknown> | null }>("GET", "/identity/v1/me/profile");
    return out.profile ?? {};
  }

  /** Changes self-service profile properties; answers the profile after the change. */
  async updateProperties(profile: Record<string, unknown>): Promise<Record<string, unknown>> {
    const out = await this.call<{ profile: Record<string, unknown> | null }>("PATCH", "/identity/v1/me/profile", { scopeInBody: true, body: { profile } });
    return out.profile ?? {};
  }

  /** Verifying and removing the user's phone number (a recent sign-in is needed). */
  readonly phone = {
    /** Texts a code to `phone` (E.164); the number changes once `verify` gets the code. */
    start: (phone: string): Promise<{ destination: string; expires_at: string }> => this.call("POST", "/identity/v1/me/phone", { scopeInBody: true, body: { phone } }),
    verify: async (phone: string, code: string): Promise<void> => void (await this.call("POST", "/identity/v1/me/phone/verify", { scopeInBody: true, body: { phone, code } })),
    remove: async (): Promise<void> => void (await this.call("DELETE", "/identity/v1/me/phone")),
  };

  // ── Password ──

  /**
   * Changes the user's password. Needs a recent sign-in
   * (`REAUTHENTICATION_REQUIRED`); a wrong current password is
   * `INVALID_CURRENT_PASSWORD` (it counts toward the lockout), a refused new
   * one `PASSWORD_POLICY` with `details.rule`, an account without a
   * password `NO_PASSWORD`. The user's other sessions end.
   */
  changePassword(currentPassword: string, newPassword: string): Promise<PasswordChanged> {
    return this.call("POST", "/identity/v1/me/password", { body: { current_password: currentPassword, new_password: newPassword } });
  }

  // ── Sessions ──

  readonly sessions = {
    /** The user's live sessions across organizations and applications, newest first. */
    list: async (page: { limit?: number; offset?: number } = {}): Promise<SessionPage> => {
      const out = await this.call<SessionPage>("GET", "/identity/v1/me/sessions", { query: { limit: page.limit, offset: page.offset } });
      return { ...out, items: out.items ?? [] };
    },
    /** Ends one session (the current one too). */
    revoke: async (sessionId: string): Promise<void> => void (await this.call("DELETE", `/identity/v1/me/sessions/${encodeURIComponent(sessionId)}`)),
    /** Ends every session but the current one; answers how many ended. */
    revokeOthers: async (): Promise<number> => (await this.call<{ count: number }>("POST", "/identity/v1/me/sessions/revoke-others")).count,
  };

  // ── API keys ──

  readonly apiKeys = {
    list: async (filter: ApiKeyFilter = {}): Promise<ApiKeyPage> => {
      const out = await this.call<ApiKeyPage>("GET", "/identity/v1/me/api-keys", {
        query: { limit: filter.limit, offset: filter.offset, search: filter.search, state: filter.state, resource_id: filter.resourceId },
      });
      return { ...out, items: out.items ?? [] };
    },
    /** Whether keys are enabled and what the user may create. */
    options: (): Promise<ApiKeyOptions> => this.call("GET", "/identity/v1/me/api-keys/options"),
    /** Creates a key (a recent sign-in is needed); `value` is shown once. */
    create: (key: NewApiKey): Promise<IssuedApiKey> => this.call("POST", "/identity/v1/me/api-keys", { body: { ...key } }),
    revoke: async (keyId: string): Promise<void> => void (await this.call("DELETE", `/identity/v1/me/api-keys/${encodeURIComponent(keyId)}`)),
  };

  // ── Organizations ──

  /** The organizations the user may sign in to for this application. */
  async organizations(): Promise<Organization[]> {
    return (await this.call<Organization[] | null>("GET", "/identity/v1/organizations")) ?? [];
  }

  /**
   * Moves the session of `refreshToken` into another organization and
   * answers the tokens of the new session (the old session and refresh token
   * end: store the new pair). The current boundary is read from the access
   * token's claims; pass `boundary` when the token is opaque.
   *
   * A target that needs a sign-in the session lacks (enforced single sign-on,
   * a second factor, another method) throws `REAUTHENTICATION_REQUIRED`;
   * `switchRefusal(error)` names the organization and the `reason`: start a
   * new authorization with that organization. No access to the organization
   * is a 403 `FORBIDDEN`.
   */
  async switchOrganization(refreshToken: string, organizationId: string, boundary?: Boundary): Promise<Tokens> {
    let current = boundary;
    if (!current) {
      const claims = claimsOf(await this.token());
      current = {
        environmentId: String(claims.environment_id ?? this.environmentId),
        organizationId: String(claims.organization_id ?? ""),
        applicationId: String(claims.application_id ?? ""),
        resourceId: String(claims.resource_id ?? ""),
      };
    }
    const response = await this.fetcher(`${this.baseUrl}/identity/v1/refresh`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      credentials: "omit",
      body: JSON.stringify({
        environment_id: current.environmentId,
        organization_id: current.organizationId,
        application_id: current.applicationId,
        resource_id: current.resourceId,
        refresh_token: refreshToken,
        switch_organization_id: organizationId,
      }),
    });
    const parsed = parse(await response.text());
    if (!response.ok) {
      throw toError(response.status, parsed);
    }
    return parsed as Tokens;
  }

  // ── Second factors ──

  readonly mfa = {
    /** The user's factors (TOTP, email, SMS, security keys, passkeys) and the recovery codes left. */
    factors: async (): Promise<FactorSummary> => {
      const out = await this.call<Schema<"MfaSummary">>("GET", "/identity/v1/me/factors");
      return { ...out, factors: (out.factors ?? []) as Factor[] };
    },
    /** An authenticator app (RFC 6238): `start`, show the QR code/secret, then `confirm` its first code. */
    totp: {
      start: (): Promise<TotpEnrollment> => this.call("POST", "/identity/v1/me/factors/totp", { scopeInBody: true }),
      /** Answers the recovery codes (shown once) when this was the user's first factor. */
      confirm: (code: string): Promise<string[]> => this.codes("/identity/v1/me/factors/totp/confirm", code),
      /** `proof` is a code from any active factor or a recovery code. */
      remove: (proof: string): Promise<void> => this.remove("/identity/v1/me/factors/totp", { code: proof }),
    },
    /** Codes to the account email. */
    email: {
      start: (): Promise<CodeSent> => this.call("POST", "/identity/v1/me/factors/email", { scopeInBody: true }),
      confirm: (code: string): Promise<string[]> => this.codes("/identity/v1/me/factors/email/confirm", code),
      /** Sends a code to the active factor, to prove possession before `remove`. */
      send: (): Promise<CodeSent> => this.call("POST", "/identity/v1/me/factors/email/challenge", { scopeInBody: true }),
      remove: (proof: string): Promise<void> => this.remove("/identity/v1/me/factors/email", { code: proof }),
    },
    /** Codes by text message; confirming also verifies the phone. */
    sms: {
      start: (phone: string): Promise<CodeSent> => this.call("POST", "/identity/v1/me/factors/sms", { scopeInBody: true, body: { phone } }),
      confirm: (code: string): Promise<string[]> => this.codes("/identity/v1/me/factors/sms/confirm", code),
      send: (): Promise<CodeSent> => this.call("POST", "/identity/v1/me/factors/sms/challenge", { scopeInBody: true }),
      remove: (proof: string): Promise<void> => this.remove("/identity/v1/me/factors/sms", { code: proof }),
    },
    /** Replaces the recovery codes (answers the new ones, shown once); `proof` is a code from any active factor. */
    recoveryCodes: (proof: string): Promise<string[]> => this.codes("/identity/v1/me/factors/recovery-codes", proof),
  };

  // ── Security keys and passkeys ──

  /**
   * Security keys (second factor only) and passkeys (also sign in on their
   * own). `add` runs the whole browser ceremony; `begin`/`finish` are the
   * two server calls for UIs that drive `navigator.credentials` themselves.
   */
  readonly passkeys = {
    /** The user's security keys and passkeys (`webauthn` factors; `passkey` tells which). */
    list: async (): Promise<Factor[]> => (await this.mfa.factors()).factors.filter((f) => f.kind === "webauthn"),
    begin: (name: string, kind: { passkey: boolean }): Promise<WebAuthnCeremony> =>
      this.call("POST", "/identity/v1/me/factors/webauthn", { scopeInBody: true, body: { name, passkey: kind.passkey } }),
    finish: (webauthnSession: string, credential: unknown): Promise<WebAuthnRegistration> =>
      this.call("POST", "/identity/v1/me/factors/webauthn/confirm", { scopeInBody: true, body: { webauthn_session: webauthnSession, credential } }),
    /** Registers a passkey (`passkey: true`, the default) or a security key in this browser; null when the user dismissed the prompt. */
    add: async (name: string, kind: { passkey: boolean; signal?: AbortSignal } = { passkey: true }): Promise<WebAuthnRegistration | null> => {
      const ceremony = await this.passkeys.begin(name, kind);
      const credential = await createCredential(ceremony.options, { signal: kind.signal });
      return credential ? this.passkeys.finish(ceremony.webauthn_session, credential) : null;
    },
    rename: (factorId: string, name: string): Promise<Factor> => this.call("PATCH", `/identity/v1/me/factors/webauthn/${encodeURIComponent(factorId)}`, { scopeInBody: true, body: { name } }),
    /** Starts a key assertion that proves possession for `remove` (a code works too). */
    prove: (): Promise<WebAuthnCeremony> => this.call("POST", "/identity/v1/me/factors/webauthn/challenge", { scopeInBody: true }),
    /** Proves possession with the browser: runs `prove`, asks for the key and answers the proof for `remove`; null when dismissed. */
    assert: async (init: { signal?: AbortSignal } = {}): Promise<Proof | null> => {
      const ceremony = await this.passkeys.prove();
      const credential = await getAssertion(ceremony.options, init);
      return credential ? { webauthnSession: ceremony.webauthn_session, credential } : null;
    },
    remove: (factorId: string, proof: Proof): Promise<void> =>
      this.remove(`/identity/v1/me/factors/webauthn/${encodeURIComponent(factorId)}`, "code" in proof ? { code: proof.code } : { webauthn_session: proof.webauthnSession, credential: proof.credential }),
  };

  private async codes(path: string, code: string): Promise<string[]> {
    const out = await this.call<{ recovery_codes: string[] | null }>("POST", path, { scopeInBody: true, body: { code } });
    return out.recovery_codes ?? [];
  }

  private async remove(path: string, proof: Record<string, unknown>): Promise<void> {
    await this.call("DELETE", path, { scopeInBody: true, body: proof });
  }
}

/** Creates the self-service client of a signed-in user. */
export function createAccount(options: AccountOptions): Account {
  return new Account(options);
}

// ── WebAuthn registration glue ──

interface CreationOptionsJSON {
  challenge: string;
  user: { id: string; [key: string]: unknown };
  excludeCredentials?: { id: string; type: string; transports?: string[] }[];
  [key: string]: unknown;
}

/** Decodes IAMKit's registration options (`options.publicKey` or the bare object). */
export function creationOptions(options: unknown): PublicKeyCredentialCreationOptions {
  const wrapped = options as { publicKey?: CreationOptionsJSON } & CreationOptionsJSON;
  const o = { ...(wrapped.publicKey ?? wrapped) } as CreationOptionsJSON;
  return {
    ...(o as object),
    challenge: fromBase64url(o.challenge),
    user: { ...o.user, id: fromBase64url(o.user.id) },
    excludeCredentials: (o.excludeCredentials ?? []).map((c) => ({ ...c, id: fromBase64url(c.id) })),
  } as unknown as PublicKeyCredentialCreationOptions;
}

/** Encodes an attestation the way IAMKit's registration reads it. */
export function attestationJSON(credential: PublicKeyCredential): Record<string, unknown> {
  const r = credential.response as AuthenticatorAttestationResponse;
  const enc = (b: ArrayBuffer | null | undefined) => (b ? base64url(new Uint8Array(b)) : undefined);
  return {
    id: credential.id,
    rawId: enc(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    response: {
      clientDataJSON: enc(r.clientDataJSON),
      attestationObject: enc(r.attestationObject),
      transports: typeof r.getTransports === "function" ? r.getTransports() : undefined,
    },
  };
}

/** Asks the browser to create a credential; null when the user dismissed the prompt. */
export async function createCredential(options: unknown, init: { signal?: AbortSignal } = {}): Promise<Record<string, unknown> | null> {
  if (typeof window === "undefined" || typeof navigator?.credentials?.create !== "function") {
    throw new Error("WebAuthn is not available in this browser");
  }
  try {
    const credential = (await navigator.credentials.create({ publicKey: creationOptions(options), signal: init.signal })) as PublicKeyCredential | null;
    return credential ? attestationJSON(credential) : null;
  } catch (err) {
    if (err instanceof DOMException && (err.name === "AbortError" || err.name === "NotAllowedError")) {
      return null;
    }
    throw err;
  }
}
