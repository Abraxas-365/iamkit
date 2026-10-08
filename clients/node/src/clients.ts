import { createIAMKitClient, type IAMKitClient, type IAMKitOptions } from "@iamkit/api";
import { invalidArgument } from "./errors.js";
import { Transport, withQuery, type FetchLike } from "./http.js";

/**
 * Typed clients for every documented route, from `@iamkit/api`
 * (openapi-fetch: calls resolve with `{data, error, response}`).
 */
export { createIAMKitClient, isApiError, type IAMKitClient, type IAMKitOptions, type Schema, type paths, type components, type operations } from "@iamkit/api";

/**
 * A typed client for `/management/v1` authenticated with a management key
 * (`ik_mgmt_…`, sent as `X-API-Key`). Keep the key server-side.
 */
export function createManagementClient(options: Omit<IAMKitOptions, "managementKey" | "token"> & { key: string }): IAMKitClient {
  const { key, ...rest } = options;
  if (!key) {
    throw invalidArgument("key is required");
  }
  return createIAMKitClient({ ...rest, managementKey: key });
}

/**
 * A typed client for the permission-scoped `/api/v1` and `/scim/v2` routes:
 * token is a user's or service account's access token, a machine user's
 * `ik_pat_` token or a SCIM credential. A function is called per request,
 * so it can refresh.
 */
export function createApiClient(options: Omit<IAMKitOptions, "managementKey" | "token"> & { token: NonNullable<IAMKitOptions["token"]> }): IAMKitClient {
  return createIAMKitClient(options);
}

/** A token pair from `/identity/v1`. */
export interface TokenPair {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  /** Returned once, by the login that enrolled the user's first authenticator. */
  recovery_codes?: string[];
}

/** A login that needs a second factor: continue with verifyMFA. */
export interface MFAPending {
  mfa_required: true;
  mfa_token: string;
  enrollment_required: boolean;
  factors: string[];
  expires_in: number;
}

/** Where a session lives: the token's organization, application and resource. */
export interface Boundary {
  environmentId: string;
  organizationId: string;
  applicationId: string;
  resourceId: string;
}

/** The authenticated user. */
export interface Profile {
  id: string;
  email: string;
  name: string;
  username: string;
  avatar_url: string;
  email_verified: boolean;
  phone: string;
  phone_verified: boolean;
  environment_id: string;
  organization_id: string;
  actor_id: string;
}

export interface IdentityClientOptions {
  baseUrl: string;
  fetch?: FetchLike;
  timeoutMs?: number;
}

/**
 * Server-side calls of the identity API (`/identity/v1`): password login
 * for first-party backends (BFF), refresh, logout, the user's profile,
 * service-account and personal-access-token exchanges. Browser sign-in UIs
 * use `@iamkit/js` instead. Failures throw IAMKitError.
 */
export class IdentityClient {
  private readonly http: Transport;

  constructor(options: IdentityClientOptions) {
    this.http = new Transport(options);
  }

  /**
   * Password login (`login` = email or username). Answers tokens, or an
   * MFAPending to continue with verifyMFA. A `PASSWORD_CHANGE_REQUIRED`
   * error asks to send the same login again with newPassword.
   */
  login(boundary: Boundary, credentials: { login: string; password: string; newPassword?: string }): Promise<TokenPair | MFAPending> {
    return this.http.json("/identity/v1/login", {
      ...body(boundary),
      login: credentials.login,
      password: credentials.password,
      ...(credentials.newPassword ? { new_password: credentials.newPassword } : {}),
    });
  }

  /** Completes a pending login with an authenticator or recovery code. */
  verifyMFA(mfaToken: string, code: string): Promise<TokenPair> {
    return this.http.json("/identity/v1/mfa/verify", { mfa_token: mfaToken, code });
  }

  /** Exchanges a refresh token (rotated: store the new one). */
  refresh(boundary: Boundary, refreshToken: string): Promise<TokenPair> {
    return this.http.json("/identity/v1/refresh", { ...body(boundary), refresh_token: refreshToken });
  }

  /** Ends the token's session. */
  async logout(accessToken: string, environmentId: string, audience: string): Promise<void> {
    await this.http.json("/identity/v1/logout", { environment_id: environmentId, audience }, accessToken);
  }

  /** The token's user. */
  profile(accessToken: string, environmentId: string, audience: string): Promise<Profile> {
    return this.http.get(withQuery("/identity/v1/me", { environment_id: environmentId, audience }), accessToken);
  }

  /** The organizations the token's user belongs to. */
  organizations(accessToken: string, environmentId: string, audience: string): Promise<{ id: string; name: string; org_unit_id: string | null; manager_id: string | null }[]> {
    return this.http.get(withQuery("/identity/v1/organizations", { environment_id: environmentId, audience }), accessToken);
  }

  /** A service account's access token from its `ik_svc_` secret. */
  machineToken(secret: string): Promise<TokenPair> {
    if (!secret.startsWith("ik_svc_")) {
      return Promise.reject(invalidArgument("service credential required"));
    }
    return this.http.json("/identity/v1/machine-token", undefined, secret);
  }

  /**
   * Trades a machine user's personal access token (`ik_pat_`) for a
   * session-backed access JWT that offline verification accepts.
   */
  exchangeAccessToken(token: string): Promise<TokenPair> {
    if (!token.startsWith("ik_pat_")) {
      return Promise.reject(invalidArgument("personal access token required"));
    }
    return this.http.json("/identity/v1/token-exchange", undefined, token);
  }
}

/** Whether a login answer still needs a second factor. */
export function isMFAPending(answer: TokenPair | MFAPending): answer is MFAPending {
  return (answer as MFAPending).mfa_required === true;
}

function body(b: Boundary): Record<string, string> {
  return {
    environment_id: b.environmentId,
    organization_id: b.organizationId,
    application_id: b.applicationId,
    resource_id: b.resourceId,
  };
}
