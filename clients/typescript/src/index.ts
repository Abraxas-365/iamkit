import createClient, { type Client, type ClientOptions, type Middleware } from "openapi-fetch";
import type { components, operations, paths } from "./schema";

export type { components, operations, paths };

/** A component schema of the API, e.g. `Schema<"Application">`. */
export type Schema<Name extends keyof components["schemas"]> = components["schemas"][Name];

/** The `{"error": {...}}` body of a failed request. */
export type ApiError = components["schemas"]["Error"];

export type IAMKitClient = Client<paths>;

export interface IAMKitOptions extends Omit<ClientOptions, "baseUrl"> {
  /** Deployment origin, e.g. `https://iam.example.com`. */
  baseUrl: string;
  /** Management key (`ik_mgmt_…`), sent as `X-API-Key` (/management/v1). */
  managementKey?: string;
  /**
   * Bearer token: an access token (/api/v1, /identity/v1, /oauth/userinfo),
   * a machine user's `ik_pat_` token or a SCIM credential (/scim/v2). A
   * function is called for every request, so it can refresh.
   */
  token?: string | (() => string | undefined | Promise<string | undefined>);
}

/**
 * Creates a typed client for every documented IAMKit route.
 *
 * ```ts
 * const iam = createIAMKitClient({ baseUrl, managementKey });
 * const { data, error } = await iam.GET("/management/v1/environments/{environment}/applications", {
 *   params: { path: { environment }, query: { limit: 20 } },
 * });
 * ```
 */
export function createIAMKitClient(options: IAMKitOptions): IAMKitClient {
  const { managementKey, token, ...rest } = options;
  const client = createClient<paths>({ ...rest, baseUrl: rest.baseUrl.replace(/\/+$/, "") });
  if (managementKey || token) {
    client.use(credentials(managementKey, token));
  }
  return client;
}

function credentials(managementKey: string | undefined, token: IAMKitOptions["token"]): Middleware {
  return {
    async onRequest({ request }) {
      if (managementKey && !request.headers.has("X-API-Key")) {
        request.headers.set("X-API-Key", managementKey);
      }
      const value = typeof token === "function" ? await token() : token;
      if (value && !request.headers.has("Authorization")) {
        request.headers.set("Authorization", `Bearer ${value}`);
      }
      return request;
    },
  };
}

/** Reports whether a response body is IAMKit's error envelope. */
export function isApiError(body: unknown): body is ApiError {
  if (typeof body !== "object" || body === null || !("error" in body)) {
    return false;
  }
  const error = (body as { error: unknown }).error;
  return typeof error === "object" && error !== null && "code" in error && "message" in error;
}
