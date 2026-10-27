/**
 * Protect a resource server (for example a remote MCP server over
 * Streamable HTTP) with IAMKit as its OAuth 2.1 authorization server.
 *
 * Serves RFC 9728 protected resource metadata, verifies access tokens issued
 * for the resource (RFC 8707: `aud` is the resource's canonical URL) and
 * answers like the MCP authorization specification asks: 401 with
 * `WWW-Authenticate: Bearer resource_metadata="…"` for a missing or invalid
 * token, 403 `insufficient_scope` for a missing scope.
 *
 * Scopes are IAMKit permissions (`prefix:name`) of the resource. Only JWT
 * access tokens are accepted. The client's token never reaches handlers:
 * they see claims only. To call another API for the user, exchange the token
 * with a confidential client of the server (`OAuthClient.exchangeToken`)
 * instead of forwarding it.
 *
 * Same canonicalization (and shared vectors) as IAMKit and the Go SDK
 * `sdk/resourceserver`.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { errors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";
import { createKeySet, type KeySetOptions } from "./tokens.js";

/** The RFC 9728 well-known path. */
export const METADATA_PATH = "/.well-known/oauth-protected-resource";

const MAX_RESOURCE_URI = 2048;

/**
 * The canonical form of an RFC 8707 resource indicator, or undefined when it
 * has none: absolute https (http only on localhost, 127.0.0.1, [::1]),
 * lowercase scheme and host, no default port, userinfo, query, fragment,
 * dot or empty segments, no trailing slash; path case and percent-encoding
 * kept.
 */
export function canonicalResource(raw: string): string | undefined {
  if (raw === "" || raw.length > MAX_RESOURCE_URI) return undefined;
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c <= 0x20 || c >= 0x7f) return undefined;
  }
  const sep = raw.indexOf("://");
  if (sep < 0) return undefined;
  const scheme = raw.slice(0, sep).toLowerCase();
  const rest = raw.slice(sep + 3);
  if ((scheme !== "https" && scheme !== "http") || /[?#]/.test(rest)) return undefined;
  const slash = rest.indexOf("/");
  const authority = slash >= 0 ? rest.slice(0, slash) : rest;
  const rawPath = slash >= 0 ? rest.slice(slash) : "";
  const hp = splitAuthority(authority);
  if (!hp) return undefined;
  let { port } = hp;
  const { host } = hp;
  if ((scheme === "https" && port === "443") || (scheme === "http" && port === "80")) port = "";
  if (scheme === "http" && host !== "localhost" && host !== "127.0.0.1" && host !== "[::1]") return undefined;
  const path = canonicalPath(rawPath);
  if (path === undefined) return undefined;
  return `${scheme}://${host}${port ? `:${port}` : ""}${path}`;
}

const isHex = (c: string) => /^[0-9a-fA-F]$/.test(c);

function validPort(port: string): string | undefined {
  if (port === "" || port[0] === "0" || !/^[0-9]+$/.test(port)) return undefined;
  const n = Number(port);
  return n >= 1 && n <= 65535 ? port : undefined;
}

function splitAuthority(authority: string): { host: string; port: string } | undefined {
  if (authority === "" || authority.includes("@")) return undefined;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end < 0) return undefined;
    const host = authority.slice(0, end + 1).toLowerCase();
    const rest = authority.slice(end + 1);
    const inner = host.slice(1, -1);
    if (inner === "" || ![...inner].every((c) => c === ":" || c === "." || isHex(c))) return undefined;
    if (rest === "") return { host, port: "" };
    if (!rest.startsWith(":")) return undefined;
    const port = validPort(rest.slice(1));
    return port === undefined ? undefined : { host, port };
  }
  const colon = authority.indexOf(":");
  const host = (colon >= 0 ? authority.slice(0, colon) : authority).toLowerCase();
  if (host === "" || host.startsWith(".") || host.endsWith(".") || host.includes("..") || !/^[a-z0-9.-]+$/.test(host)) return undefined;
  if (colon < 0) return { host, port: "" };
  const port = validPort(authority.slice(colon + 1));
  return port === undefined ? undefined : { host, port };
}

const PCHAR = /^[A-Za-z0-9\-._~!$&'()*+,;=:@]$/;

function canonicalPath(path: string): string | undefined {
  if (path === "" || path === "/") return "";
  if (path.endsWith("/")) path = path.slice(0, -1);
  for (const segment of path.slice(1).split("/")) {
    if (segment === "") return undefined;
    for (let i = 0; i < segment.length; i++) {
      const c = segment[i]!;
      if (c === "%") {
        if (i + 2 >= segment.length || !isHex(segment[i + 1]!) || !isHex(segment[i + 2]!)) return undefined;
        i += 2;
      } else if (!PCHAR.test(c)) {
        return undefined;
      }
    }
    const dot = segment.toLowerCase().replaceAll("%2e", ".");
    if (dot === "." || dot === "..") return undefined;
  }
  return path;
}

/** The RFC 9728 §3.1 metadata URL of a canonical resource. */
export function metadataUrl(resource: string): string {
  const sep = resource.indexOf("://");
  const rest = resource.slice(sep + 3);
  const slash = rest.indexOf("/");
  const host = slash >= 0 ? rest.slice(0, slash) : rest;
  const path = slash >= 0 ? rest.slice(slash) : "";
  return `${resource.slice(0, sep)}://${host}${METADATA_PATH}${path}`;
}

export interface ResourceServerOptions {
  /** IAMKit's issuer URL (the `iss` of its tokens). */
  issuer: string;
  /** The server's URL as registered in IAMKit (canonicalized). */
  resource: string;
  /** The IAMKit environment of the resource. */
  environmentId: string;
  /** When set, only tokens of these organizations are admitted. */
  organizations?: string[];
  /** Scopes advertised in the metadata (the resource's permissions). */
  scopesSupported?: string[];
  resourceName?: string;
  documentationUrl?: string;
  /** A shared key set; by default one for `<issuer>/.well-known/jwks.json`. */
  keys?: JWTVerifyGetKey;
  keySet?: Omit<KeySetOptions, "issuer">;
  /** Clock skew tolerance in seconds (default 30). */
  clockToleranceSec?: number;
  /**
   * Also admit tokens issued without the RFC 8707 resource parameter (no
   * `resource` claim), such as plain OpenID Connect tokens of a client whose
   * resource is this server. Off by default: such tokens were never
   * consented for this server. Even then only granted scopes count.
   */
  allowTokensWithoutResource?: boolean;
}

/** The claims of a verified access token. */
export interface ResourceClaims {
  sub: string;
  environmentId: string;
  organizationId: string;
  applicationId: string;
  resourceId: string;
  sessionId: string;
  oauthClientId?: string;
  /**
   * The protected resource the authorization named (the token's `resource`
   * claim; undefined only with allowTokensWithoutResource).
   */
  resource?: string;
  /** Granted scopes (OpenID Connect scopes included). */
  scopes: string[];
  /**
   * The granted scopes that are permissions (the token's `permissions`
   * claim is not read).
   */
  permissions: string[];
  amr: string[];
  authTime?: number;
  exp: number;
}

/**
 * Why a request is refused. For insufficient_scope, `required` are the
 * missing route scopes and `granted` the token's: the 403 challenge asks for
 * granted ∪ required, so a client stepping up keeps what it had.
 */
export class ResourceError extends Error {
  constructor(
    readonly kind: "no_token" | "invalid_token" | "insufficient_scope" | "unavailable",
    readonly required: string[] = [],
    readonly granted: string[] = [],
  ) {
    super(kind === "insufficient_scope" ? `insufficient scope: ${required.join(" ")}` : kind.replace("_", " "));
  }
}

/** RFC 9728 protected resource metadata. */
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  scopes_supported?: string[];
  bearer_methods_supported: string[];
  resource_name?: string;
  resource_documentation?: string;
}

/**
 * A request after protect(): the verified claims on `iamkit` (not `auth`,
 * which the MCP SDK reserves for an AuthInfo carrying the raw token).
 */
export interface ProtectedRequest extends IncomingMessage {
  iamkit?: ResourceClaims;
}

/** The claims protect() verified for req (undefined before protect). */
export function resourceClaimsOf(req: IncomingMessage): ResourceClaims | undefined {
  return (req as ProtectedRequest).iamkit;
}

type Next = (error?: unknown) => void;
export type Middleware = (req: IncomingMessage, res: ServerResponse, next: Next) => void;

export interface ResourceServer {
  /** The canonical resource (the tokens' aud). */
  readonly resource: string;
  readonly metadataUrl: string;
  /** Paths the metadata must be served at (RFC 9728 path, then root). */
  readonly metadataPaths: string[];
  metadata(): ProtectedResourceMetadata;
  /** Verifies a raw token; throws ResourceError. */
  verify(token: string | undefined): Promise<ResourceClaims>;
  /** Connect/Express middleware serving the metadata at metadataPaths (CORS *). */
  metadataHandler(): Middleware;
  /**
   * Connect/Express middleware: a valid token with every scope, else
   * 401/403 with the challenge. Claims on `req.iamkit`; the Authorization
   * header is removed.
   */
  protect(...scopes: string[]): Middleware;
  /** Throws ResourceError insufficient_scope when claims lack a scope. */
  require(claims: ResourceClaims, ...scopes: string[]): void;
  /** Writes the 401/403/503 answer for error. */
  deny(res: ServerResponse, error: unknown, scopes?: string[]): void;
  /** The WWW-Authenticate value and status for error. */
  challenge(error: unknown, scopes?: string[]): { status: number; header: string };
}

export function hasScope(claims: ResourceClaims, scope: string): boolean {
  return claims.scopes.includes(scope);
}

const PROTOCOL_SCOPES = ["openid", "profile", "email", "phone", "offline_access"];

/** The granted scopes that are permissions (not OIDC scopes nor IAMKit hints). */
function permissionsOf(scopes: string[]): string[] {
  return scopes.filter((s) => !PROTOCOL_SCOPES.includes(s) && !s.startsWith("urn:iamkit:"));
}

export function createResourceServer(options: ResourceServerOptions): ResourceServer {
  if (!options.issuer || !options.environmentId) throw new TypeError("issuer and environmentId are required");
  const resource = canonicalResource(options.resource);
  if (!resource) throw new TypeError(`resource ${options.resource} has no canonical form`);
  const keys = options.keys ?? createKeySet({ ...options.keySet, issuer: options.issuer });
  const url = metadataUrl(resource);
  const rest = resource.slice(resource.indexOf("://") + 3);
  const slash = rest.indexOf("/");
  const paths = slash >= 0 ? [METADATA_PATH + rest.slice(slash), METADATA_PATH] : [METADATA_PATH];
  const document: ProtectedResourceMetadata = {
    resource,
    authorization_servers: [options.issuer],
    ...(options.scopesSupported?.length ? { scopes_supported: options.scopesSupported } : {}),
    bearer_methods_supported: ["header"],
    ...(options.resourceName ? { resource_name: options.resourceName } : {}),
    ...(options.documentationUrl ? { resource_documentation: options.documentationUrl } : {}),
  };

  async function verify(token: string | undefined): Promise<ResourceClaims> {
    if (!token) throw new ResourceError("no_token");
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, keys, {
        algorithms: ["RS256"],
        issuer: options.issuer,
        requiredClaims: ["exp", "sub"],
        clockTolerance: options.clockToleranceSec ?? 30,
      }));
    } catch (error) {
      if (error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid || error instanceof TypeError) {
        throw new ResourceError("unavailable");
      }
      throw new ResourceError("invalid_token");
    }
    const p = payload as Record<string, unknown>;
    const text = (k: string) => (typeof p[k] === "string" ? (p[k] as string) : "");
    const list = (k: string) => (Array.isArray(p[k]) ? (p[k] as unknown[]).filter((v): v is string => typeof v === "string") : []);
    const aud = typeof p.aud === "string" ? [p.aud] : list("aud");
    if (!aud.some((a) => canonicalResource(a) === resource)) throw new ResourceError("invalid_token");
    if (text("environment_id") !== options.environmentId || text("purpose") !== "application" || !text("sid") || !text("organization_id")) {
      throw new ResourceError("invalid_token");
    }
    if (options.organizations?.length && !options.organizations.includes(text("organization_id"))) {
      throw new ResourceError("invalid_token");
    }
    // Only tokens of an authorization that named this resource (RFC 8707)
    // open it: a plain OpenID Connect token of the same client was never
    // consented for it.
    const marker = text("resource");
    if (marker ? canonicalResource(marker) !== resource : !options.allowTokensWithoutResource) {
      throw new ResourceError("invalid_token");
    }
    const scp = list("scp");
    const scopes = scp.length ? scp : text("scope").split(" ").filter(Boolean);
    return {
      sub: text("sub"),
      environmentId: text("environment_id"),
      organizationId: text("organization_id"),
      applicationId: text("application_id"),
      resourceId: text("resource_id"),
      sessionId: text("sid"),
      oauthClientId: text("oauth_client_id") || undefined,
      resource: marker || undefined,
      scopes,
      permissions: permissionsOf(scopes),
      amr: list("amr"),
      authTime: typeof p.auth_time === "number" ? p.auth_time : undefined,
      exp: Number(p.exp),
    };
  }

  function require(claims: ResourceClaims, ...scopes: string[]): void {
    if (!scopes.every((s) => hasScope(claims, s))) {
      throw new ResourceError("insufficient_scope", scopes, claims.scopes);
    }
  }

  function challenge(error: unknown, scopes: string[] = []): { status: number; header: string } {
    const params = [`resource_metadata="${url}"`];
    let status = 401;
    if (error instanceof ResourceError && error.kind === "insufficient_scope") {
      status = 403;
      params.unshift('error="insufficient_scope"');
      scopes = [...new Set([...error.granted, ...error.required])];
    } else if (error instanceof ResourceError && error.kind === "unavailable") {
      status = 503;
    } else if (!(error instanceof ResourceError && error.kind === "no_token")) {
      params.unshift('error="invalid_token"', 'error_description="The access token is invalid or expired"');
    }
    if (scopes.length) params.push(`scope="${scopes.join(" ")}"`);
    return { status, header: `Bearer ${params.join(", ")}` };
  }

  function deny(res: ServerResponse, error: unknown, scopes: string[] = []): void {
    const { status, header } = challenge(error, scopes);
    if (status !== 503) res.setHeader("WWW-Authenticate", header);
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Access-Control-Expose-Headers", "WWW-Authenticate");
    res.statusCode = status;
    const code = status === 403 ? "insufficient_scope" : status === 503 ? "temporarily_unavailable" : error instanceof ResourceError && error.kind === "no_token" ? "unauthorized" : "invalid_token";
    res.end(JSON.stringify({ error: code }));
  }

  const body = JSON.stringify(document);
  return {
    resource,
    metadataUrl: url,
    metadataPaths: paths,
    metadata: () => structuredClone(document),
    verify,
    require,
    challenge,
    deny,
    metadataHandler() {
      return (req, res, next) => {
        const path = (req.url ?? "").split("?")[0]!;
        if (!paths.includes(path)) return next();
        res.setHeader("Access-Control-Allow-Origin", "*");
        if (req.method === "OPTIONS") {
          res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
          res.setHeader("Access-Control-Allow-Headers", "*");
          res.setHeader("Access-Control-Max-Age", "86400");
          res.statusCode = 204;
          res.end();
          return;
        }
        if (req.method !== "GET" && req.method !== "HEAD") {
          res.setHeader("Allow", "GET, OPTIONS");
          res.statusCode = 405;
          res.end();
          return;
        }
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Cache-Control", "public, max-age=3600");
        res.statusCode = 200;
        res.end(req.method === "GET" ? body : undefined);
      };
    },
    protect(...scopes: string[]) {
      return (req, res, next) => {
        if (req.method === "OPTIONS") return next();
        const header = req.headers.authorization ?? "";
        const [scheme, token] = header.trim().split(/\s+/, 2);
        verify(scheme?.toLowerCase() === "bearer" ? token : undefined)
          .then((claims) => {
            require(claims, ...scopes);
            (req as ProtectedRequest).iamkit = claims;
            delete req.headers.authorization;
            next();
          })
          .catch((error) => deny(res, error, scopes));
      };
    },
  };
}
