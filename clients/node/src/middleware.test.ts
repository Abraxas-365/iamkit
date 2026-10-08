import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { IAMKitError } from "./errors.js";
import { authenticate, claimsOf, requireMFA, requireOrganization, requirePermissions, type Middleware } from "./middleware.js";
import type { AccessClaims, TokenVerifier } from "./tokens.js";

const claims: AccessClaims = {
  sub: "user-1",
  iss: "i",
  aud: ["a"],
  exp: 0,
  iat: 0,
  jti: "j",
  environment_id: "e",
  organization_id: "org-1",
  application_id: "app",
  resource_id: "res",
  permissions: ["invoices:read"],
  purpose: "application",
  sid: "s",
  amr: ["pwd"],
};

const verifier = (tokens: Record<string, AccessClaims | Error>): TokenVerifier => ({
  async verify(token) {
    const found = tokens[token];
    if (!found) throw new IAMKitError(401, "UNAUTHORIZED", "invalid");
    if (found instanceof Error) throw found;
    return found;
  },
});

/** Runs middlewares like Connect, then answers 200 with the claims' subject. */
function chain(...middlewares: Middleware[]) {
  return (req: IncomingMessage, res: ServerResponse) => {
    const step = (index: number) => {
      if (index === middlewares.length) {
        res.end(JSON.stringify({ sub: claimsOf(req)?.sub }));
        return;
      }
      middlewares[index](req, res, () => step(index + 1));
    };
    step(0);
  };
}

let server: Server | undefined;
afterEach(() => server?.close());

async function serve(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<string> {
  server = createServer(handler);
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

async function call(url: string, token?: string) {
  const response = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  return { status: response.status, body: await response.json(), www: response.headers.get("www-authenticate") };
}

describe("middleware", () => {
  it("authenticates, checks the organization from the route and permissions", async () => {
    const machine: AccessClaims = { ...claims, purpose: "machine", organization_id: undefined, sid: undefined };
    const mfa: AccessClaims = { ...claims, amr: ["pwd", "mfa"], auth_time: Math.floor(Date.now() / 1000) };
    const url = await serve((req, res) => {
      const organization = (r: IncomingMessage) => new URL(r.url!, "http://x").searchParams.get("org") ?? undefined;
      const step = new URL(req.url!, "http://x").pathname === "/sensitive" ? [requireMFA({ maxAgeSec: 300 })] : [];
      chain(authenticate(verifier({ good: claims, machine, mfa, down: new IAMKitError(503, "UNAVAILABLE", "down") })), requireOrganization(organization), requirePermissions("invoices:read"), ...step)(req, res);
    });
    expect(await call(`${url}/?org=org-1`, "good")).toMatchObject({ status: 200, body: { sub: "user-1" } });
    expect(await call(`${url}/?org=org-2`, "good")).toMatchObject({ status: 403, body: { error: { code: "FORBIDDEN" } } });
    expect(await call(`${url}/?org=org-1`)).toMatchObject({ status: 401, www: 'Bearer error="invalid_token"' });
    expect(await call(`${url}/?org=org-1`, "bad")).toMatchObject({ status: 401 });
    expect(await call(`${url}/?org=org-1`, "down")).toMatchObject({ status: 503 });
    expect(await call(`${url}/`, "machine")).toMatchObject({ status: 403 });
    expect(await call(`${url}/sensitive?org=org-1`, "good")).toMatchObject({ status: 403, body: { error: { code: "STEP_UP_REQUIRED" } } });
    expect(await call(`${url}/sensitive?org=org-1`, "mfa")).toMatchObject({ status: 200 });
  });

  it("refuses missing permissions and requests without claims", async () => {
    const url = await serve(chain(authenticate(verifier({ good: claims })), requirePermissions("invoices:write")));
    expect(await call(url, "good")).toMatchObject({ status: 403 });
    const bare = await serve(chain(requirePermissions("invoices:read")));
    expect(await call(bare)).toMatchObject({ status: 401 });
  });
});
