import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPair, SignJWT, type JWTPayload, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { canonicalResource, createResourceServer, hasScope, metadataUrl, ResourceError, resourceClaimsOf, type ResourceServer } from "./resource-server.js";

const vectors = JSON.parse(readFileSync(new URL("../../../sdk/resourceserver/testdata/canonical.json", import.meta.url), "utf8")) as {
  cases: { name: string; input: string; canonical: string | null }[];
};

describe("canonicalResource", () => {
  it("matches the shared vectors", () => {
    expect(vectors.cases.length).toBeGreaterThanOrEqual(20);
    for (const c of vectors.cases) {
      expect(canonicalResource(c.input) ?? null, c.name).toBe(c.canonical);
    }
  });

  it("derives the RFC 9728 metadata URL", () => {
    expect(metadataUrl("https://mcp.example.com")).toBe("https://mcp.example.com/.well-known/oauth-protected-resource");
    expect(metadataUrl("https://mcp.example.com/mcp")).toBe("https://mcp.example.com/.well-known/oauth-protected-resource/mcp");
    expect(metadataUrl("http://localhost:3000/a/b")).toBe("http://localhost:3000/.well-known/oauth-protected-resource/a/b");
  });
});

const issuer = "https://iam.example";
const resource = "https://mcp.example.com/mcp";

describe("createResourceServer", () => {
  let key: CryptoKey;
  let other: CryptoKey;
  let publicKey: CryptoKey;
  let rs: ResourceServer;
  let server: Server;
  let base: string;

  const token = (edit: (c: JWTPayload) => void = () => {}, signer?: CryptoKey) => {
    const now = Math.floor(Date.now() / 1000);
    const c: JWTPayload = {
      iss: issuer,
      sub: "user-1",
      aud: [resource],
      exp: now + 900,
      iat: now,
      environment_id: "env-1",
      organization_id: "org-1",
      application_id: "app-1",
      resource_id: "res-1",
      sid: "s-1",
      purpose: "application",
      permissions: ["mcp:tools:read"],
      scp: ["mcp:tools:read", "offline_access"],
      resource,
    };
    edit(c);
    return new SignJWT(c).setProtectedHeader({ alg: "RS256", kid: "k1" }).sign(signer ?? key);
  };

  beforeAll(async () => {
    const pair = await generateKeyPair("RS256");
    key = pair.privateKey;
    publicKey = pair.publicKey;
    ({ privateKey: other } = await generateKeyPair("RS256"));
    rs = createResourceServer({
      issuer,
      resource: "https://MCP.example.com:443/mcp/",
      environmentId: "env-1",
      scopesSupported: ["mcp:tools:read", "mcp:tools:write"],
      keys: async () => pair.publicKey,
    });
    const meta = rs.metadataHandler();
    const guard = rs.protect("mcp:tools:read");
    server = createServer((req, res) => {
      meta(req, res, () => {
        guard(req, res, () => {
          const auth = resourceClaimsOf(req)!;
          if (req.headers.authorization) throw new Error("token reached the handler");
          if (req.url?.includes("tool=write")) {
            try {
              rs.require(auth, "mcp:tools:write");
            } catch (error) {
              rs.deny(res, error);
              return;
            }
          }
          res.end(auth.sub);
        });
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it("canonicalizes the resource and refuses bad configuration", () => {
    expect(rs.resource).toBe(resource);
    expect(rs.metadataPaths).toEqual(["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"]);
    expect(() => createResourceServer({ issuer, resource: "http://mcp.example.com", environmentId: "e" })).toThrow();
    expect(() => createResourceServer({ issuer: "", resource, environmentId: "e" })).toThrow();
  });

  it("verifies tokens for the resource only", async () => {
    const claims = await rs.verify(await token());
    expect(claims).toMatchObject({ sub: "user-1", organizationId: "org-1", scopes: ["mcp:tools:read", "offline_access"] });
    await expect(rs.verify(await token((c) => (c.aud = "https://mcp.example.com:443/mcp")))).resolves.toBeTruthy();
    const bad: Record<string, Promise<string>> = {
      audience: token((c) => (c.aud = "https://iam.example/api")),
      issuer: token((c) => (c.iss = "https://evil.example")),
      expired: token((c) => (c.exp = Math.floor(Date.now() / 1000) - 120)),
      environment: token((c) => (c.environment_id = "env-2")),
      machine: token((c) => {
        c.purpose = "machine";
        delete c.sid;
        delete c.organization_id;
      }),
      session: token((c) => delete c.sid),
      "no resource": token((c) => delete c.resource),
      "other resource": token((c) => (c.resource = "https://mcp.example.com/other")),
      signature: token(undefined, other),
    };
    for (const [name, raw] of Object.entries(bad)) {
      await expect(rs.verify(await raw), name).rejects.toMatchObject({ kind: "invalid_token" });
    }
    await expect(rs.verify("ik_at_opaque")).rejects.toMatchObject({ kind: "invalid_token" });
    await expect(rs.verify(undefined)).rejects.toBeInstanceOf(ResourceError);
  });

  it("takes permissions from the granted scopes only", async () => {
    const claims = await rs.verify(
      await token((c) => {
        c.permissions = ["mcp:tools:read", "mcp:tools:write", "mcp:admin"];
        c.scp = ["openid", "mcp:tools:read", "offline_access", "urn:iamkit:org:id:org-1"];
      }),
    );
    expect(claims.permissions).toEqual(["mcp:tools:read"]);
    expect(claims.resource).toBe(resource);
    expect(hasScope(claims, "mcp:tools:write")).toBe(false);
    const none = await rs.verify(await token((c) => delete c.scp));
    expect(none.permissions).toEqual([]);
    expect(() => rs.require(none, "mcp:tools:read")).toThrow(ResourceError);
  });

  it("admits tokens without the resource claim only when told to", async () => {
    const lenient = createResourceServer({ issuer, resource, environmentId: "env-1", keys: async () => publicKey, allowTokensWithoutResource: true });
    const claims = await lenient.verify(await token((c) => delete c.resource));
    expect(claims.resource).toBeUndefined();
    expect(hasScope(claims, "mcp:tools:read")).toBe(true);
    await expect(lenient.verify(await token((c) => (c.resource = "https://mcp.example.com/other")))).rejects.toMatchObject({ kind: "invalid_token" });
  });

  it("serves metadata with CORS at both well-known paths", async () => {
    for (const path of rs.metadataPaths) {
      const res = await fetch(base + path);
      expect(res.status).toBe(200);
      expect(res.headers.get("access-control-allow-origin")).toBe("*");
      expect(await res.json()).toEqual({
        resource,
        authorization_servers: [issuer],
        scopes_supported: ["mcp:tools:read", "mcp:tools:write"],
        bearer_methods_supported: ["header"],
      });
    }
    const preflight = await fetch(base + rs.metadataPaths[0], { method: "OPTIONS" });
    expect(preflight.status).toBe(204);
  });

  it("answers 401/403 with the MCP challenge", async () => {
    const metadata = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
    const call = async (raw?: string, query = "") =>
      fetch(`${base}/mcp${query}`, { method: "POST", headers: raw ? { authorization: `Bearer ${raw}` } : {} });

    let res = await call();
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe(`Bearer resource_metadata="${metadata}", scope="mcp:tools:read"`);

    res = await call(await token((c) => (c.aud = "https://other.example")));
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toMatch(/^Bearer error="invalid_token", .*resource_metadata=/);

    res = await call(await token());
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("user-1");

    res = await call(await token((c) => (c.scp = ["offline_access"])));
    expect(res.status).toBe(403);
    expect(res.headers.get("www-authenticate")).toBe(`Bearer error="insufficient_scope", resource_metadata="${metadata}", scope="offline_access mcp:tools:read"`);

    res = await call(await token(), "?tool=write");
    expect(res.status).toBe(403);
    expect(res.headers.get("www-authenticate")).toContain('scope="mcp:tools:read offline_access mcp:tools:write"');

    res = await call(await token((c) => (c.scp = ["mcp:tools:read", "mcp:tools:write"])), "?tool=write");
    expect(res.status).toBe(200);
  });
});
