import { generateKeyPair, SignJWT, type CryptoKey, type JWTPayload } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { createIntrospector } from "./introspection.js";
import { createResourceServer, ResourceError, type ResourceServer } from "./resource-server.js";

const issuer = "https://iam.example";
const resource = "https://mcp.example.com/mcp";
const live = { active: true, token_use: "access_token", sub: "user-1", sid: "s-1", client_id: "client-1", scope: "mcp:tools:read", aud: [resource] };

/** A fake IAMKit introspection endpoint answering with `answer` (undefined: 503). */
function fakeIAMKit() {
  const state: { answer?: Record<string, unknown>; calls: number; auth?: string } = { answer: live, calls: 0 };
  const fetch = async (input: string | URL | Request, init?: RequestInit) => {
    state.calls++;
    state.auth = new Headers(init?.headers).get("authorization") ?? undefined;
    expect(String(input)).toBe(`${issuer}/oauth/introspect`);
    if (!state.answer) return new Response("", { status: 503 });
    return new Response(JSON.stringify(state.answer), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  return { state, fetch };
}

describe("introspection", () => {
  let key: CryptoKey;
  let keys: () => Promise<CryptoKey>;

  const token = (edit: (c: JWTPayload) => void = () => {}) => {
    const now = Math.floor(Date.now() / 1000);
    const c: JWTPayload = {
      iss: issuer, sub: "user-1", aud: [resource], exp: now + 900, iat: now, environment_id: "env-1", organization_id: "org-1",
      sid: "s-1", purpose: "application", scp: ["mcp:tools:read"], resource, client_id: "client-1", oauth_client_id: "client-1",
    };
    edit(c);
    return new SignJWT(c).setProtectedHeader({ alg: "RS256", kid: "k1" }).sign(key);
  };
  const server = (fetch: ReturnType<typeof fakeIAMKit>["fetch"], cacheTtlSec = 0): ResourceServer =>
    createResourceServer({ issuer, resource, environmentId: "env-1", keys, introspection: { clientId: "rs-client", clientSecret: "rs-secret", cacheTtlSec, fetch } });

  beforeAll(async () => {
    const pair = await generateKeyPair("RS256");
    key = pair.privateKey;
    keys = async () => pair.publicKey;
  });

  it("refuses incomplete configuration", () => {
    expect(() => createIntrospector(issuer, { clientId: "", clientSecret: "s" })).toThrow(TypeError);
    expect(() => createIntrospector(issuer, { clientId: "c", clientSecret: "s", cacheTtlSec: -1 })).toThrow(TypeError);
  });

  it("asks on every request by default and stops a revoked token at once", async () => {
    const iam = fakeIAMKit();
    const rs = server(iam.fetch);
    const raw = await token();
    await expect(rs.verify(raw)).resolves.toMatchObject({ sub: "user-1" });
    await rs.verify(raw);
    expect(iam.state.calls).toBe(2);
    expect(iam.state.auth).toBe(`Basic ${Buffer.from("rs-client:rs-secret").toString("base64")}`);
    iam.state.answer = { active: false };
    await expect(rs.verify(raw)).rejects.toMatchObject({ kind: "invalid_token" });
  });

  it("refuses an answer about another token, client or grant", async () => {
    const iam = fakeIAMKit();
    const rs = server(iam.fetch);
    const raw = await token();
    const { client_id: _client, scope: _scope, aud: _aud, ...bare } = live;
    for (const answer of [
      { ...live, sub: "user-2" },
      { ...live, sid: "s-2" },
      { ...live, aud: ["https://other.example"] },
      { ...bare, client_id: "client-1", scope: "mcp:tools:read" },
      { ...live, token_use: "refresh_token" },
      { ...live, client_id: "client-2" },
      { ...bare, scope: "mcp:tools:read", aud: [resource] },
      { ...live, scope: "" },
      { ...bare, client_id: "client-1", aud: [resource] },
      { ...live, scope: "mcp:tools:read mcp:tools:write" },
      { ...live, scope: "mcp:tools:write" },
    ]) {
      iam.state.answer = answer;
      await expect(rs.verify(raw)).rejects.toMatchObject({ kind: "invalid_token" });
    }
    // Scopes compare as sets.
    iam.state.answer = { ...live, scope: "mcp:tools:read mcp:tools:read" };
    await expect(rs.verify(raw)).resolves.toMatchObject({ clientId: "client-1" });
    // A token without client_id cannot be matched to the answer.
    iam.state.answer = live;
    await expect(rs.verify(await token((c) => delete c.client_id))).rejects.toMatchObject({ kind: "invalid_token" });
    // An external client's client_id is its URL, not the row id.
    iam.state.answer = { ...live, client_id: "https://client.example/meta.json" };
    await expect(
      rs.verify(await token((c) => Object.assign(c, { client_id: "https://client.example/meta.json", oauth_client_id: "row-9" }))),
    ).resolves.toMatchObject({ clientId: "https://client.example/meta.json", oauthClientId: "row-9" });
  });

  it("fails closed with 503 and no challenge", async () => {
    const iam = fakeIAMKit();
    const rs = server(iam.fetch);
    iam.state.answer = undefined;
    const error = await rs.verify(await token()).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ResourceError);
    expect((error as ResourceError).kind).toBe("unavailable");
    const headers: Record<string, string> = {};
    const res = { statusCode: 0, setHeader: (k: string, v: string) => (headers[k.toLowerCase()] = v), end: () => {} };
    rs.deny(res as never, error);
    expect(res.statusCode).toBe(503);
    expect(headers["www-authenticate"]).toBeUndefined();
  });

  it("never introspects a token that fails the local checks", async () => {
    const iam = fakeIAMKit();
    const rs = server(iam.fetch);
    await expect(rs.verify(await token((c) => (c.aud = "https://other.example")))).rejects.toMatchObject({ kind: "invalid_token" });
    expect(iam.state.calls).toBe(0);
  });

  it("caches active answers only, never past exp", async () => {
    const iam = fakeIAMKit();
    let now = 1_000_000;
    const check = createIntrospector(issuer, { clientId: "c", clientSecret: "s", cacheTtlSec: 60, fetch: iam.fetch }, () => now);
    const same = (a: string) => a === resource;
    const t = { sub: "user-1", sessionId: "s-1", clientId: "client-1", scopes: ["mcp:tools:read"], exp: now + 30 };
    expect(await check.check("raw-1", t, same)).toBe("active");
    expect(await check.check("raw-1", t, same)).toBe("active");
    expect(iam.state.calls).toBe(1);
    now += 31; // past exp, before the TTL
    await check.check("raw-1", t, same);
    expect(iam.state.calls).toBe(2);
    iam.state.answer = { active: false };
    expect(await check.check("raw-2", t, same)).toBe("inactive");
    iam.state.answer = live;
    expect(await check.check("raw-2", t, same)).toBe("active");
    expect(iam.state.calls).toBe(4);
  });
});
