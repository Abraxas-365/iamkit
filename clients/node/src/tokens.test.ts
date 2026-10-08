import { describe, expect, it } from "vitest";
import { createJwtVerifier, createIntrospectionVerifier, createKeySet, hasMFA, hasPermission, isImpersonated, verifyIdToken, verifyLogoutToken, BackchannelLogoutEvent } from "./tokens.js";
import { IAMKitError } from "./errors.js";
import { expected, fakeFetch, issuer, jwksFetch, rsaSigner, sign, userClaims } from "./testing/helpers.js";

describe("createJwtVerifier", () => {
  it("accepts a user token inside the expected boundaries", async () => {
    const signer = await rsaSigner("k1");
    const verifier = createJwtVerifier({ ...expected, keySet: { fetch: jwksFetch(signer).fetch } });
    const claims = await verifier.verify(await sign(signer, userClaims({ amr: ["pwd", "otp", "mfa"] })));
    expect(claims.organization_id).toBe("org-1");
    expect(hasPermission(claims, "invoices:read")).toBe(true);
    expect(hasPermission(claims, "invoices:read", "invoices:write")).toBe(false);
    expect(hasPermission(claims)).toBe(false);
    expect(hasMFA(claims)).toBe(true);
    expect(isImpersonated(claims)).toBe(false);
  });

  it("accepts machine tokens without organization or session", async () => {
    const signer = await rsaSigner("k1");
    const verifier = createJwtVerifier({ ...expected, keySet: { fetch: jwksFetch(signer).fetch } });
    const claims = await verifier.verify(await sign(signer, userClaims({ purpose: "machine", organization_id: undefined, sid: undefined })));
    expect(claims.purpose).toBe("machine");
  });

  it.each([
    ["another environment", { environment_id: "env-2" }],
    ["another application", { application_id: "app-2" }],
    ["another resource", { resource_id: "res-2" }],
    ["another audience", { aud: ["https://other.example.com"] }],
    ["another issuer", { iss: "https://evil.example.com" }],
    ["a user token without session", { sid: undefined }],
    ["a machine token with an organization", { purpose: "machine", sid: undefined }],
    ["an unknown purpose", { purpose: "pat" }],
  ])("refuses %s", async (_, overrides) => {
    const signer = await rsaSigner("k1");
    const verifier = createJwtVerifier({ ...expected, keySet: { fetch: jwksFetch(signer).fetch } });
    await expect(verifier.verify(await sign(signer, userClaims(overrides)))).rejects.toMatchObject({ status: 401, code: "UNAUTHORIZED" });
  });

  it("refuses expired tokens, unknown keys and other algorithms", async () => {
    const signer = await rsaSigner("k1");
    const stranger = await rsaSigner("k2");
    const verifier = createJwtVerifier({ ...expected, keySet: { fetch: jwksFetch(signer).fetch } });
    await expect(verifier.verify(await sign(signer, userClaims(), { expiresIn: Math.floor(Date.now() / 1000) - 10 }))).rejects.toMatchObject({ status: 401 });
    await expect(verifier.verify(await sign(stranger, userClaims()))).rejects.toMatchObject({ status: 401 });
    await expect(verifier.verify("not-a-jwt")).rejects.toMatchObject({ status: 401 });
    const header = Buffer.from(JSON.stringify({ alg: "none", kid: "k1" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify(userClaims({ exp: Math.floor(Date.now() / 1000) + 60 }))).toString("base64url");
    await expect(verifier.verify(`${header}.${payload}.`)).rejects.toMatchObject({ status: 401 });
  });

  it("follows key rotation by refetching on an unknown kid", async () => {
    const old = await rsaSigner("old");
    const next = await rsaSigner("next");
    let published = [old];
    const { fetch, calls } = fakeFetch(() => ({ body: { keys: published.map((s) => s.jwk) } }));
    const keys = createKeySet({ issuer, fetch, cooldownMs: 0 });
    const verifier = createJwtVerifier({ ...expected, keys });
    await verifier.verify(await sign(old, userClaims()));
    published = [old, next];
    await verifier.verify(await sign(next, userClaims()));
    expect(calls.map((c) => c.url)).toEqual([`${issuer}/.well-known/jwks.json`, `${issuer}/.well-known/jwks.json`]);
  });

  it("reports an unreachable JWKS as 503, not as a bad token", async () => {
    const signer = await rsaSigner("k1");
    const { fetch } = fakeFetch(() => ({ status: 500, body: {} }));
    const verifier = createJwtVerifier({ ...expected, keySet: { fetch } });
    await expect(verifier.verify(await sign(signer, userClaims()))).rejects.toMatchObject({ status: 503, code: "JWKS_UNAVAILABLE" });
  });

  it("requires every expected boundary", () => {
    expect(() => createJwtVerifier({ ...expected, resourceId: "" })).toThrow(IAMKitError);
  });

  it("maps the act claim of impersonated tokens", async () => {
    const signer = await rsaSigner("k1");
    const verifier = createJwtVerifier({ ...expected, keySet: { fetch: jwksFetch(signer).fetch } });
    const claims = await verifier.verify(await sign(signer, userClaims({ act: { sub: "svc-1" } })));
    expect(claims.act).toEqual({ sub: "svc-1" });
    expect(isImpersonated(claims)).toBe(true);
  });
});

describe("createIntrospectionVerifier", () => {
  const active = {
    active: true,
    claims: { ...userClaims(), exp: 2_000_000_000, iat: 1, nbf: 1, actor_account_id: "" },
  };

  it("posts the token to /identity/v1/introspect and checks the boundaries", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: active }));
    const verifier = createIntrospectionVerifier({ ...expected, baseUrl: "https://internal:8080/", fetch });
    const claims = await verifier.verify("tok");
    expect(claims.sub).toBe("user-1");
    expect(claims.act).toBeUndefined();
    expect(calls[0].url).toBe("https://internal:8080/identity/v1/introspect");
    expect(calls[0].headers.get("authorization")).toBe("Bearer tok");
    expect(JSON.parse(calls[0].body)).toEqual({ environment_id: "env-1", audience: expected.audience });
  });

  it("refuses inactive tokens and boundary mismatches", async () => {
    for (const body of [{ active: false }, { ...active, claims: { ...active.claims, resource_id: "res-2" } }, { ...active, claims: { ...active.claims, iss: "x" } }]) {
      const verifier = createIntrospectionVerifier({ ...expected, baseUrl: issuer, fetch: fakeFetch(() => ({ body })).fetch });
      await expect(verifier.verify("tok")).rejects.toMatchObject({ status: 401 });
    }
    const unauthorized = fakeFetch(() => ({ status: 401, body: { error: { code: "UNAUTHORIZED", message: "no" } } }));
    await expect(createIntrospectionVerifier({ ...expected, baseUrl: issuer, fetch: unauthorized.fetch }).verify("tok")).rejects.toMatchObject({ status: 401 });
  });

  it("fails closed when IAMKit errors", async () => {
    const down = fakeFetch(() => ({ status: 503, body: { error: { code: "UNAVAILABLE", message: "down" } } }));
    await expect(createIntrospectionVerifier({ ...expected, baseUrl: issuer, fetch: down.fetch }).verify("tok")).rejects.toMatchObject({ status: 503 });
  });
});

describe("verifyLogoutToken", () => {
  const logout = (overrides: Record<string, unknown> = {}) => ({
    iss: issuer,
    aud: "client-1",
    sub: "user-1",
    sid: "session-1",
    jti: "j1",
    events: { [BackchannelLogoutEvent]: {} },
    ...overrides,
  });

  it("accepts a logout token for the client", async () => {
    const signer = await rsaSigner("k1");
    const keys = createKeySet({ issuer, fetch: jwksFetch(signer).fetch });
    const token = await verifyLogoutToken(await sign(signer, logout(), { typ: "logout+jwt" }), { issuer, clientId: "client-1", keys });
    expect(token).toMatchObject({ sub: "user-1", sid: "session-1", aud: ["client-1"] });
  });

  it.each([
    ["another audience", { aud: "client-2" }],
    ["no event", { events: {} }],
    ["a nonce", { nonce: "n" }],
    ["no sid", { sid: undefined }],
  ])("refuses %s", async (_, overrides) => {
    const signer = await rsaSigner("k1");
    const keys = createKeySet({ issuer, fetch: jwksFetch(signer).fetch });
    await expect(verifyLogoutToken(await sign(signer, logout(overrides)), { issuer, clientId: "client-1", keys })).rejects.toMatchObject({ status: 400 });
  });
});

describe("verifyIdToken", () => {
  it("checks audience and nonce", async () => {
    const signer = await rsaSigner("k1");
    const keys = createKeySet({ issuer, fetch: jwksFetch(signer).fetch });
    const raw = await sign(signer, { iss: issuer, aud: "client-1", sub: "user-1", nonce: "n-1", email: "a@example.com" });
    await expect(verifyIdToken(raw, { issuer, clientId: "client-1", keys, nonce: "n-1" })).resolves.toMatchObject({ email: "a@example.com" });
    await expect(verifyIdToken(raw, { issuer, clientId: "client-1", keys, nonce: "other" })).rejects.toMatchObject({ status: 401 });
    await expect(verifyIdToken(raw, { issuer, clientId: "client-2", keys, nonce: "n-1" })).rejects.toMatchObject({ status: 401 });
  });
});
