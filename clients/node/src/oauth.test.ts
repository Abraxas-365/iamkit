import { generateKeyPairSync } from "node:crypto";
import { createLocalJWKSet, exportJWK, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { KeyLogin, OAuthClient, createPKCE, randomToken, GrantTypes, TokenTypes } from "./oauth.js";
import { createHash } from "node:crypto";
import { fakeFetch, issuer } from "./testing/helpers.js";

const tokens = { access_token: "at", token_type: "bearer", expires_in: 900, refresh_token: "rt", id_token: "idt", scope: "openid" };

function form(body: string): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(body));
}

describe("OAuthClient", () => {
  it("builds the authorize URL with PKCE, nonce and the organization hint", () => {
    const client = new OAuthClient({ baseUrl: `${issuer}/`, clientId: "client-1" });
    const pkce = createPKCE();
    expect(pkce.challenge).toBe(createHash("sha256").update(pkce.verifier).digest("base64url"));
    const url = new URL(client.authorizationUrl({ redirectUri: "https://app.example.com/cb", state: "state-123", nonce: "n", codeChallenge: pkce.challenge, scopes: ["email", "openid"], organizationId: "org-1" }));
    expect(url.origin + url.pathname).toBe(`${issuer}/oauth/authorize`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: "client-1",
      response_type: "code",
      redirect_uri: "https://app.example.com/cb",
      scope: "openid email",
      state: "state-123",
      nonce: "n",
      code_challenge: pkce.challenge,
      code_challenge_method: "S256",
      organization_id: "org-1",
    });
    expect(() => client.authorizationUrl({ redirectUri: "x", state: "short", nonce: "n", codeChallenge: "c" })).toThrow();
    expect(randomToken()).toMatch(/^[A-Za-z0-9_-]{32}$/);
  });

  it("exchanges a code with HTTP Basic client authentication", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: tokens }));
    const client = new OAuthClient({ baseUrl: issuer, clientId: "client 1", clientSecret: "s3cr:t", fetch });
    await expect(client.exchangeCode("code-1", "https://app/cb", "verifier")).resolves.toEqual(tokens);
    expect(calls[0].url).toBe(`${issuer}/oauth/token`);
    expect(calls[0].headers.get("content-type")).toBe("application/x-www-form-urlencoded");
    expect(calls[0].headers.get("authorization")).toBe(`Basic ${Buffer.from("client+1:s3cr%3At").toString("base64")}`);
    expect(form(calls[0].body)).toEqual({ grant_type: "authorization_code", code: "code-1", redirect_uri: "https://app/cb", code_verifier: "verifier", client_id: "client 1" });
  });

  it("sends the secret in the form with client_secret_post and nothing for public clients", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: tokens }));
    await new OAuthClient({ baseUrl: issuer, clientId: "c", auth: { method: "client_secret_post", secret: "s" }, fetch }).refresh("rt");
    await new OAuthClient({ baseUrl: issuer, clientId: "c", fetch }).refresh("rt");
    expect(form(calls[0].body)).toEqual({ grant_type: "refresh_token", refresh_token: "rt", client_id: "c", client_secret: "s" });
    expect(calls[0].headers.get("authorization")).toBeNull();
    expect(form(calls[1].body)).toEqual({ grant_type: "refresh_token", refresh_token: "rt", client_id: "c" });
    expect(calls[1].headers.get("authorization")).toBeNull();
  });

  it("signs a fresh private_key_jwt assertion per request", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const { fetch, calls } = fakeFetch(() => ({ body: tokens }));
    const client = new OAuthClient({ baseUrl: "http://internal:8080", issuer, clientId: "svc-1", auth: { method: "private_key_jwt", key: pem, kid: "key-1" }, fetch });
    await client.clientCredentials();
    await client.clientCredentials();
    const keys = createLocalJWKSet({ keys: [{ ...(await exportJWK(publicKey)), kid: "key-1" }] });
    const sent = calls.map((c) => form(c.body));
    expect(sent[0].grant_type).toBe("client_credentials");
    expect(sent[0].client_assertion_type).toBe("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    const { payload, protectedHeader } = await jwtVerify(sent[0].client_assertion, keys, { issuer: "svc-1", subject: "svc-1", audience: `${issuer}/oauth/token` });
    expect(protectedHeader).toMatchObject({ alg: "ES256", kid: "key-1" });
    expect(payload.exp! - payload.iat!).toBe(60);
    const second = await jwtVerify(sent[1].client_assertion, keys);
    expect(second.payload.jti).not.toBe(payload.jti);
  });

  it("refuses keys it cannot sign assertions with", async () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const client = new OAuthClient({ baseUrl: issuer, clientId: "c", auth: { method: "private_key_jwt", key: privateKey, kid: "k" }, fetch: fakeFetch(() => ({ body: tokens })).fetch });
    await expect(client.clientCredentials()).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("surfaces OAuth errors with their code and description", async () => {
    const { fetch } = fakeFetch(() => ({ status: 400, body: { error: "invalid_grant", error_description: "code reused" } }));
    await expect(new OAuthClient({ baseUrl: issuer, clientId: "c", fetch }).exchangeCode("x", "y", "z")).rejects.toMatchObject({
      status: 400,
      code: "invalid_grant",
      message: "code reused",
    });
  });

  it("revokes, reads UserInfo and introspects", async () => {
    const { fetch, calls } = fakeFetch((call) => {
      if (call.url.endsWith("/oauth/revoke")) return { status: 200 };
      if (call.url.endsWith("/oauth/userinfo")) return { body: { sub: "u", environment_id: "e", email: "a@b.c" } };
      return { body: { active: true, sub: "u", token_use: "access_token" } };
    });
    const client = new OAuthClient({ baseUrl: issuer, clientId: "c", clientSecret: "s", fetch });
    await client.revoke("rt");
    expect(form(calls[0].body)).toEqual({ token: "rt", client_id: "c" });
    await expect(client.userInfo("at")).resolves.toMatchObject({ email: "a@b.c" });
    expect(calls[1].method).toBe("GET");
    expect(calls[1].headers.get("authorization")).toBe("Bearer at");
    await expect(client.introspect("at")).resolves.toMatchObject({ active: true });
    expect(form(calls[2].body)).toEqual({ token: "at" });
    expect(calls[2].headers.get("authorization")).toMatch(/^Basic /);
    await expect(new OAuthClient({ baseUrl: issuer, clientId: "c", fetch }).introspect("at")).rejects.toMatchObject({ code: "invalid_client" });
  });

  it("polls a device authorization until approved, slowing down when asked", async () => {
    const answers = [{ status: 400, body: { error: "authorization_pending" } }, { status: 400, body: { error: "slow_down" } }, { body: tokens }];
    const { fetch, calls } = fakeFetch((call) => (call.url.endsWith("/device_authorization") ? { body: { device_code: "dc", user_code: "BCDF", verification_uri: "v", verification_uri_complete: "vc", expires_in: 600, interval: 1 } } : answers.shift()!));
    const client = new OAuthClient({ baseUrl: issuer, clientId: "tv", fetch });
    const authorization = await client.authorizeDevice(["openid", "offline_access"]);
    expect(form(calls[0].body)).toEqual({ scope: "openid offline_access", client_id: "tv" });
    await expect(client.waitForDevice(authorization, { stepMs: 1 })).resolves.toEqual(tokens);
    expect(form(calls[1].body)).toEqual({ grant_type: GrantTypes.DeviceCode, device_code: "dc", client_id: "tv" });
    expect(calls).toHaveLength(4);
  });

  it("stops polling on denial or abort", async () => {
    const denied = fakeFetch(() => ({ status: 400, body: { error: "access_denied" } }));
    const authorization = { device_code: "dc", user_code: "u", verification_uri: "v", verification_uri_complete: "vc", expires_in: 1, interval: 1 };
    await expect(new OAuthClient({ baseUrl: issuer, clientId: "tv", fetch: denied.fetch }).waitForDevice(authorization, { stepMs: 1 })).rejects.toMatchObject({ code: "access_denied" });
    const pending = fakeFetch(() => ({ status: 400, body: { error: "authorization_pending" } }));
    const controller = new AbortController();
    const wait = new OAuthClient({ baseUrl: issuer, clientId: "tv", fetch: pending.fetch }).waitForDevice(authorization, { stepMs: 5, signal: controller.signal });
    setTimeout(() => controller.abort(new Error("stop")), 20);
    await expect(wait).rejects.toThrow("stop");
  });

  it("exchanges tokens and impersonates", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: { access_token: "x", issued_token_type: TokenTypes.AccessToken, token_type: "bearer", expires_in: 60 } }));
    const client = new OAuthClient({ baseUrl: issuer, clientId: "c", clientSecret: "s", fetch });
    await client.exchangeToken("user-at", "https://billing.example.com", ["billing:read"]);
    await client.impersonate("user-1", "org-1", "ticket 42");
    expect(form(calls[0].body)).toEqual({ grant_type: GrantTypes.TokenExchange, subject_token: "user-at", subject_token_type: TokenTypes.AccessToken, audience: "https://billing.example.com", scope: "billing:read", client_id: "c" });
    expect(form(calls[1].body)).toEqual({ grant_type: GrantTypes.TokenExchange, subject_token: "user-1", subject_token_type: TokenTypes.UserId, organization_id: "org-1", reason: "ticket 42", client_id: "c" });
  });

  it("builds the end-session URL", () => {
    const url = new URL(new OAuthClient({ baseUrl: issuer, clientId: "c" }).endSessionUrl({ idTokenHint: "idt", postLogoutRedirectUri: "https://app/bye", state: "s" }));
    expect(url.pathname).toBe("/oauth/end_session");
    expect(Object.fromEntries(url.searchParams)).toEqual({ client_id: "c", id_token_hint: "idt", post_logout_redirect_uri: "https://app/bye", state: "s" });
  });
});

describe("KeyLogin", () => {
  it("signs an RS256 assertion as the machine user and asks for a token in the boundary", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const { fetch, calls } = fakeFetch(() => ({ body: { access_token: "at", token_type: "bearer", expires_in: 900 } }));
    const login = new KeyLogin({ baseUrl: issuer, userId: "machine-1", kid: "key-1", privateKey: pem, fetch });
    await login.token({ organizationId: "org-1", applicationId: "app-1", resourceId: "res-1" });
    const sent = form(calls[0].body);
    expect(sent).toMatchObject({ grant_type: GrantTypes.JWTBearer, organization_id: "org-1", application_id: "app-1", resource_id: "res-1" });
    expect(sent.client_id).toBeUndefined();
    const keys = createLocalJWKSet({ keys: [{ ...(await exportJWK(publicKey)), kid: "key-1", alg: "RS256" }] });
    const { protectedHeader } = await jwtVerify(sent.assertion, keys, { issuer: "machine-1", subject: "machine-1", audience: `${issuer}/oauth/token` });
    expect(protectedHeader.alg).toBe("RS256");
  });

  it("refuses a malformed key", async () => {
    await expect(new KeyLogin({ baseUrl: issuer, userId: "u", kid: "k", privateKey: "nope" }).assertion()).rejects.toMatchObject({ code: "VALIDATION" });
  });
});
