import { describe, expect, it } from "vitest";
import { createAccount, IAMKitError, isReauthenticationRequired, switchRefusal } from "./index.js";
import { base64url } from "./pkce.js";
import { creationOptions } from "./account.js";

interface Call {
  method: string;
  path: string;
  query: Record<string, string>;
  body: Record<string, unknown> | undefined;
  auth: string | null;
}

type Answer = { status?: number; body?: unknown };

function setup(answer: (call: Call) => Answer = () => ({ body: {} })) {
  const calls: Call[] = [];
  const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    const query: Record<string, string> = {};
    url.searchParams.forEach((value, key) => {
      query[key] = value;
    });
    const call: Call = {
      method: init?.method ?? "GET",
      path: url.pathname,
      query,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
      auth: headers.get("Authorization"),
    };
    calls.push(call);
    const { status = 200, body } = answer(call);
    return new Response(status === 204 || body === undefined ? null : JSON.stringify(body), { status });
  }) as typeof fetch;
  let n = 0;
  const account = createAccount({
    baseUrl: "https://id.example.com/",
    environmentId: "env-1",
    audience: "https://api.example.com",
    fetch: fetcher,
    getAccessToken: () => `at-${++n}`,
  });
  return { account, calls };
}

const scope = { environment_id: "env-1", audience: "https://api.example.com" };

describe("createAccount", () => {
  it("reads the token before every call and puts the scope in the query", async () => {
    const { account, calls } = setup(() => ({ body: { id: "u1", email: "ada@example.com" } }));
    expect((await account.me()).email).toBe("ada@example.com");
    await account.me();
    expect(calls.map((c) => c.auth)).toEqual(["Bearer at-1", "Bearer at-2"]);
    expect(calls[0]).toMatchObject({ method: "GET", path: "/identity/v1/me", query: scope });
  });

  it("updates the profile and the properties with the scope in the body", async () => {
    const { account, calls } = setup((call) => (call.path.endsWith("/profile") ? { body: { profile: { nickname: "ada" } } } : { status: 204 }));
    await account.updateMe({ name: "Ada", avatarUrl: null });
    expect(await account.updateProperties({ nickname: "ada" })).toEqual({ nickname: "ada" });
    expect(await account.properties()).toEqual({ nickname: "ada" });
    expect(calls[0]).toMatchObject({ method: "PATCH", path: "/identity/v1/me", query: {}, body: { ...scope, name: "Ada", avatar_url: null } });
    expect(calls[1]).toMatchObject({ method: "PATCH", path: "/identity/v1/me/profile", body: { ...scope, profile: { nickname: "ada" } } });
    expect(calls[2]).toMatchObject({ method: "GET", path: "/identity/v1/me/profile", query: scope });
  });

  it("manages the phone", async () => {
    const { account, calls } = setup((call) => (call.path.endsWith("/phone") && call.method === "POST" ? { status: 202, body: { destination: "+51 ***", expires_at: "x" } } : { status: 204 }));
    expect((await account.phone.start("+51999999999")).destination).toBe("+51 ***");
    await account.phone.verify("+51999999999", "123456");
    await account.phone.remove();
    expect(calls[0].body).toEqual({ ...scope, phone: "+51999999999" });
    expect(calls[1]).toMatchObject({ path: "/identity/v1/me/phone/verify", body: { ...scope, phone: "+51999999999", code: "123456" } });
    expect(calls[2]).toMatchObject({ method: "DELETE", path: "/identity/v1/me/phone", query: scope, body: undefined });
  });

  it("changes the password and surfaces the error codes", async () => {
    const { account, calls } = setup((call) => {
      switch (call.body?.current_password) {
        case "stale":
          return { status: 403, body: { error: { code: "REAUTHENTICATION_REQUIRED", message: "sign in again", http_status: 403 } } };
        case "wrong":
          return { status: 422, body: { error: { code: "INVALID_CURRENT_PASSWORD", message: "nope", http_status: 422 } } };
        case "policy":
          return { status: 400, body: { error: { code: "PASSWORD_POLICY", message: "too short", http_status: 400, details: { rule: "length", min_length: 12 } } } };
        default:
          return { body: { sessions_revoked: 2 } };
      }
    });
    expect(await account.changePassword("old", "new")).toEqual({ sessions_revoked: 2 });
    expect(calls[0]).toMatchObject({ method: "POST", path: "/identity/v1/me/password", query: scope, body: { current_password: "old", new_password: "new" } });

    const stale = await account.changePassword("stale", "new").catch((e) => e);
    expect(stale).toBeInstanceOf(IAMKitError);
    expect(isReauthenticationRequired(stale)).toBe(true);
    expect(stale.status).toBe(403);
    expect(await account.changePassword("wrong", "new").catch((e) => e.code)).toBe("INVALID_CURRENT_PASSWORD");
    const policy = await account.changePassword("policy", "x").catch((e) => e);
    expect(policy.code).toBe("PASSWORD_POLICY");
    expect(policy.details).toEqual({ rule: "length", min_length: 12 });
  });

  it("lists and revokes sessions", async () => {
    const { account, calls } = setup((call) => {
      if (call.path.endsWith("/revoke-others")) {
        return { body: { count: 3 } };
      }
      return call.method === "GET" ? { body: { items: null, page: { total: 0, limit: 20, offset: 0 } } } : { status: 204 };
    });
    expect((await account.sessions.list({ limit: 5, offset: 10 })).items).toEqual([]);
    await account.sessions.revoke("s/1");
    expect(await account.sessions.revokeOthers()).toBe(3);
    expect(calls[0]).toMatchObject({ path: "/identity/v1/me/sessions", query: { ...scope, limit: "5", offset: "10" } });
    expect(calls[1]).toMatchObject({ method: "DELETE", path: "/identity/v1/me/sessions/s%2F1" });
    expect(calls[2]).toMatchObject({ method: "POST", path: "/identity/v1/me/sessions/revoke-others" });
  });

  it("manages API keys", async () => {
    const { account, calls } = setup((call) => {
      if (call.method === "DELETE") {
        return { status: 204 };
      }
      if (call.path.endsWith("/options")) {
        return { body: { enabled: true, max_ttl_days: 30, resources: [] } };
      }
      return call.method === "POST" ? { status: 201, body: { id: "k1", value: "ik_key_example" } } : { body: { items: [{ id: "k1" }], page: { total: 1, limit: 20, offset: 0 } } };
    });
    expect((await account.apiKeys.list({ state: "active", resourceId: "r1", limit: 10 })).items).toHaveLength(1);
    expect((await account.apiKeys.options()).enabled).toBe(true);
    expect((await account.apiKeys.create({ name: "ci", resource_id: "r1", permissions: ["invoices:read"], expires_in: "720h" })).value).toBe("ik_key_example");
    await account.apiKeys.revoke("k1");
    expect(calls[0].query).toEqual({ ...scope, state: "active", resource_id: "r1", limit: "10" });
    expect(calls[2]).toMatchObject({ method: "POST", path: "/identity/v1/me/api-keys", query: scope, body: { name: "ci", resource_id: "r1", permissions: ["invoices:read"], expires_in: "720h" } });
    expect(calls[3]).toMatchObject({ method: "DELETE", path: "/identity/v1/me/api-keys/k1" });
  });

  it("lists the organizations", async () => {
    const { account, calls } = setup(() => ({ body: null }));
    expect(await account.organizations()).toEqual([]);
    expect(calls[0]).toMatchObject({ path: "/identity/v1/organizations", query: scope });
  });

  it("switches organization from the token's claims or an explicit boundary", async () => {
    const claims = base64url(new TextEncoder().encode(JSON.stringify({ environment_id: "env-1", organization_id: "org-1", application_id: "app-1", resource_id: "res-1" })));
    const jwt = `h.${claims}.s`;
    const fetcher = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      return body.switch_organization_id === "sso-org"
        ? new Response(JSON.stringify({ error: { code: "REAUTHENTICATION_REQUIRED", message: "sign in again", http_status: 403, details: { organization_id: "sso-org", reason: "sso" } } }), { status: 403 })
        : new Response(JSON.stringify({ access_token: "at2", refresh_token: "rt2", token_type: "Bearer", expires_in: 900 }), { status: 200 });
    }) as typeof fetch;
    const sent: unknown[] = [];
    const recording = ((input: RequestInfo | URL, init?: RequestInit) => {
      sent.push({ url: String(input), body: JSON.parse(String(init?.body)) });
      return fetcher(input, init);
    }) as typeof fetch;
    const account = createAccount({ baseUrl: "https://id.example.com", environmentId: "env-1", audience: "aud", fetch: recording, getAccessToken: () => jwt });

    const tokens = await account.switchOrganization("ik_refresh_1", "org-2");
    expect(tokens).toMatchObject({ access_token: "at2", refresh_token: "rt2" });
    expect(sent[0]).toEqual({
      url: "https://id.example.com/identity/v1/refresh",
      body: { environment_id: "env-1", organization_id: "org-1", application_id: "app-1", resource_id: "res-1", refresh_token: "ik_refresh_1", switch_organization_id: "org-2" },
    });

    const refused = await account.switchOrganization("ik_refresh_1", "sso-org", { environmentId: "e", organizationId: "o", applicationId: "a", resourceId: "r" }).catch((e) => e);
    expect(switchRefusal(refused)).toEqual({ organizationId: "sso-org", reason: "sso" });
    expect(sent[1]).toMatchObject({ body: { organization_id: "o", switch_organization_id: "sso-org" } });
    expect(switchRefusal(new IAMKitError(403, "FORBIDDEN", "no"))).toBeUndefined();

    const opaque = createAccount({ baseUrl: "https://id.example.com", environmentId: "e", audience: "a", fetch: recording, getAccessToken: () => "opaque" });
    await expect(opaque.switchOrganization("ik_refresh_1", "org-2")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("runs the factor flows", async () => {
    const { account, calls } = setup((call) => {
      if (call.method === "DELETE") {
        return { status: 204 };
      }
      if (call.path.endsWith("/me/factors")) {
        return {
          body: {
            factors: [
              { id: "f1", kind: "totp" },
              { id: "f2", kind: "webauthn", passkey: true, name: "laptop" },
            ],
            recovery_codes_remaining: 8,
          },
        };
      }
      if (call.path.endsWith("/confirm") || call.path.endsWith("/recovery-codes")) {
        return { body: { recovery_codes: ["aaaa-bbbb"] } };
      }
      return { status: 201, body: { factor_id: "f1", otpauth_uri: "otpauth://totp/x", secret: "S" } };
    });
    const summary = await account.mfa.factors();
    expect(summary.recovery_codes_remaining).toBe(8);
    expect((await account.passkeys.list()).map((f) => f.id)).toEqual(["f2"]);
    expect((await account.mfa.totp.start()).factor_id).toBe("f1");
    expect(await account.mfa.totp.confirm("123456")).toEqual(["aaaa-bbbb"]);
    await account.mfa.email.start();
    expect(await account.mfa.email.confirm("111111")).toEqual(["aaaa-bbbb"]);
    await account.mfa.email.send();
    await account.mfa.email.remove("222222");
    await account.mfa.sms.start("+51999999999");
    await account.mfa.sms.confirm("333333");
    await account.mfa.sms.send();
    await account.mfa.sms.remove("444444");
    await account.mfa.totp.remove("555555");
    expect(await account.mfa.recoveryCodes("666666")).toEqual(["aaaa-bbbb"]);

    const by = (method: string, path: string) => calls.find((c) => c.method === method && c.path === path);
    expect(calls[0]).toMatchObject({ method: "GET", path: "/identity/v1/me/factors", query: scope });
    expect(by("POST", "/identity/v1/me/factors/totp")?.body).toEqual(scope);
    expect(by("POST", "/identity/v1/me/factors/totp/confirm")?.body).toEqual({ ...scope, code: "123456" });
    expect(by("POST", "/identity/v1/me/factors/email/challenge")?.body).toEqual(scope);
    expect(by("DELETE", "/identity/v1/me/factors/email")?.body).toEqual({ ...scope, code: "222222" });
    expect(by("POST", "/identity/v1/me/factors/sms")?.body).toEqual({ ...scope, phone: "+51999999999" });
    expect(by("DELETE", "/identity/v1/me/factors/sms")?.body).toEqual({ ...scope, code: "444444" });
    expect(by("DELETE", "/identity/v1/me/factors/totp")?.body).toEqual({ ...scope, code: "555555" });
    expect(by("POST", "/identity/v1/me/factors/recovery-codes")?.body).toEqual({ ...scope, code: "666666" });
  });

  it("manages security keys and passkeys", async () => {
    const { account, calls } = setup((call) => {
      if (call.method === "DELETE") {
        return { status: 204 };
      }
      if (call.method === "PATCH") {
        return { body: { id: "f2", kind: "webauthn", name: "renamed" } };
      }
      if (call.path.endsWith("/confirm")) {
        return { status: 201, body: { factor: { id: "f2", kind: "webauthn" }, recovery_codes: null } };
      }
      return { status: 201, body: { webauthn_session: "ik_wa_1", options: { publicKey: {} }, expires_at: "x" } };
    });
    const ceremony = await account.passkeys.begin("laptop", { passkey: true });
    expect(ceremony.webauthn_session).toBe("ik_wa_1");
    const registered = await account.passkeys.finish(ceremony.webauthn_session, { id: "cred" });
    expect(registered.factor.id).toBe("f2");
    expect((await account.passkeys.rename("f2", "renamed")).name).toBe("renamed");
    await account.passkeys.remove("f2", { code: "123456" });
    await account.passkeys.remove("f2", { webauthnSession: "ik_wa_2", credential: { id: "cred" } });
    expect(calls[0].body).toEqual({ ...scope, name: "laptop", passkey: true });
    expect(calls[1]).toMatchObject({ path: "/identity/v1/me/factors/webauthn/confirm", body: { ...scope, webauthn_session: "ik_wa_1", credential: { id: "cred" } } });
    expect(calls[2]).toMatchObject({ method: "PATCH", path: "/identity/v1/me/factors/webauthn/f2", body: { ...scope, name: "renamed" } });
    expect(calls[3]).toMatchObject({ method: "DELETE", body: { ...scope, code: "123456" } });
    expect(calls[4].body).toEqual({ ...scope, webauthn_session: "ik_wa_2", credential: { id: "cred" } });
  });

  it("throws the server's error for any failed call", async () => {
    const { account } = setup(() => ({ status: 401, body: { error: { code: "UNAUTHORIZED", message: "expired", http_status: 401 } } }));
    await expect(account.sessions.list()).rejects.toMatchObject({ name: "IAMKitError", status: 401, code: "UNAUTHORIZED" });
  });
});

describe("registration options", () => {
  it("decodes the base64url buffers", () => {
    const o = creationOptions({
      publicKey: { challenge: base64url(new Uint8Array([1, 2])), user: { id: base64url(new Uint8Array([7])), name: "ada" }, excludeCredentials: [{ id: base64url(new Uint8Array([9])), type: "public-key" }], rp: { name: "x" } },
    });
    expect([...new Uint8Array(o.challenge as ArrayBuffer)]).toEqual([1, 2]);
    expect([...new Uint8Array(o.user.id as ArrayBuffer)]).toEqual([7]);
    expect([...new Uint8Array(o.excludeCredentials![0].id as ArrayBuffer)]).toEqual([9]);
    expect(o.user.name).toBe("ada");
  });
});
