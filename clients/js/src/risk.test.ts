import { describe, expect, it } from "vitest";
import { captchaProvider, createDeviceId, createSignIn, deviceKey, IAMKitError, isCaptchaRequired, isSignInBlocked, isRiskChallenge, isChallengeUnavailable, type Boundary, type VerifierStore } from "./index";

interface Call {
  method: string;
  url: string;
  body: any;
}

function fake(routes: Record<string, (body: any) => Response>) {
  const calls: Call[] = [];
  const fetcher = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    const text = await request.text();
    const url = new URL(request.url);
    const call = { method: request.method, url: url.pathname, body: text ? JSON.parse(text) : undefined };
    calls.push(call);
    const route = routes[`${request.method} ${url.pathname}`];
    return route ? route(call.body) : json(404, { error: { code: "NOT_FOUND", message: "no route" } });
  };
  return { calls, fetch: fetcher as typeof fetch };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function memory(): VerifierStore & { items: Map<string, string> } {
  const items = new Map<string, string>();
  return { items, getItem: (k) => items.get(k) ?? null, setItem: (k, v) => void items.set(k, v), removeItem: (k) => void items.delete(k) };
}

const boundary: Boundary = { environmentId: "env", organizationId: "org", applicationId: "app", resourceId: "res" };
const pair = { access_token: "at", refresh_token: "rt", token_type: "Bearer", expires_in: 300 };

describe("device id", () => {
  it("is 32 hex characters", () => {
    expect(createDeviceId()).toMatch(/^[0-9a-f]{32}$/);
  });

  it("is created once in the device storage and sent on login, challenge, signup and ldap", async () => {
    const store = memory();
    const f = fake({
      "POST /identity/v1/login": () => json(200, pair),
      "POST /identity/v1/challenges": () => json(202, { challenge_id: "c1", expires_in: 600 }),
      "POST /identity/v1/challenges/verify": () => json(200, pair),
      "POST /identity/v1/signup": () => json(202, { challenge_id: "c2", expires_in: 600 }),
      "POST /identity/v1/federation/ldap/login": () => json(200, pair),
    });
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch, deviceStorage: store });
    await iam.login(boundary, { login: "ada", password: "pw" });
    await iam.sendCode({ environmentId: "env", login: "ada", purpose: "login" });
    await iam.verifyCode(boundary, { challengeId: "c1", code: "123456" });
    await iam.signup.start({ environmentId: "env", email: "a@example.com", name: "Ada" });
    await iam.federation.ldap(boundary, { connectionId: "conn", email: "a@example.com", password: "pw" });
    const id = store.items.get(deviceKey)!;
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(f.calls).toHaveLength(5);
    for (const call of f.calls) {
      expect(call.body.device_id).toBe(id);
    }
    expect(iam.deviceId()).toBe(id);
  });

  it("reuses a stored id", async () => {
    const store = memory();
    store.setItem(deviceKey, "abcdef0123456789abcdef0123456789");
    const f = fake({ "POST /identity/v1/login": () => json(200, pair) });
    await createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch, deviceStorage: store }).login(boundary, { login: "a", password: "b" });
    expect(f.calls[0].body.device_id).toBe("abcdef0123456789abcdef0123456789");
  });

  it("opts out, takes an own id or a per-call override", async () => {
    const store = memory();
    const f = fake({ "POST /identity/v1/login": () => json(200, pair) });
    const off = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch, deviceStorage: store, deviceId: false });
    await off.login(boundary, { login: "a", password: "b" });
    expect(f.calls[0].body).not.toHaveProperty("device_id");
    expect(store.items.size).toBe(0);

    const own = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch, deviceId: "my-own-device-id-0001" });
    await own.login(boundary, { login: "a", password: "b" });
    expect(f.calls[1].body.device_id).toBe("my-own-device-id-0001");

    const per = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch, deviceStorage: store });
    await per.login(boundary, { login: "a", password: "b", deviceId: false });
    expect(f.calls[2].body).not.toHaveProperty("device_id");
  });

  it("sends none where there is no storage (server rendering)", async () => {
    const f = fake({ "POST /identity/v1/login": () => json(200, pair) });
    await createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch }).login(boundary, { login: "a", password: "b" });
    expect(f.calls[0].body).not.toHaveProperty("device_id");
    expect(f.calls[0].body).not.toHaveProperty("captcha_token");
  });
});

describe("captcha", () => {
  it("sends captchaToken as captcha_token on login, challenge, signup and ldap", async () => {
    const f = fake({
      "POST /identity/v1/login": () => json(200, pair),
      "POST /identity/v1/challenges": () => json(202, { challenge_id: "c1", expires_in: 600 }),
      "POST /identity/v1/signup": () => json(202, { challenge_id: "c2", expires_in: 600 }),
      "POST /identity/v1/federation/ldap/login": () => json(200, pair),
    });
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch, deviceId: false });
    await iam.login(boundary, { login: "a", password: "b", captchaToken: "tok1" });
    await iam.sendCode({ environmentId: "env", login: "a", purpose: "password_reset", captchaToken: "tok2" });
    await iam.signup.start({ environmentId: "env", email: "a@example.com", name: "A", captchaToken: "tok3" });
    await iam.federation.ldap(boundary, { connectionId: "c", email: "a@example.com", password: "p", captchaToken: "tok4" });
    expect(f.calls.map((c) => c.body.captcha_token)).toEqual(["tok1", "tok2", "tok3", "tok4"]);
  });

  it("reads the public captcha configuration", async () => {
    const f = fake({ "GET /identity/v1/captcha/env": () => json(200, { enabled: true, provider: "turnstile", site_key: "1x00000000000000000000AA", headless: true }) });
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch });
    expect(await iam.getCaptchaConfig("env")).toEqual({ enabled: true, provider: "turnstile", site_key: "1x00000000000000000000AA", headless: true });
  });

  it("answers enabled false when there is none", async () => {
    const f = fake({ "GET /identity/v1/captcha/env": () => json(200, { enabled: false }) });
    expect((await createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch }).getCaptchaConfig("env")).enabled).toBe(false);
  });

  it("types the ticket's captcha", async () => {
    const f = fake({ "GET /identity/v1/authorize/t1": () => json(200, { environment_id: "env", captcha: { provider: "hcaptcha", site_key: "10000000-ffff-ffff-ffff-000000000001" } }) });
    const authz = await createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch }).authorization("t1");
    expect(authz.captcha?.provider).toBe("hcaptcha");
  });
});

describe("risk", () => {
  it("surfaces the reason of a risk challenge", async () => {
    const f = fake({ "POST /identity/v1/login": () => json(200, { mfa_required: true, mfa_token: "ik_mfa_x", factors: ["email"], enrollment_required: false, expires_in: 300, reason: "risk_challenge" }) });
    const out = await createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch }).login(boundary, { login: "a", password: "b" });
    expect(out.status).toBe("mfa_required");
    if (out.status !== "mfa_required") throw new Error("unreachable");
    expect(out.mfa.reason).toBe("risk_challenge");
    expect(out.mfa.factors).toEqual(["email"]);
  });

  it("recognizes the error codes", async () => {
    const envelope = (code: string, details?: object) => json(403, { error: { code, message: code, details } });
    const f = fake({ "POST /identity/v1/login": (b) => (b.login === "bot" ? envelope("CAPTCHA_REQUIRED", { provider: "turnstile" }) : b.login === "ban" ? envelope("SIGN_IN_BLOCKED") : b.login === "risk" ? envelope("RISK_CHALLENGE") : envelope("CHALLENGE_UNAVAILABLE")) });
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch });
    const attempt = (login: string) => iam.login(boundary, { login, password: "b" }).catch((e) => e);
    const captcha = await attempt("bot");
    expect(captcha).toBeInstanceOf(IAMKitError);
    expect(isCaptchaRequired(captcha)).toBe(true);
    expect(captchaProvider(captcha)).toBe("turnstile");
    expect(isSignInBlocked(await attempt("ban"))).toBe(true);
    expect(isRiskChallenge(await attempt("risk"))).toBe(true);
    expect(isChallengeUnavailable(await attempt("other"))).toBe(true);
    expect(isSignInBlocked(captcha)).toBe(false);
    expect(captchaProvider(new Error("x"))).toBeUndefined();
  });
});
