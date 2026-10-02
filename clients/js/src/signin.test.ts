import { describe, expect, it } from "vitest";
import { challengeOf, createSignIn, createVerifier, IAMKitError, type Boundary, type VerifierStore } from "./index";

interface Call {
  method: string;
  url: string;
  headers: Headers;
  credentials: RequestCredentials;
  body: unknown;
}

function fake(routes: Record<string, (body: any) => Response>) {
  const calls: Call[] = [];
  const fetcher = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    const text = await request.text();
    const url = new URL(request.url);
    const call = { method: request.method, url: url.pathname + url.search, headers: request.headers, credentials: init?.credentials ?? request.credentials, body: text ? JSON.parse(text) : undefined };
    calls.push(call);
    const route = routes[`${request.method} ${url.pathname}`];
    if (!route) {
      return json(404, { error: { code: "NOT_FOUND", message: "no route", type: "not_found", http_status: 404 } });
    }
    return route(call.body);
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
const pending = { mfa_required: true, mfa_token: "ik_mfa_x", factors: ["totp"], enrollment_required: false, expires_in: 300 };

describe("SignIn", () => {
  it("signs in with a password and sends the boundary", async () => {
    const f = fake({ "POST /identity/v1/login": () => json(200, pair) });
    const iam = createSignIn({ baseUrl: "https://id.example.com/", fetch: f.fetch });
    const out = await iam.login(boundary, { login: "ada@example.com", password: "pw" });
    expect(out).toEqual({ status: "signed_in", tokens: pair });
    expect(f.calls[0].url).toBe("/identity/v1/login");
    expect(f.calls[0].body).toMatchObject({ environment_id: "env", organization_id: "org", application_id: "app", resource_id: "res", login: "ada@example.com" });
    expect(f.calls[0].credentials).toBe("include");
  });

  it("reports a pending second factor and answers it", async () => {
    const f = fake({
      "POST /identity/v1/login": () => json(200, pending),
      "POST /identity/v1/mfa/verify": () => json(200, pair),
    });
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch });
    const out = await iam.login(boundary, { login: "ada", password: "pw" });
    expect(out.status).toBe("mfa_required");
    if (out.status !== "mfa_required") throw new Error("unreachable");
    expect(out.mfa.factors).toEqual(["totp"]);
    expect(await iam.mfa.verify(out.mfa.mfa_token, "123456")).toEqual(pair);
    expect(f.calls[1].body).toEqual({ mfa_token: "ik_mfa_x", code: "123456" });
  });

  it("throws IAMKitError with the envelope's code and details", async () => {
    const f = fake({
      "POST /identity/v1/login": () => json(403, { error: { code: "PASSWORD_CHANGE_REQUIRED", message: "change it", type: "forbidden", http_status: 403, details: { rule: "x" } } }),
    });
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch });
    const err = await iam.login(boundary, { login: "ada", password: "pw" }).catch((e) => e);
    expect(err).toBeInstanceOf(IAMKitError);
    expect(err).toMatchObject({ status: 403, code: "PASSWORD_CHANGE_REQUIRED", message: "change it", details: { rule: "x" } });
  });

  it("verifies login codes and resets passwords (204)", async () => {
    const f = fake({
      "POST /identity/v1/challenges": () => json(202, { challenge_id: "c1", message: "sent", expires_in: 600 }),
      "POST /identity/v1/challenges/verify": (body) => (body.purpose === "login" ? json(200, pair) : new Response(null, { status: 204 })),
    });
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch });
    expect(await iam.sendCode({ environmentId: "env", login: "ada@example.com", purpose: "login" })).toEqual({ challengeId: "c1", expiresIn: 600 });
    expect(await iam.verifyCode(boundary, { challengeId: "c1", code: "111111" })).toEqual({ status: "signed_in", tokens: pair });
    await iam.resetPassword({ environmentId: "env", challengeId: "c1", code: "111111", password: "new" });
    expect(f.calls[2].body).toMatchObject({ purpose: "password_reset", password: "new", environment_id: "env" });
  });

  it("describes a ticket and completes the authorization with the user token", async () => {
    const f = fake({
      "GET /identity/v1/authorize/ik_ticket": () => json(200, { client_id: "cl", environment_id: "env", application_id: "app", resource_id: "res", audience: "api", scopes: ["openid"], organization_id: null }),
      "POST /oauth/authorize/complete": () => json(200, { redirect_to: "https://app.example.com/cb?code=c&state=s" }),
    });
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch });
    const authz = await iam.authorization("ik_ticket");
    expect(authz.client_id).toBe("cl");
    expect(await iam.complete("ik_ticket", "at")).toBe("https://app.example.com/cb?code=c&state=s");
    const call = f.calls[1];
    expect(call.headers.get("Authorization")).toBe("Bearer at");
    expect(call.headers.get("Accept")).toBe("application/json");
    expect(call.body).toEqual({ authorization_ticket: "ik_ticket", approve: true });
  });

  it("starts an authorization and refuses hosted-login clients", async () => {
    const start = { authorization_ticket: "ik_t", client_id: "cl", environment_id: "env", application_id: "app", resource_id: "res", audience: "api", scopes: ["openid"] };
    let hosted = false;
    const f = fake({ "GET /oauth/authorize": () => (hosted ? new Response(null, { status: 303, headers: { Location: "/hosted/login?ticket=x" } }) : json(200, start)) });
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch });
    expect(await iam.authorize({ client_id: "cl", response_type: "code" })).toEqual(start);
    expect(f.calls[0].url).toBe("/oauth/authorize?client_id=cl&response_type=code");
    hosted = true;
    await expect(iam.authorize("client_id=cl")).rejects.toMatchObject({ code: "HOSTED_LOGIN" });
  });

  it("runs single sign-on back to the UI with PKCE", async () => {
    const f = fake({
      "POST /identity/v1/federation/start": () => json(200, { authorization_url: "https://idp.example.com/authorize?x=1" }),
      "POST /identity/v1/federation/result": () => json(200, pair),
    });
    const storage = memory();
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch, storage });
    const url = await iam.federation.start(boundary, { connectionId: "conn", returnTo: "https://app.example.com/sso" });
    expect(url).toBe("https://idp.example.com/authorize?x=1");
    const verifier = [...storage.items.values()][0];
    expect(f.calls[0].body).toMatchObject({ connection_id: "conn", return_to: "https://app.example.com/sso", code_challenge: await challengeOf(verifier) });

    expect(await iam.federation.finish("https://app.example.com/sso")).toBeNull();
    const out = await iam.federation.finish("https://app.example.com/sso?federation_result=ik_fedres_h");
    expect(out).toEqual({ status: "signed_in", tokens: pair });
    expect(f.calls[1].body).toEqual({ federation_result: "ik_fedres_h", code_verifier: verifier });
    expect(storage.items.size).toBe(0);
  });

  it("surfaces a provider error on the return and drops the verifier", async () => {
    const storage = memory();
    storage.setItem("iamkit.federation.verifier", "v");
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: fake({}).fetch, storage });
    await expect(iam.federation.finish(new URLSearchParams("error=access_denied&error_description=nope"))).rejects.toMatchObject({ code: "access_denied", message: "nope" });
    expect(storage.items.size).toBe(0);
    await expect(iam.federation.finish(new URLSearchParams("federation_result=ik_fedres_h"))).rejects.toMatchObject({ code: "FEDERATION_VERIFIER_MISSING" });
  });

  it("lists organizations with the bearer token", async () => {
    const f = fake({ "GET /identity/v1/organizations": () => json(200, [{ id: "org", name: "Acme", manager_id: null, org_unit_id: null }]) });
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch });
    const list = await iam.organizations("at", { environmentId: "env", audience: "api" });
    expect(list.map((o) => o.name)).toEqual(["Acme"]);
    expect(f.calls[0].url).toBe("/identity/v1/organizations?environment_id=env&audience=api");
    expect(f.calls[0].headers.get("Authorization")).toBe("Bearer at");
  });
});

describe("PKCE", () => {
  it("makes RFC 7636 verifiers and S256 challenges", async () => {
    const v = createVerifier();
    expect(v).toMatch(/^[A-Za-z0-9\-._~]{64}$/);
    // RFC 7636 appendix B.
    expect(await challengeOf("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    expect(() => createVerifier(10)).toThrow(RangeError);
  });
});
