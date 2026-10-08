import { describe, expect, it } from "vitest";
import { IdentityClient, createApiClient, createManagementClient, isMFAPending } from "./clients.js";
import { fakeFetch, issuer } from "./testing/helpers.js";

const boundary = { environmentId: "e", organizationId: "o", applicationId: "a", resourceId: "r" };

describe("IdentityClient", () => {
  it("logs in, continues MFA and refreshes", async () => {
    const { fetch, calls } = fakeFetch((call) =>
      call.url.endsWith("/login")
        ? { body: { mfa_required: true, mfa_token: "ik_mfa_1", enrollment_required: false, factors: ["totp"], expires_in: 300 } }
        : { body: { access_token: "at", refresh_token: "rt", token_type: "Bearer", expires_in: 900 } },
    );
    const iam = new IdentityClient({ baseUrl: issuer, fetch });
    const answer = await iam.login(boundary, { login: "ada", password: "pw" });
    expect(isMFAPending(answer)).toBe(true);
    expect(JSON.parse(calls[0].body)).toEqual({ environment_id: "e", organization_id: "o", application_id: "a", resource_id: "r", login: "ada", password: "pw" });
    const tokens = await iam.verifyMFA("ik_mfa_1", "123456");
    expect(isMFAPending(tokens)).toBe(false);
    await iam.refresh(boundary, "rt");
    expect(calls.map((c) => new URL(c.url).pathname)).toEqual(["/identity/v1/login", "/identity/v1/mfa/verify", "/identity/v1/refresh"]);
    expect(JSON.parse(calls[2].body)).toMatchObject({ refresh_token: "rt", resource_id: "r" });
  });

  it("reads the profile with the token and query boundary", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: { id: "u" } }));
    await new IdentityClient({ baseUrl: issuer, fetch }).profile("at", "e", "https://api.example.com");
    expect(calls[0].url).toBe(`${issuer}/identity/v1/me?environment_id=e&audience=https%3A%2F%2Fapi.example.com`);
    expect(calls[0].headers.get("authorization")).toBe("Bearer at");
  });

  it("sends credentials as bearer and refuses the wrong prefixes", async () => {
    const { fetch, calls } = fakeFetch((call) => (call.url.endsWith("/logout") ? { status: 204 } : { body: { access_token: "at", token_type: "Bearer", expires_in: 60 } }));
    const iam = new IdentityClient({ baseUrl: issuer, fetch });
    await iam.machineToken("ik_svc_x");
    await iam.exchangeAccessToken("ik_pat_x");
    await iam.logout("at", "e", "aud");
    expect(calls.map((c) => c.headers.get("authorization"))).toEqual(["Bearer ik_svc_x", "Bearer ik_pat_x", "Bearer at"]);
    expect(calls[0].body).toBe("");
    await expect(iam.machineToken("ik_pat_x")).rejects.toMatchObject({ code: "VALIDATION" });
    await expect(iam.exchangeAccessToken("ik_svc_x")).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("maps IAMKit error envelopes", async () => {
    const { fetch } = fakeFetch(() => ({ status: 403, body: { error: { code: "PASSWORD_CHANGE_REQUIRED", message: "change it", type: "FORBIDDEN", http_status: 403 } } }));
    await expect(new IdentityClient({ baseUrl: issuer, fetch }).login(boundary, { login: "a", password: "b" })).rejects.toMatchObject({ status: 403, code: "PASSWORD_CHANGE_REQUIRED", message: "change it" });
  });
});

describe("typed clients", () => {
  it("sends the management key and API tokens", async () => {
    const seen: Request[] = [];
    const fetch = async (request: Request) => {
      seen.push(request);
      return new Response(JSON.stringify({ items: [], page: { total: 0, limit: 20, offset: 0 } }), { headers: { "Content-Type": "application/json" } });
    };
    const management = createManagementClient({ baseUrl: issuer, key: "ik_mgmt_x", fetch });
    const { data } = await management.GET("/management/v1/environments/{environment}/users", { params: { path: { environment: "e" } } });
    expect(data?.page.total).toBe(0);
    expect(seen[0].headers.get("x-api-key")).toBe("ik_mgmt_x");
    const api = createApiClient({ baseUrl: issuer, token: async () => "at", fetch });
    await api.GET("/api/v1/environments/{environment}/users", { params: { path: { environment: "e" } } });
    expect(seen[1].headers.get("authorization")).toBe("Bearer at");
    expect(() => createManagementClient({ baseUrl: issuer, key: "" })).toThrow();
  });
});
