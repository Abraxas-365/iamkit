import { describe, expect, it } from "vitest";
import { APIKeysClient, IdentityClient, createAPIKeyValidator, hasAPIKeyPermission, validateAPIKey } from "./index.js";
import { fakeFetch } from "./testing/helpers.js";

const baseUrl = "https://iam.example.com";
const environmentId = "env-1";
const audience = "https://orders";

function introspected(overrides: Record<string, unknown> = {}, key: Record<string, unknown> = {}) {
  return {
    active: true,
    claims: {
      purpose: "api_key",
      environment_id: environmentId,
      organization_id: "org-1",
      resource_id: "res-1",
      aud: [audience],
      permissions: ["orders:read"],
      exp: 0,
      api_key: { id: "k1", name: "erp", owner: { type: "organization", organization_id: "org-1" }, resource_id: "res-1", permissions: ["orders:read", "orders:write"], expires_at: 0, ...key },
      ...overrides,
    },
  };
}

describe("validateAPIKey", () => {
  it("introspects with the boundary and returns a typed key", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: introspected() }));
    const key = await createAPIKeyValidator({ baseUrl, environmentId, audience, fetch }).validate("ik_key_secret");
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(`${baseUrl}/identity/v1/introspect`);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].headers.get("authorization")).toBe("Bearer ik_key_secret");
    expect(JSON.parse(calls[0].body)).toEqual({ environment_id: environmentId, audience });
    expect(key).toMatchObject({ id: "k1", name: "erp", organization_id: "org-1", resource_id: "res-1", expires_at: 0, owner: { type: "organization" } });
    expect(hasAPIKeyPermission(key, "orders:write")).toBe(true);
    expect(hasAPIKeyPermission(key, "orders:read", "orders:delete")).toBe(false);
    expect(hasAPIKeyPermission(key)).toBe(false);
  });

  it("refuses everything that is not an active key of this boundary", async () => {
    const answers: Record<string, unknown> = {
      inactive: { active: false },
      "token purpose": introspected({ purpose: "application" }),
      "other environment": introspected({ environment_id: "env-2" }),
      "other audience": introspected({ aud: ["https://other"] }),
      "no key": introspected({ api_key: undefined }),
      "no permissions": introspected({}, { permissions: [] }),
      expired: introspected({}, { expires_at: Math.floor(Date.now() / 1000) - 60 }),
    };
    for (const [name, body] of Object.entries(answers)) {
      const { fetch } = fakeFetch(() => ({ body }));
      await expect(validateAPIKey("ik_key_secret", { baseUrl, environmentId, audience, fetch }), name).rejects.toMatchObject({ status: 401, code: "UNAUTHORIZED" });
    }
    const unauthorized = fakeFetch(() => ({ status: 401, body: { error: { code: "UNAUTHORIZED", message: "no" } } }));
    await expect(validateAPIKey("ik_key_secret", { baseUrl, environmentId, audience, fetch: unauthorized.fetch })).rejects.toMatchObject({ status: 401 });
  });

  it("accepts a future expiry and fails closed on outages", async () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    const ok = fakeFetch(() => ({ body: introspected({}, { expires_at: future }) }));
    expect((await validateAPIKey("ik_key_secret", { baseUrl, environmentId, audience, fetch: ok.fetch })).expires_at).toBe(future);
    const down = fakeFetch(() => ({ status: 503, body: { error: { code: "UNAVAILABLE", message: "later" } } }));
    await expect(validateAPIKey("ik_key_secret", { baseUrl, environmentId, audience, fetch: down.fetch })).rejects.toMatchObject({ status: 503 });
  });

  it("refuses other credentials before any request", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: introspected() }));
    const validator = createAPIKeyValidator({ baseUrl, environmentId, audience, fetch });
    for (const value of ["", "ik_pat_x", "ik_svc_x", "eyJ.a.b"]) {
      await expect(validator.validate(value), value).rejects.toMatchObject({ status: 401 });
    }
    expect(calls).toHaveLength(0);
    expect(() => createAPIKeyValidator({ baseUrl, environmentId: "", audience })).toThrow();
    expect(() => createAPIKeyValidator({ baseUrl, environmentId, audience: "" })).toThrow();
  });
});

describe("APIKeysClient", () => {
  const record = { id: "k1", name: "erp", owner: { type: "organization" }, state: "active" };
  const run = (call: (client: APIKeysClient) => Promise<unknown>, status = 200, body: unknown = record) => {
    const { fetch, calls } = fakeFetch(() => ({ status, body }));
    return call(new APIKeysClient({ baseUrl, token: async () => "jwt", fetch })).then(() => calls[0]);
  };

  it("calls the operator routes", async () => {
    const list = await run((c) => c.list("e1", { ownerType: "user", organizationId: "o1", userId: "u1", resourceId: "r1", state: "revoked", limit: 5, offset: 10 }), 200, { items: [record], page: { total: 1, limit: 5, offset: 10 } });
    expect(list.method).toBe("GET");
    expect(list.headers.get("authorization")).toBe("Bearer jwt");
    expect(list.url).toBe(`${baseUrl}/api/v1/environments/e1/api-keys?owner_type=user&organization_id=o1&user_id=u1&resource_id=r1&state=revoked&limit=5&offset=10`);

    expect((await run((c) => c.get("e1", "k1"))).url).toBe(`${baseUrl}/api/v1/environments/e1/api-keys/k1`);
    const create = await run((c) => c.create("e1", { organizationId: "o1", resourceId: "r1", name: "erp", permissions: ["orders:read"], expiresIn: "never" }), 201, { ...record, value: "ik_key_x" });
    expect(create.method).toBe("POST");
    expect(JSON.parse(create.body)).toEqual({ organization_id: "o1", resource_id: "r1", name: "erp", permissions: ["orders:read"], expires_in: "never" });
    const omitted = await run((c) => c.create("e1", { organizationId: "o1", resourceId: "r1", name: "erp" }), 201);
    expect(JSON.parse(omitted.body)).not.toHaveProperty("expires_in");
    const revoke = await run((c) => c.revoke("e1", "k1"), 204, undefined);
    expect([revoke.method, revoke.url]).toEqual(["DELETE", `${baseUrl}/api/v1/environments/e1/api-keys/k1`]);
  });

  it("calls policy, allowlist and machine key routes", async () => {
    const policy = { user_keys: true, organization_keys: false, max_ttl_days: null, max_per_user: 10, max_per_organization: 50 };
    expect((await run((c) => c.policy("e1"), 200, policy)).url).toBe(`${baseUrl}/api/v1/environments/e1/api-key-policy`);
    const save = await run((c) => c.savePolicy("e1", policy), 200, policy);
    expect([save.method, JSON.parse(save.body)]).toEqual(["PUT", policy]);
    const allow = await run((c) => c.setResourceAPIKeyPermissions("e1", "r1", { organization: ["a"] }), 204, undefined);
    expect([allow.method, allow.url, JSON.parse(allow.body)]).toEqual(["PUT", `${baseUrl}/api/v1/environments/e1/resources/r1/api-key-permissions`, { user: [], organization: ["a"] }]);
    expect((await run((c) => c.userKeys("e1", "u1"), 200, { items: [], page: { total: 0, limit: 20, offset: 0 } })).url).toBe(`${baseUrl}/api/v1/environments/e1/users/u1/api-keys`);
    const machine = await run((c) => c.createMachineKey("e1", "m1", { organizationId: "o1", applicationId: "a1", resourceId: "r1", name: "ci", expiresIn: "720h" }), 201);
    expect([machine.method, machine.url, JSON.parse(machine.body).application_id]).toEqual(["POST", `${baseUrl}/api/v1/environments/e1/users/m1/api-keys`, "a1"]);
    const gone = await run((c) => c.revokeUserKey("e1", "m1", "k1"), 204, undefined);
    expect([gone.method, gone.url]).toEqual(["DELETE", `${baseUrl}/api/v1/environments/e1/users/m1/api-keys/k1`]);
  });

  it("calls the organization admin routes", async () => {
    const base = `${baseUrl}/api/v1/environments/e1/organizations/o1/admin`;
    const list = await run((c) => c.listOrganization("e1", "o1", { ownerType: "user", organizationId: "ignored" }), 200, { items: [], page: { total: 0, limit: 20, offset: 0 } });
    expect(list.url).toBe(`${base}/api-keys?owner_type=user`);
    expect((await run((c) => c.organizationOptions("e1", "o1"), 200, { enabled: true, max_ttl_days: null, resources: [] })).url).toBe(`${base}/api-keys/options`);
    expect((await run((c) => c.getOrganizationKey("e1", "o1", "k1"))).url).toBe(`${base}/api-keys/k1`);
    const create = await run((c) => c.createOrganizationKey("e1", "o1", { resourceId: "r1", name: "erp", expiresIn: "720h" }), 201);
    expect([create.url, JSON.parse(create.body).organization_id]).toEqual([`${base}/api-keys`, "o1"]);
    const revoke = await run((c) => c.revokeOrganizationKey("e1", "o1", "k1"), 204, undefined);
    expect([revoke.method, revoke.url]).toEqual(["DELETE", `${base}/api-keys/k1`]);
  });

  it("refuses unsafe identifiers and a missing token", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: {} }));
    const client = new APIKeysClient({ baseUrl, token: "jwt", fetch });
    await expect(client.get("e1", "../x")).rejects.toMatchObject({ code: "VALIDATION" });
    await expect(client.revoke("e1", "a/b")).rejects.toMatchObject({ code: "VALIDATION" });
    expect(calls).toHaveLength(0);
    expect(() => new APIKeysClient({ baseUrl, token: "", fetch })).toThrow();
    await expect(new APIKeysClient({ baseUrl, token: () => undefined, fetch }).get("e1", "k1")).rejects.toMatchObject({ code: "VALIDATION" });
  });
});

describe("IdentityClient.me", () => {
  it("manages the user's own keys with the boundary", async () => {
    const { fetch, calls } = fakeFetch((call) => {
      if (call.method === "DELETE") return { status: 204 };
      if (call.method === "POST") return { status: 201, body: { id: "k1", value: "ik_key_secret" } };
      return { body: call.url.includes("/options") ? { enabled: true, max_ttl_days: 30, resources: [] } : { items: [{ id: "k1" }], page: { total: 1, limit: 20, offset: 0 } } };
    });
    const me = new IdentityClient({ baseUrl, fetch }).me("at", environmentId, audience);
    const scope = "environment_id=env-1&audience=https%3A%2F%2Forders";
    expect((await me.list({ limit: 5 })).items).toHaveLength(1);
    expect((await me.options()).max_ttl_days).toBe(30);
    expect((await me.create({ resourceId: "r1", name: "cli", permissions: ["orders:read"], expiresIn: "720h" })).value).toBe("ik_key_secret");
    await me.revoke("k1");
    expect(calls.map((c) => `${c.method} ${c.url.replace(baseUrl, "")}`)).toEqual([
      `GET /identity/v1/me/api-keys?${scope}&limit=5`,
      `GET /identity/v1/me/api-keys/options?${scope}`,
      `POST /identity/v1/me/api-keys?${scope}`,
      `DELETE /identity/v1/me/api-keys/k1?${scope}`,
    ]);
    expect(calls.every((c) => c.headers.get("authorization") === "Bearer at")).toBe(true);
    expect(JSON.parse(calls[2].body)).toEqual({ resource_id: "r1", name: "cli", permissions: ["orders:read"], expires_in: "720h" });
    await expect(me.revoke("../x")).rejects.toMatchObject({ code: "VALIDATION" });
  });
});
