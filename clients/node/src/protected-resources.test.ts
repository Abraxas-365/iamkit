import { describe, expect, it } from "vitest";
import { ProtectedResourcesClient } from "./index.js";
import { fakeFetch, issuer } from "./testing/helpers.js";

describe("ProtectedResourcesClient", () => {
  it("registers, updates, lists and deletes", async () => {
    const { fetch, calls } = fakeFetch((call) => (call.method === "DELETE" ? { status: 204, body: undefined } : { body: { id: "p1", uri: "https://mcp.example/mcp", items: null } }));
    const client = new ProtectedResourcesClient({ baseUrl: issuer, token: () => "at", fetch });
    const created = await client.create("e1", { application_id: "a1", resource_id: "r1", name: "Notes", default_scopes: ["notes:read"] });
    expect(created.uri).toBe("https://mcp.example/mcp");
    await client.update("e1", "p1", { active: false });
    expect((await client.list("e1", { limit: 5 })).items).toEqual([]);
    await client.delete("e1", "p1");
    await client.setPolicy("e1", { max_idle_ttl_seconds: 600, max_lifetime_ttl_seconds: 7200 });
    expect(calls.map((c) => `${c.method} ${new URL(c.url).pathname}`)).toEqual([
      "POST /api/v1/environments/e1/protected-resources",
      "PATCH /api/v1/environments/e1/protected-resources/p1",
      "GET /api/v1/environments/e1/protected-resources",
      "DELETE /api/v1/environments/e1/protected-resources/p1",
      "PUT /api/v1/environments/e1/protected-resource-policy",
    ]);
    expect(JSON.parse(calls[1].body)).toEqual({ active: false });
    expect(new URL(calls[2].url).searchParams.get("limit")).toBe("5");
    expect(calls[0].headers.get("authorization")).toBe("Bearer at");
    await expect(client.get("e1", "../x")).rejects.toThrow();
  });
});
