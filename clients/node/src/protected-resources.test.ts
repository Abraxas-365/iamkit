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

  it("manages external clients, the allowlist and presets", async () => {
    const { fetch, calls } = fakeFetch((call) => {
      const path = new URL(call.url).pathname;
      if (call.method === "DELETE") return { status: 204, body: undefined };
      if (path.endsWith("/impact")) return { body: { active_sessions: 3, external_clients: 2 } };
      if (path.endsWith("/oauth-client-presets") && call.method === "GET") return { body: { items: null } };
      if (path.endsWith("/clients")) return { body: { items: null, page: { total: 0, limit: 50, offset: 0 } } };
      return { body: { id: "x", admission: "approved" } };
    });
    const client = new ProtectedResourcesClient({ baseUrl: issuer, token: "at", fetch });
    expect(await client.impact("e1", "p1")).toEqual({ active_sessions: 3, external_clients: 2 });
    expect((await client.clients("e1", "p1", { admission: "pending", limit: 20 })).items).toEqual([]);
    await client.client("e1", "p1", "c1");
    await client.approveClient("e1", "p1", "c1", { metadata_hash: "h1", expires_at: "2027-01-01T00:00:00Z" });
    await client.blockClient("e1", "p1", "c1");
    await client.unblockClient("e1", "p1", "c1");
    await client.forgetClient("e1", "p1", "c1");
    await client.createClientFromTemplate("e1", "p1", "gemini_cli");
    await client.createAllowlistEntry("e1", { origin: "https://tools.example", path_prefix: "/oauth" });
    await client.deleteAllowlistEntry("e1", "en1");
    expect(await client.presets("e1")).toEqual([]);
    await client.applyPreset("e1", { preset: "claude_code" });
    await client.update("e1", "p1", { allow_client_metadata: true, client_admission: "open" });
    expect(calls.map((c) => `${c.method} ${new URL(c.url).pathname}`)).toEqual([
      "GET /api/v1/environments/e1/protected-resources/p1/impact",
      "GET /api/v1/environments/e1/protected-resources/p1/clients",
      "GET /api/v1/environments/e1/protected-resources/p1/clients/c1",
      "POST /api/v1/environments/e1/protected-resources/p1/clients/c1/approve",
      "POST /api/v1/environments/e1/protected-resources/p1/clients/c1/block",
      "POST /api/v1/environments/e1/protected-resources/p1/clients/c1/unblock",
      "DELETE /api/v1/environments/e1/protected-resources/p1/clients/c1",
      "POST /api/v1/environments/e1/protected-resources/p1/client-templates",
      "POST /api/v1/environments/e1/oauth-client-allowlist",
      "DELETE /api/v1/environments/e1/oauth-client-allowlist/en1",
      "GET /api/v1/environments/e1/oauth-client-presets",
      "POST /api/v1/environments/e1/oauth-client-presets",
      "PATCH /api/v1/environments/e1/protected-resources/p1",
    ]);
    const query = new URL(calls[1].url).searchParams;
    expect(query.get("admission")).toBe("pending");
    expect(query.get("limit")).toBe("20");
    expect(JSON.parse(calls[3].body)).toEqual({ metadata_hash: "h1", expires_at: "2027-01-01T00:00:00Z" });
    expect(JSON.parse(calls[7].body)).toEqual({ preset: "gemini_cli" });
    expect(JSON.parse(calls[8].body)).toEqual({ origin: "https://tools.example", path_prefix: "/oauth" });
    expect(JSON.parse(calls[12].body)).toEqual({ allow_client_metadata: true, client_admission: "open" });
    await expect(client.approveClient("e1", "p1", "a/b", { metadata_hash: "h1" })).rejects.toThrow();
    await expect(client.deleteAllowlistEntry("e1", "..")).rejects.toThrow();
  });
});
