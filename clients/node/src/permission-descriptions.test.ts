import { describe, expect, it } from "vitest";
import { PermissionDescriptionsClient } from "./index.js";
import { fakeFetch, issuer } from "./testing/helpers.js";

describe("PermissionDescriptionsClient", () => {
  it("reads and replaces the descriptions", async () => {
    const { fetch, calls } = fakeFetch((call) => (call.method === "PUT" ? { status: 204, body: undefined } : { body: { items: null } }));
    const client = new PermissionDescriptionsClient({ baseUrl: issuer, token: () => "at", fetch });
    expect(await client.get("e1", "r1")).toEqual([]);
    await client.set("e1", "r1", [{ permission: "orders:read", display_name: "Read orders" }, { permission: "orders:read", locale: "es", display_name: "Leer pedidos", description: "Ver pedidos." }]);
    await client.set("e1", "r1", []);
    expect(calls.map((c) => `${c.method} ${new URL(c.url).pathname}`)).toEqual([
      "GET /api/v1/environments/e1/resources/r1/permission-descriptions",
      "PUT /api/v1/environments/e1/resources/r1/permission-descriptions",
      "PUT /api/v1/environments/e1/resources/r1/permission-descriptions",
    ]);
    expect(JSON.parse(calls[1].body)).toEqual({
      items: [
        { permission: "orders:read", locale: "", display_name: "Read orders", description: "" },
        { permission: "orders:read", locale: "es", display_name: "Leer pedidos", description: "Ver pedidos." },
      ],
    });
    expect(JSON.parse(calls[2].body)).toEqual({ items: [] });
    expect(calls[0].headers.get("authorization")).toBe("Bearer at");
    await expect(client.get("e1", "../x")).rejects.toThrow();
  });
});
