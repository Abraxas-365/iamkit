import { describe, expect, it } from "vitest";
import { EventRetentionClient, EventRetentionManagement } from "./index.js";
import { fakeFetch, issuer } from "./testing/helpers.js";

const retention = {
  security_retention_seconds: 2592000,
  default_retention_seconds: null,
  ceilings: { security: 31536000, default: 7776000 },
  effective: { security: 2592000, default: 7776000 },
};

describe("event retention", () => {
  it("reads with an access token", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: retention }));
    const client = new EventRetentionClient({ baseUrl: issuer, token: () => "at", fetch });
    expect((await client.get("e1")).effective.security).toBe(2592000);
    expect(new URL(calls[0].url).pathname).toBe("/api/v1/environments/e1/event-retention");
    expect(calls[0].headers.get("authorization")).toBe("Bearer at");
    await expect(client.get("../x")).rejects.toThrow();
  });

  it("reads and replaces with a management key", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: retention }));
    const management = new EventRetentionManagement({ baseUrl: issuer, key: "ik_mgmt_x", fetch });
    await management.get("e1");
    await management.set("e1", { security_retention_seconds: 2592000 });
    expect(calls.map((c) => `${c.method} ${new URL(c.url).pathname}`)).toEqual([
      "GET /management/v1/environments/e1/event-retention",
      "PUT /management/v1/environments/e1/event-retention",
    ]);
    expect(calls[1].headers.get("x-api-key")).toBe("ik_mgmt_x");
    expect(JSON.parse(calls[1].body)).toEqual({ security_retention_seconds: 2592000, default_retention_seconds: null });
  });
});
