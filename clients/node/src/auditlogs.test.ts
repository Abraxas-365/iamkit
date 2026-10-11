import { describe, expect, it } from "vitest";
import { AuditLogsClient, decodeAuditLogEvents } from "./auditlogs.js";
import { fakeFetch, issuer } from "./testing/helpers.js";

const input = {
  organization_id: "o1",
  action: "invoice.paid",
  occurred_at: "2026-01-02T03:04:05Z",
  actor: { type: "user", id: "u1" },
  targets: [{ type: "invoice", id: "inv-1" }],
};

describe("AuditLogsClient", () => {
  it("emits an event with the bearer token and idempotency key", async () => {
    const { fetch, calls } = fakeFetch(() => ({ status: 201, body: { id: "a1", created_at: "2026-01-02T03:04:06Z" } }));
    const logs = new AuditLogsClient({ baseUrl: issuer, token: "at", fetch });
    const receipt = await logs.createEvent("e1", input, { idempotencyKey: "pay-1" });
    expect(receipt.id).toBe("a1");
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toBe(`${issuer}/api/v1/environments/e1/audit-logs/events`);
    expect(calls[0].headers.get("authorization")).toBe("Bearer at");
    expect(calls[0].headers.get("idempotency-key")).toBe("pay-1");
    expect(JSON.parse(calls[0].body)).toMatchObject({ action: "invoice.paid", targets: [{ id: "inv-1" }] });
    await logs.createEvent("e1", input);
    expect(calls[1].headers.has("idempotency-key")).toBe(false);
  });

  it("lists with filters and a cursor", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: { items: null, next: 0 } }));
    const logs = new AuditLogsClient({ baseUrl: issuer, token: () => "at2", fetch });
    const page = await logs.listEvents("e1", { action: ["invoice.paid", "invoice.void"], actorId: "u1", after: 5, limit: 10 });
    expect(page).toEqual({ items: [], next: 0 });
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/environments/e1/audit-logs/events");
    expect(url.searchParams.get("action")).toBe("invoice.paid,invoice.void");
    expect(url.searchParams.get("actor_id")).toBe("u1");
    expect(url.searchParams.get("after")).toBe("5");
    expect(url.searchParams.get("limit")).toBe("10");
    expect(url.searchParams.has("before")).toBe(false);
    expect(calls[0].headers.get("authorization")).toBe("Bearer at2");
  });

  it("exports as a stream decoded event by event", async () => {
    const lines = [{ seq: 1, id: "a" }, { seq: 2, id: "b" }].map((e) => JSON.stringify(e)).join("\n") + "\n";
    const calls: string[] = [];
    const fetch = async (url: string | URL | Request) => {
      calls.push(String(url));
      return new Response(new TextEncoder().encode(lines), { headers: { "Content-Type": "application/x-ndjson" } });
    };
    const logs = new AuditLogsClient({ baseUrl: issuer, token: "at", fetch });
    const seen: number[] = [];
    for await (const event of decodeAuditLogEvents(await logs.exportEvents("e1", { targetType: "invoice", limit: 5 }))) {
      seen.push(event.seq);
    }
    expect(seen).toEqual([1, 2]);
    expect(calls[0]).toBe(`${issuer}/api/v1/environments/e1/audit-logs/events/export?target_type=invoice`);
    await logs.exportEvents("e1", {}, { format: "csv" });
    expect(calls[1]).toBe(`${issuer}/api/v1/environments/e1/audit-logs/events/export?format=csv`);
  });

  it("reads an organization's own log without organization_id", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: { items: [], next: 0 } }));
    const logs = new AuditLogsClient({ baseUrl: issuer, token: "at", fetch });
    await logs.listOrganizationEvents("e1", "o1", { organizationId: "other", before: 9 });
    expect(calls[0].url).toBe(`${issuer}/api/v1/environments/e1/organizations/o1/admin/audit-logs?before=9`);
  });

  it("maps errors and refuses unsafe ids", async () => {
    const { fetch } = fakeFetch(() => ({ status: 409, body: { error: { code: "IDEMPOTENCY_KEY_REUSED", message: "reused", type: "CONFLICT", http_status: 409 } } }));
    const logs = new AuditLogsClient({ baseUrl: issuer, token: "at", fetch });
    await expect(logs.createEvent("e1", input, { idempotencyKey: "k" })).rejects.toMatchObject({ status: 409, code: "IDEMPOTENCY_KEY_REUSED" });
    await expect(logs.exportEvents("e1")).rejects.toMatchObject({ status: 409, code: "IDEMPOTENCY_KEY_REUSED" });
    await expect(logs.listEvents("../x")).rejects.toMatchObject({ code: "VALIDATION" });
    expect(() => new AuditLogsClient({ baseUrl: issuer, token: "" })).toThrow();
  });
});
