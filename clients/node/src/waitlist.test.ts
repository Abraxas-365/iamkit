import { describe, expect, it } from "vitest";
import { WaitlistClient } from "./index.js";
import { fakeFetch, issuer } from "./testing/helpers.js";

describe("WaitlistClient", () => {
  it("lists with filters and the bearer token", async () => {
    const { fetch, calls } = fakeFetch(() => ({ body: { items: null, page: { total: 0, limit: 20, offset: 0 } } }));
    const waitlist = new WaitlistClient({ baseUrl: issuer, token: () => "at", fetch });
    const page = await waitlist.list("e1", { status: "pending", email: "ana", limit: 5 });
    expect(page.items).toEqual([]);
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/environments/e1/waitlist");
    expect(url.searchParams.get("status")).toBe("pending");
    expect(url.searchParams.get("email")).toBe("ana");
    expect(url.searchParams.get("limit")).toBe("5");
    expect(calls[0].headers.get("authorization")).toBe("Bearer at");
  });

  it("approves, rejects and deletes one entry", async () => {
    const { fetch, calls } = fakeFetch((call) => (call.method === "DELETE" ? { status: 204, body: undefined } : { body: { id: "w1", status: "approved" } }));
    const waitlist = new WaitlistClient({ baseUrl: issuer, token: "at", fetch });
    expect((await waitlist.approve("e1", "w1")).status).toBe("approved");
    await waitlist.reject("e1", "w1", { notify: true });
    await waitlist.delete("e1", "w1");
    expect(calls.map((c) => `${c.method} ${new URL(c.url).pathname}`)).toEqual([
      "POST /api/v1/environments/e1/waitlist/w1/approve",
      "POST /api/v1/environments/e1/waitlist/w1/reject",
      "DELETE /api/v1/environments/e1/waitlist/w1",
    ]);
    expect(JSON.parse(calls[1].body)).toEqual({ notify: true });
    await expect(waitlist.get("e1", "../x")).rejects.toThrow();
  });

  it("approves every pending entry while more remain", async () => {
    const answers = [
      { approved: 500, skipped: 0, more: true },
      { approved: 3, skipped: 2, more: false },
    ];
    const { fetch, calls } = fakeFetch(() => ({ body: answers.shift() }));
    const waitlist = new WaitlistClient({ baseUrl: issuer, token: "at", fetch });
    expect(await waitlist.approveAllPending("e1")).toEqual({ approved: 503, skipped: 2 });
    expect(calls).toHaveLength(2);
    expect(JSON.parse(calls[0].body)).toEqual({ all_pending: true });
  });
});
