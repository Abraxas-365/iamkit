import { describe, expect, it } from "vitest";
import { createIAMKitClient, isApiError, type Schema } from "./index";

function recorder(status: number, body: unknown) {
  const seen: Request[] = [];
  const fetch = async (input: Request) => {
    seen.push(input);
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  };
  return { seen, fetch };
}

describe("createIAMKitClient", () => {
  it("sends the management key and builds typed paths", async () => {
    const page: Schema<"PaginatedApplication"> = { items: [], page: { total: 0, limit: 20, offset: 0 } };
    const { seen, fetch } = recorder(200, page);
    const iam = createIAMKitClient({ baseUrl: "https://iam.example/", managementKey: "ik_mgmt_x", fetch });
    const { data, error } = await iam.GET("/management/v1/environments/{environment}/applications", {
      params: { path: { environment: "env-1" }, query: { limit: 20 } },
    });
    expect(error).toBeUndefined();
    expect(data?.page.total).toBe(0);
    expect(seen[0].url).toBe("https://iam.example/management/v1/environments/env-1/applications?limit=20");
    expect(seen[0].headers.get("X-API-Key")).toBe("ik_mgmt_x");
    expect(seen[0].headers.get("Authorization")).toBeNull();
  });

  it("asks a token function on every request", async () => {
    const { seen, fetch } = recorder(200, {});
    let n = 0;
    const iam = createIAMKitClient({ baseUrl: "https://iam.example", token: () => `t${++n}`, fetch });
    await iam.GET("/identity/v1/me");
    await iam.GET("/identity/v1/me");
    expect(seen.map((r) => r.headers.get("Authorization"))).toEqual(["Bearer t1", "Bearer t2"]);
  });

  it("returns the error envelope", async () => {
    const body = { error: { code: "NOT_FOUND", message: "user not found", type: "NOT_FOUND", http_status: 404 } };
    const { fetch } = recorder(404, body);
    const iam = createIAMKitClient({ baseUrl: "https://iam.example", token: "jwt", fetch });
    const { error } = await iam.GET("/identity/v1/me");
    expect(isApiError(error)).toBe(true);
    expect(isApiError({ error: "invalid_grant" })).toBe(false);
  });
});
