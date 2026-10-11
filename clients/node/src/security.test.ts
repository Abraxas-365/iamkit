import { describe, expect, it } from "vitest";
import { IAMKitError } from "./errors.js";
import { IdentityClient } from "./clients.js";
import { SecurityClient } from "./security.js";
import { fakeFetch, issuer } from "./testing/helpers.js";

const base = `${issuer}/api/v1/environments/e1`;

function client(handler: Parameters<typeof fakeFetch>[0]) {
  const f = fakeFetch(handler);
  return { ...f, security: new SecurityClient({ baseUrl: issuer, token: "at", fetch: f.fetch }) };
}

describe("SecurityClient", () => {
  it("reads, saves, tests and deletes the CAPTCHA", async () => {
    const config = { environment_id: "e1", provider: "turnstile", site_key: "1x00000000000000000000AA", has_secret: true, hosted: true, headless: true, hostnames: [], updated_at: "2026-01-01T00:00:00Z" };
    const { security, calls } = client((call) => (call.method === "DELETE" || call.url.endsWith("/test") ? { status: 204 } : { body: config }));
    expect((await security.getCaptcha("e1")).has_secret).toBe(true);
    expect(calls[0]).toMatchObject({ method: "GET", url: `${base}/captcha` });
    expect(calls[0].headers.get("authorization")).toBe("Bearer at");

    await security.setCaptcha("e1", { provider: "turnstile", site_key: "1x00000000000000000000AA", secret: "1x0000000000000000000000000000000AA", headless: false });
    expect(calls[1].method).toBe("PUT");
    expect(calls[1].headers.get("content-type")).toBe("application/json");
    expect(JSON.parse(calls[1].body)).toMatchObject({ provider: "turnstile", headless: false });

    await expect(security.testCaptcha("e1")).resolves.toBeUndefined();
    expect(calls[2]).toMatchObject({ method: "POST", url: `${base}/captcha/test` });
    await expect(security.deleteCaptcha("e1")).resolves.toBeUndefined();
    expect(calls[3]).toMatchObject({ method: "DELETE", url: `${base}/captcha` });
  });

  it("surfaces a missing configuration and a bad secret as IAMKitError", async () => {
    const { security } = client((call) => (call.url.endsWith("/test") ? { status: 422, body: { error: { code: "CAPTCHA_SECRET_INVALID", message: "the provider refused the secret" } } } : { status: 404, body: { error: { code: "NOT_FOUND", message: "no captcha" } } }));
    expect(await security.getCaptcha("e1").catch((e) => e)).toMatchObject({ status: 404, code: "NOT_FOUND" });
    const err = await security.testCaptcha("e1").catch((e) => e);
    expect(err).toBeInstanceOf(IAMKitError);
    expect(err.status).toBe(422);
  });

  it("reads and replaces the risk policy", async () => {
    const policy = { environment_id: "e1", actions: { new_device: "notify" }, thresholds: {}, notify_user: true, block_if_unverifiable: false, saved: true };
    const { security, calls } = client((call) => (call.method === "DELETE" ? { status: 204 } : { body: policy }));
    expect((await security.getRiskPolicy("e1")).actions.new_device).toBe("notify");
    await security.setRiskPolicy("e1", { actions: { new_device: "challenge", ip_velocity: "block" }, thresholds: { ip_failures_per_hour: 30 }, block_if_unverifiable: true });
    expect(calls[1]).toMatchObject({ method: "PUT", url: `${base}/risk-policy` });
    expect(JSON.parse(calls[1].body)).toEqual({ actions: { new_device: "challenge", ip_velocity: "block" }, thresholds: { ip_failures_per_hour: 30 }, block_if_unverifiable: true });
    await security.deleteRiskPolicy("e1");
    expect(calls[2]).toMatchObject({ method: "DELETE", url: `${base}/risk-policy` });
  });

  it("manages restrictions", async () => {
    const rule = { id: "r1", environment_id: "e1", kind: "country", value: "XX", action: "deny", note: "", created_at: "2026-01-01T00:00:00Z" };
    const { security, calls } = client((call) => {
      if (call.method === "DELETE") return { status: 204 };
      if (call.method === "POST") return { status: 201, body: rule };
      return { body: { items: null } };
    });
    expect(await security.listRestrictions("e1")).toEqual([]);
    expect(calls[0].url).toBe(`${base}/risk-restrictions`);
    await security.listRestrictions("e1", { kind: "country", action: "deny" });
    expect(calls[1].url).toBe(`${base}/risk-restrictions?kind=country&action=deny`);
    expect((await security.createRestriction("e1", { kind: "country", value: "XX", action: "deny" })).id).toBe("r1");
    expect(JSON.parse(calls[2].body)).toEqual({ kind: "country", value: "XX", action: "deny" });
    await security.deleteRestriction("e1", "r1");
    expect(calls[3]).toMatchObject({ method: "DELETE", url: `${base}/risk-restrictions/r1` });
  });

  it("pages the attempt log and reads one attempt", async () => {
    const attempt = { id: "a1", environment_id: "e1", device: true, method: "password", surface: "headless", outcome: "blocked", detections: ["ip_velocity"], action: "block", created_at: "2026-01-01T00:00:00Z" };
    const { security, calls } = client((call) => (call.url.includes("/sign-in-attempts/a1") ? { body: attempt } : { body: { items: [attempt], next: "a0" } }));
    const page = await security.listAttempts("e1", { userId: "u1", outcome: "blocked", detection: "ip_velocity", country: "XX", ip: "203.0.113.9", limit: 25, before: "a9" });
    expect(page).toEqual({ items: [attempt], next: "a0" });
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/environments/e1/sign-in-attempts");
    expect(Object.fromEntries(url.searchParams)).toEqual({ user_id: "u1", outcome: "blocked", detection: "ip_velocity", country: "XX", ip: "203.0.113.9", limit: "25", before: "a9" });
    expect((await security.getAttempt("e1", "a1")).outcome).toBe("blocked");
    expect(calls[1].url).toBe(`${base}/sign-in-attempts/a1`);
  });

  it("reads the status and a user's devices", async () => {
    const { security, calls } = client((call) => (call.url.endsWith("/devices") ? { body: { items: null } } : { body: { geoip: { source: "none", countries: false, travel: false }, captcha: true, risk_signals: false } }));
    expect((await security.getStatus("e1")).captcha).toBe(true);
    expect(calls[0].url).toBe(`${base}/risk/status`);
    expect(await security.listUserDevices("e1", "u1")).toEqual([]);
    expect(calls[1].url).toBe(`${base}/users/u1/devices`);
  });

  it("validates ids and the token locally", async () => {
    const { security, calls } = client(() => ({ body: {} }));
    await expect(security.getCaptcha("../x")).rejects.toMatchObject({ status: 400 });
    await expect(security.deleteRestriction("e1", "a/b")).rejects.toMatchObject({ status: 400 });
    await expect(security.listUserDevices("e1", "")).rejects.toMatchObject({ status: 400 });
    expect(() => new SecurityClient({ baseUrl: issuer, token: "" })).toThrow(IAMKitError);
    const empty = new SecurityClient({ baseUrl: issuer, token: () => undefined, fetch: fakeFetch(() => ({ body: {} })).fetch });
    await expect(empty.getStatus("e1")).rejects.toMatchObject({ status: 400 });
    expect(calls).toHaveLength(0);
  });
});

describe("IdentityClient login signals", () => {
  const boundary = { environmentId: "e", organizationId: "o", applicationId: "a", resourceId: "r" };

  it("forwards captchaToken and deviceId", async () => {
    const f = fakeFetch(() => ({ body: { mfa_required: true, mfa_token: "ik_mfa_x", enrollment_required: false, factors: ["email"], expires_in: 300, reason: "risk_challenge" } }));
    const out = await new IdentityClient({ baseUrl: issuer, fetch: f.fetch }).login(boundary, { login: "ada", password: "pw", captchaToken: "tok", deviceId: "0123456789abcdef0123456789abcdef" });
    expect(JSON.parse(f.calls[0].body)).toMatchObject({ captcha_token: "tok", device_id: "0123456789abcdef0123456789abcdef" });
    expect((out as { reason?: string }).reason).toBe("risk_challenge");
  });

  it("sends neither when unset", async () => {
    const f = fakeFetch(() => ({ body: { access_token: "at", token_type: "Bearer", expires_in: 1 } }));
    await new IdentityClient({ baseUrl: issuer, fetch: f.fetch }).login(boundary, { login: "ada", password: "pw" });
    const body = JSON.parse(f.calls[0].body);
    expect(body).not.toHaveProperty("captcha_token");
    expect(body).not.toHaveProperty("device_id");
  });
});
