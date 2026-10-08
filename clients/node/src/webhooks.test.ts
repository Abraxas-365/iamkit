import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Conditions, deny, verifyAction, verifySignature, verifyWebhook, WebhookError } from "./webhooks.js";

// The Standard Webhooks reference vector (also used by sdk/webhook).
const secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const body = '{"test": 2432232314}';
const now = new Date(1614265330 * 1000);
const headers = {
  "webhook-id": "msg_p5jXN8AQM9LWM0D4loKWxJek",
  "webhook-timestamp": "1614265330",
  "webhook-signature": "v1,bogus v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
};

function signed(payload: string, key = secret, at = Math.floor(Date.now() / 1000)) {
  const id = "msg_1";
  const signature = createHmac("sha256", Buffer.from(key.slice(6), "base64")).update(`${id}.${at}.${payload}`).digest("base64");
  return new Headers({ "webhook-id": id, "webhook-timestamp": String(at), "webhook-signature": `v1,${signature}` });
}

describe("verifySignature", () => {
  it("accepts the reference vector (string, bytes, Headers)", () => {
    expect(() => verifySignature(secret, headers, body, { now })).not.toThrow();
    expect(() => verifySignature(secret, new Headers(headers), new TextEncoder().encode(body), { now })).not.toThrow();
    expect(() => verifySignature(secret, { "Webhook-Id": headers["webhook-id"], "Webhook-Timestamp": headers["webhook-timestamp"], "Webhook-Signature": headers["webhook-signature"] }, body, { now })).not.toThrow();
  });

  it("refuses stale timestamps, tampering and malformed secrets", () => {
    const code = (fn: () => void) => {
      try {
        fn();
      } catch (error) {
        expect(error).toBeInstanceOf(WebhookError);
        return (error as WebhookError).code;
      }
      return "none";
    };
    expect(code(() => verifySignature(secret, headers, body, { now: new Date(now.getTime() + 10 * 60_000) }))).toBe("TIMESTAMP");
    expect(code(() => verifySignature(secret, { ...headers, "webhook-id": "msg_other" }, body, { now }))).toBe("SIGNATURE");
    expect(code(() => verifySignature(secret, headers, body + " ", { now }))).toBe("SIGNATURE");
    expect(code(() => verifySignature("nope!", headers, body, { now }))).toBe("SECRET");
    expect(code(() => verifySignature(secret, { ...headers, "webhook-timestamp": "" }, body, { now }))).toBe("TIMESTAMP");
  });

  it("accepts either secret's signature during a rotation", () => {
    const payload = '{"id":1}';
    const h = signed(payload, "whsec_c2VjcmV0");
    const other = signed(payload, secret, Number(h.get("webhook-timestamp")));
    h.set("webhook-signature", `${other.get("webhook-signature")} ${h.get("webhook-signature")}`);
    expect(() => verifySignature("whsec_c2VjcmV0", h, payload)).not.toThrow();
    expect(() => verifySignature(secret, h, payload)).not.toThrow();
  });
});

describe("verifyWebhook / verifyAction", () => {
  it("decodes a verified event", () => {
    const payload = JSON.stringify({ id: 7, environment_id: "e", type: "user.created", actor: { kind: "operator", id: "o" }, subject: { kind: "user", id: "u" }, occurred_at: "2026-01-01T00:00:00Z" });
    expect(verifyWebhook(secret, signed(payload), payload)).toMatchObject({ id: 7, type: "user.created" });
  });

  it("decodes a verified action input and builds answers", () => {
    const payload = JSON.stringify({ condition: Conditions.PreAccessToken, environment_id: "e", user: { id: "u", email: "a@b.c" }, amr: ["pwd"] });
    const input = verifyAction(secret, signed(payload), payload);
    expect(input.condition).toBe("function:pre_access_token");
    expect(input.user?.email).toBe("a@b.c");
    expect(deny("blocked")).toEqual({ deny: true, message: "blocked" });
  });

  it("refuses an unsigned body before parsing", () => {
    expect(() => verifyWebhook(secret, { "webhook-id": "x", "webhook-timestamp": String(Math.floor(Date.now() / 1000)) }, "{}")).toThrow(WebhookError);
  });
});
