import { describe, expect, it } from "vitest";
import { base64url } from "./pkce";
import { requestOptions } from "./webauthn";

describe("WebAuthn options", () => {
  it("decodes IAMKit's base64url buffers, bare or under publicKey", () => {
    const challenge = base64url(new Uint8Array([1, 2, 3, 250]));
    const id = base64url(new Uint8Array([9, 9]));
    for (const raw of [{ challenge, rpId: "id.example.com", allowCredentials: [{ id, type: "public-key" }] }, { publicKey: { challenge, rpId: "id.example.com", allowCredentials: [{ id, type: "public-key" }] } }]) {
      const o = requestOptions(raw);
      expect([...new Uint8Array(o.challenge as ArrayBuffer)]).toEqual([1, 2, 3, 250]);
      expect([...new Uint8Array(o.allowCredentials![0].id as ArrayBuffer)]).toEqual([9, 9]);
      expect(o.rpId).toBe("id.example.com");
    }
  });

  it("leaves the caller's options untouched", () => {
    const raw = { challenge: base64url(new Uint8Array([7])) };
    requestOptions(raw);
    expect(typeof raw.challenge).toBe("string");
  });
});
