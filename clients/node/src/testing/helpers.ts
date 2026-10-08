import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { SignJWT, exportJWK, type JWK } from "jose";

export const issuer = "https://iam.example.com";
export const expected = {
  issuer,
  audience: "https://api.example.com",
  environmentId: "env-1",
  applicationId: "app-1",
  resourceId: "res-1",
};

export interface Signer {
  kid: string;
  privateKey: KeyObject;
  jwk: JWK;
}

export async function rsaSigner(kid: string): Promise<Signer> {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: "RS256", use: "sig" };
  return { kid, privateKey, jwk };
}

export function sign(signer: Signer, claims: Record<string, unknown>, options: { typ?: string; expiresIn?: string | number } = {}): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: signer.kid, ...(options.typ ? { typ: options.typ } : {}) })
    .setIssuedAt()
    .setExpirationTime(options.expiresIn ?? "5m")
    .sign(signer.privateKey);
}

export function userClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: issuer,
    aud: [expected.audience],
    sub: "user-1",
    jti: "jti-1",
    environment_id: expected.environmentId,
    organization_id: "org-1",
    application_id: expected.applicationId,
    resource_id: expected.resourceId,
    permissions: ["invoices:read"],
    purpose: "application",
    sid: "session-1",
    amr: ["pwd"],
    ...overrides,
  };
}

export interface Call {
  url: string;
  method: string;
  headers: Headers;
  body: string;
}

/** A fake fetch answering from handler and recording every call. */
export function fakeFetch(handler: (call: Call) => { status?: number; body?: unknown } | Promise<{ status?: number; body?: unknown }>) {
  const calls: Call[] = [];
  const fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const call: Call = {
      url: String(input),
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: typeof init?.body === "string" ? init.body : "",
    };
    calls.push(call);
    const answer = await handler(call);
    const status = answer.status ?? 200;
    return new Response(answer.body === undefined || status === 204 ? null : JSON.stringify(answer.body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };
  return { fetch, calls };
}

export function jwksFetch(...signers: Signer[]) {
  return fakeFetch(() => ({ body: { keys: signers.map((s) => s.jwk) } }));
}
