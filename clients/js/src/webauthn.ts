import { base64url, fromBase64url } from "./pkce.js";

// WebAuthn glue for security keys (second factor) and passkeys (first
// factor): IAMKit sends PublicKeyCredentialRequestOptions JSON with
// base64url buffers and expects the assertion back as JSON.

/** Reports whether this browser can run WebAuthn ceremonies. */
export function webauthnSupported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined" && typeof navigator?.credentials?.get === "function";
}

interface RequestOptionsJSON {
  challenge: string;
  allowCredentials?: { id: string; type: string; transports?: string[] }[];
  [key: string]: unknown;
}

/** Decodes IAMKit's options (`options.publicKey` or the bare object). */
export function requestOptions(options: unknown): PublicKeyCredentialRequestOptions {
  const wrapped = options as { publicKey?: RequestOptionsJSON } & RequestOptionsJSON;
  const o = { ...(wrapped.publicKey ?? wrapped) } as RequestOptionsJSON;
  return {
    ...(o as object),
    challenge: fromBase64url(o.challenge),
    allowCredentials: (o.allowCredentials ?? []).map((c) => ({ ...c, id: fromBase64url(c.id) })),
  } as PublicKeyCredentialRequestOptions;
}

/** Encodes an assertion the way IAMKit's verifier reads it. */
export function assertionJSON(credential: PublicKeyCredential): Record<string, unknown> {
  const r = credential.response as AuthenticatorAssertionResponse;
  const enc = (b: ArrayBuffer | null | undefined) => (b ? base64url(new Uint8Array(b)) : undefined);
  return {
    id: credential.id,
    rawId: enc(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    response: {
      clientDataJSON: enc(r.clientDataJSON),
      authenticatorData: enc(r.authenticatorData),
      signature: enc(r.signature),
      userHandle: enc(r.userHandle),
    },
  };
}

/**
 * Asks the browser for an assertion. `mediation: "conditional"` offers
 * passkeys in the autofill of an input with `autocomplete="username webauthn"`.
 * Resolves null when the user dismissed the prompt.
 */
export async function getAssertion(options: unknown, init: { signal?: AbortSignal; mediation?: CredentialMediationRequirement } = {}): Promise<Record<string, unknown> | null> {
  if (!webauthnSupported()) {
    throw new Error("WebAuthn is not available in this browser");
  }
  try {
    const credential = (await navigator.credentials.get({ publicKey: requestOptions(options), signal: init.signal, mediation: init.mediation })) as PublicKeyCredential | null;
    return credential ? assertionJSON(credential) : null;
  } catch (err) {
    if (err instanceof DOMException && (err.name === "AbortError" || err.name === "NotAllowedError")) {
      return null;
    }
    throw err;
  }
}
