// A stable random id per browser for IAMKit's risk signals: it enables the
// new-device detection and the user's device list. It is not a fingerprint:
// 128 random bits, kept in localStorage, never derived from the browser.

import type { VerifierStore } from "./signin.js";

/** localStorage key of the device id. */
export const deviceKey = "iamkit.device_id";

/** A random 32-character hex device id (128 bits). */
export function createDeviceId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

function localStore(): VerifierStore | undefined {
  try {
    return typeof localStorage !== "undefined" ? localStorage : undefined;
  } catch {
    // Access denied (sandboxed frames, blocked cookies).
    return undefined;
  }
}

/**
 * Resolves the device id a client sends. `false` opts out (nothing is sent
 * or stored); a string is sent as is; otherwise the id is read from (or
 * created in) `storage`, defaulting to localStorage. Without any storage —
 * server rendering — it is undefined, so the call carries no device id.
 * When the browser refuses storage the id lives as long as the client.
 */
export class DeviceId {
  private memory?: string;

  constructor(
    private readonly option: string | false | undefined,
    private readonly storage?: VerifierStore,
  ) {}

  get(): string | undefined {
    if (this.option === false) {
      return undefined;
    }
    if (typeof this.option === "string") {
      return this.option || undefined;
    }
    const store = this.storage ?? localStore();
    if (!store) {
      if (typeof window === "undefined") {
        return undefined;
      }
      return (this.memory ??= createDeviceId());
    }
    try {
      const known = store.getItem(deviceKey);
      if (known) {
        return known;
      }
      const created = createDeviceId();
      store.setItem(deviceKey, created);
      return created;
    } catch {
      return (this.memory ??= createDeviceId());
    }
  }
}
