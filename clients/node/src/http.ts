import { toError } from "./errors.js";

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface TransportOptions {
  /** IAMKit deployment origin, e.g. `https://iam.example.com`. */
  baseUrl: string;
  /** Custom fetch (tests, proxies). Defaults to globalThis.fetch. */
  fetch?: FetchLike;
  /** Per-request timeout in milliseconds (default 10 000; 0 disables). */
  timeoutMs?: number;
}

/** Response bodies larger than this are refused (1 MiB). */
export const MaxBody = 1 << 20;

export class Transport {
  readonly baseUrl: string;
  private readonly fetcher: FetchLike;
  private readonly timeoutMs: number;

  constructor(options: TransportOptions) {
    if (!options.baseUrl) {
      throw new TypeError("baseUrl is required");
    }
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.fetcher = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  /** Sends a request to baseUrl + path and decodes a JSON answer (undefined for 204). */
  async send<T>(path: string, init: RequestInit & { headers?: Record<string, string> }): Promise<T> {
    const signal = init.signal ?? (this.timeoutMs > 0 ? AbortSignal.timeout(this.timeoutMs) : undefined);
    // Credentials never follow redirects: IAMKit answers its APIs directly.
    const response = await this.fetcher(this.baseUrl + path, { ...init, redirect: "manual", signal });
    const text = await readText(response);
    const body = text ? parse(text) : undefined;
    if (response.status < 200 || response.status >= 300) {
      throw toError(response.status, body);
    }
    return body as T;
  }

  /** POSTs a JSON body. */
  json<T>(path: string, body: unknown, token?: string): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    return this.send<T>(path, { method: "POST", headers, body: body === undefined ? undefined : JSON.stringify(body) });
  }

  /** GETs with an optional bearer token. */
  get<T>(path: string, token?: string): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    return this.send<T>(path, { method: "GET", headers });
  }

  /** POSTs a form (the OAuth endpoints). */
  form<T>(path: string, form: URLSearchParams, headers: Record<string, string> = {}): Promise<T> {
    return this.send<T>(path, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded", ...headers },
      body: form.toString(),
    });
  }
}

async function readText(response: Response): Promise<string> {
  const length = Number(response.headers.get("content-length") ?? "0");
  if (length > MaxBody) {
    throw toError(response.status >= 400 ? response.status : 502, undefined);
  }
  const text = await response.text();
  if (text.length > MaxBody) {
    throw toError(response.status >= 400 ? response.status : 502, undefined);
  }
  return text;
}

function parse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** Appends a query string built from the defined values. */
export function withQuery(path: string, query: Record<string, string | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== "") {
      params.set(key, value);
    }
  }
  const encoded = params.toString();
  return encoded ? `${path}?${encoded}` : path;
}
