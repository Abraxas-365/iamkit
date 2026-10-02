import { createSignIn, type VerifierStore } from "@iamkit/js";

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

export const authorization = {
  client_id: "cl",
  environment_id: "env",
  application_id: "app",
  resource_id: "res",
  audience: "api",
  scopes: ["openid"],
  organization_id: null,
  login_hint: "",
  locale: "en",
  languages: ["en"],
  texts: { "hosted.title.sign_in": "Welcome back" },
  connections: [{ id: "google", name: "Google", provider: "google" }],
  branding: {},
  methods: { password: true, email_code: true, passkey: false, organization_sso: true, password_reset: true, signup: true, terms: false },
};

export const pair = { access_token: "at", refresh_token: "rt", token_type: "Bearer", expires_in: 300 };

export type Routes = Record<string, (body: any, url: URL) => Response>;

export function fakeIAM(routes: Routes, storage?: VerifierStore) {
  const calls: { route: string; body: any }[] = [];
  const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    const text = await request.text();
    const body = text ? JSON.parse(text) : undefined;
    const route = `${request.method} ${url.pathname}`;
    calls.push({ route, body });
    const handler = routes[route];
    return handler ? handler(body, url) : json(404, { error: { code: "NOT_FOUND", message: route, type: "not_found", http_status: 404 } });
  };
  return { calls, iam: createSignIn({ baseUrl: "https://id.example.com", fetch: fetcher as typeof fetch, storage }) };
}

export function memory(): VerifierStore {
  const items = new Map<string, string>();
  return { getItem: (k) => items.get(k) ?? null, setItem: (k, v) => void items.set(k, v), removeItem: (k) => void items.delete(k) };
}
