import { t } from '@/lib/i18n'
// The organization admin portal's session: an OAuth 2.0 authorization code
// + PKCE sign-in against IAMKit's own public client for the environment,
// tokens kept in sessionStorage (this tab only), and a bearer API client for
// /api/v1/environments/:environment/organizations/:organization/admin.

export class PortalError extends Error {
  constructor(public status: number, message: string, public code?: string) { super(message) }
}

/** Portal is what GET /identity/v1/org-admin/:environment answers. */
export interface Portal { client_id: string; environment_id: string; url: string }

export interface Tokens { access_token: string; refresh_token?: string; id_token?: string; expires_at: number }

/** Claims the portal reads from its tokens (the server checks them). */
export interface Claims {
  sub?: string; organization_id?: string; permissions?: string[]; name?: string; email?: string; nonce?: string; exp?: number
}

interface Pending { environment: string; state: string; nonce: string; verifier: string; redirect: string; client: string; back: string }

const pendingKey = 'iamkit-org-admin:pending'
const tokensKey = (environment: string) => `iamkit-org-admin:${environment}`

function base64url(bytes: Uint8Array) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function randomString(bytes = 32) {
  const out = new Uint8Array(bytes)
  crypto.getRandomValues(out)
  return base64url(out)
}

export async function challenge(verifier: string) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64url(new Uint8Array(digest))
}

/** decode reads a JWT payload without verifying it: the portal only uses it
 * to know the organization and to hide what the token cannot do. */
export function decode(token: string | undefined): Claims {
  const payload = token?.split('.')[1]
  if (!payload) return {}
  try {
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(payload.length / 4) * 4, '='))
    return JSON.parse(decodeURIComponent(Array.from(json, c => `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('')))
  } catch { return {} }
}

export async function discover(environment: string, signal?: AbortSignal): Promise<Portal> {
  const res = await fetch(`/identity/v1/org-admin/${encodeURIComponent(environment)}`, { signal, credentials: 'omit' })
  if (res.status === 404) throw new PortalError(404, t('The organization admin portal is not available for this environment.'))
  if (!res.ok) throw new PortalError(res.status, t('The organization admin portal could not be loaded. Try again.'))
  return res.json()
}

export function readTokens(environment: string): Tokens | null {
  try {
    const raw = sessionStorage.getItem(tokensKey(environment))
    return raw ? JSON.parse(raw) as Tokens : null
  } catch { return null }
}

function saveTokens(environment: string, tokens: Tokens) { sessionStorage.setItem(tokensKey(environment), JSON.stringify(tokens)) }
export function clearTokens(environment: string) { sessionStorage.removeItem(tokensKey(environment)) }

/** signIn sends the browser to the hosted login. `organization` hints the
 * organization (the hosted chooser is skipped when the user belongs to it). */
export async function signIn(environment: string, portal: Portal, options: { organization?: string; back?: string } = {}) {
  const verifier = randomString(48), state = randomString(), nonce = randomString()
  const redirect = `${portal.url}/callback`
  const pending: Pending = { environment, state, nonce, verifier, redirect, client: portal.client_id, back: options.back ?? '' }
  sessionStorage.setItem(pendingKey, JSON.stringify(pending))
  const q = new URLSearchParams({
    client_id: portal.client_id, redirect_uri: redirect, response_type: 'code', scope: 'openid profile email offline_access',
    state, nonce, code_challenge_method: 'S256', code_challenge: await challenge(verifier),
  })
  if (options.organization) q.set('organization_id', options.organization)
  window.location.assign(`/oauth/authorize?${q}`)
}

async function token(form: Record<string, string>): Promise<Tokens> {
  const res = await fetch('/oauth/token', { method: 'POST', credentials: 'omit', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form) })
  const body = await res.json().catch(() => null)
  if (!res.ok || !body?.access_token) throw new PortalError(res.status || 400, body?.error_description || body?.error || t('Sign-in failed. Try again.'), body?.error)
  return { access_token: body.access_token, refresh_token: body.refresh_token, id_token: body.id_token, expires_at: Date.now() + (Number(body.expires_in) || 300) * 1000 }
}

const completing = new Map<string, Promise<string>>()

/** complete finishes the sign-in on the callback page: it checks the state
 * and nonce, redeems the code and keeps the tokens, once per state (React
 * may run the callback effect twice). It returns the path to go back to. */
export function complete(environment: string, params: URLSearchParams): Promise<string> {
  const key = `${environment}:${params.get('state') ?? ''}`
  let running = completing.get(key)
  if (!running) {
    running = redeem(environment, params)
    completing.set(key, running)
  }
  return running
}

async function redeem(environment: string, params: URLSearchParams): Promise<string> {
  const raw = sessionStorage.getItem(pendingKey)
  sessionStorage.removeItem(pendingKey)
  const pending = raw ? JSON.parse(raw) as Pending : null
  if (params.get('error')) throw new PortalError(400, params.get('error_description') || t('Sign-in was cancelled.'), params.get('error') ?? undefined)
  if (!pending || pending.environment !== environment || !params.get('state') || params.get('state') !== pending.state) throw new PortalError(400, t('This sign-in link expired or was opened in another tab. Sign in again.'))
  const tokens = await token({ grant_type: 'authorization_code', client_id: pending.client, redirect_uri: pending.redirect, code: params.get('code') ?? '', code_verifier: pending.verifier })
  if (tokens.id_token && decode(tokens.id_token).nonce !== pending.nonce) throw new PortalError(400, t('The sign-in response did not match this request. Sign in again.'))
  saveTokens(environment, tokens)
  return pending.back
}

const refreshing = new Map<string, Promise<Tokens | null>>()

/** refresh swaps the refresh token for new tokens once, however many
 * requests ask at the same time; null when the session has ended. */
export function refresh(environment: string, client: string): Promise<Tokens | null> {
  const current = readTokens(environment)
  if (!current?.refresh_token) return Promise.resolve(null)
  let running = refreshing.get(environment)
  if (!running) {
    running = token({ grant_type: 'refresh_token', client_id: client, refresh_token: current.refresh_token })
      .then(next => { const merged = { ...next, id_token: next.id_token ?? current.id_token }; saveTokens(environment, merged); return merged })
      .catch(() => { clearTokens(environment); return null })
      .finally(() => refreshing.delete(environment))
    refreshing.set(environment, running)
  }
  return running
}

/** signOut ends the IAMKit session and comes back to the portal. */
export function signOut(environment: string, portal: Portal) {
  const tokens = readTokens(environment)
  clearTokens(environment)
  const q = new URLSearchParams({ client_id: portal.client_id, post_logout_redirect_uri: portal.url })
  if (tokens?.id_token) q.set('id_token_hint', tokens.id_token)
  window.location.assign(`/oauth/end_session?${q}`)
}

/** userInfo reads who is signed in from /oauth/userinfo: IAMKit's ID and
 * access tokens do not carry the email or name. Null when it cannot. */
export async function userInfo(environment: string, signal?: AbortSignal): Promise<{ email?: string; name?: string } | null> {
  const tokens = readTokens(environment)
  if (!tokens) return null
  try {
    const res = await fetch('/oauth/userinfo', { signal, credentials: 'omit', headers: { Authorization: `Bearer ${tokens.access_token}` } })
    return res.ok ? await res.json() : null
  } catch { return null }
}

export interface Page<T> { items: T[]; page: { total: number; limit: number; offset: number } }

/** Client calls the organization's /admin routes with the bearer token,
 * refreshing it once on expiry. `onExpired` runs when the session is gone. */
export class Client {
  constructor(private environment: string, private portal: Portal, public organization: string, private onExpired: () => void) {}

  get base() { return `/api/v1/environments/${this.environment}/organizations/${this.organization}/admin` }

  async request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
    const tokens = readTokens(this.environment)
    if (!tokens) { this.onExpired(); throw new PortalError(401, t('Your session ended. Sign in again.')) }
    const res = await fetch(`${this.base}${path}`, {
      ...init, credentials: 'omit',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokens.access_token}`, ...init.headers },
    })
    if (res.status === 401 && retry) {
      if (await refresh(this.environment, this.portal.client_id)) return this.request<T>(path, init, false)
      this.onExpired()
    }
    if (!res.ok) {
      const body = await res.json().catch(() => null)
      throw new PortalError(res.status, body?.error?.message || (res.status === 403 ? t('You do not have permission to do this.') : res.statusText || t('Request failed.')), body?.error?.code)
    }
    if (res.status === 204) return undefined as T
    const text = await res.text()
    return text ? JSON.parse(text) as T : undefined as T
  }

  get<T>(path: string, signal?: AbortSignal) { return this.request<T>(path, { signal }) }
  post<T>(path: string, body?: unknown) { return this.request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) }) }
  put<T>(path: string, body: unknown) { return this.request<T>(path, { method: 'PUT', body: JSON.stringify(body) }) }
  patch(path: string, body: unknown) { return this.request<void>(path, { method: 'PATCH', body: JSON.stringify(body) }) }
  delete(path: string) { return this.request<void>(path, { method: 'DELETE' }) }
}
