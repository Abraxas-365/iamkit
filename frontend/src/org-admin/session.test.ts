// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { Client, complete, decode, readTokens, refresh, signIn, type Portal } from './session'

const portal: Portal = { client_id: 'client1', environment_id: 'env1', url: 'https://iam.example/org-admin/env1' }
const fetchMock = vi.fn()
const assign = vi.fn()

function jwt(claims: Record<string, unknown>) {
  // Real JWTs are base64url of UTF-8 JSON.
  const part = (v: unknown) => btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(v)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${part({ alg: 'none' })}.${part(claims)}.sig`
}

beforeEach(() => {
  sessionStorage.clear()
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('location', { ...window.location, assign })
})
afterEach(() => { vi.unstubAllGlobals(); vi.resetAllMocks() })

async function startSignIn() {
  await signIn('env1', portal, { organization: 'org1', back: '/org-admin/env1/members' })
  const url = new URL(assign.mock.calls[0][0], 'https://iam.example')
  return url.searchParams
}

it('starts an authorization code + PKCE sign-in with the organization hint', async () => {
  const q = await startSignIn()
  expect(q.get('client_id')).toBe('client1')
  expect(q.get('redirect_uri')).toBe('https://iam.example/org-admin/env1/callback')
  expect(q.get('response_type')).toBe('code')
  expect(q.get('code_challenge_method')).toBe('S256')
  expect(q.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/)
  expect(q.get('organization_id')).toBe('org1')
  expect(q.get('scope')).toContain('offline_access')
})

it('redeems the code once, checks the nonce and keeps the tokens in this tab', async () => {
  const q = await startSignIn()
  const idToken = jwt({ nonce: q.get('nonce') })
  fetchMock.mockResolvedValue(Response.json({ access_token: 'at1', refresh_token: 'rt1', id_token: idToken, expires_in: 300 }))
  const params = new URLSearchParams({ code: 'code1', state: q.get('state')! })
  // React may run the callback effect twice: both get the same answer.
  const [a, b] = await Promise.all([complete('env1', params), complete('env1', params)])
  expect(a).toBe('/org-admin/env1/members')
  expect(b).toBe(a)
  expect(fetchMock).toHaveBeenCalledTimes(1)
  const body = new URLSearchParams(String(fetchMock.mock.calls[0][1].body))
  expect(body.get('code_verifier')).toBeTruthy()
  expect(body.get('redirect_uri')).toBe('https://iam.example/org-admin/env1/callback')
  expect(readTokens('env1')?.access_token).toBe('at1')
})

it('refuses a callback whose state does not match', async () => {
  await startSignIn()
  await expect(complete('env1', new URLSearchParams({ code: 'c', state: 'forged' }))).rejects.toThrow(/expired|another tab/)
  expect(fetchMock).not.toHaveBeenCalled()
  expect(readTokens('env1')).toBeNull()
})

it('refuses an ID token for another sign-in', async () => {
  const q = await startSignIn()
  fetchMock.mockResolvedValue(Response.json({ access_token: 'at1', id_token: jwt({ nonce: 'other' }), expires_in: 300 }))
  await expect(complete('env1', new URLSearchParams({ code: 'c', state: q.get('state')! }))).rejects.toThrow(/did not match/)
  expect(readTokens('env1')).toBeNull()
})

it('refreshes once for concurrent requests and retries with the new token', async () => {
  sessionStorage.setItem('iamkit-org-admin:env1', JSON.stringify({ access_token: 'old', refresh_token: 'rt1', expires_at: 0 }))
  const auth: string[] = []
  fetchMock.mockImplementation(async (url: string, init: RequestInit) => {
    if (url === '/oauth/token') return Response.json({ access_token: 'new', refresh_token: 'rt2', expires_in: 300 })
    const header = (init.headers as Record<string, string>).Authorization
    auth.push(header)
    return header === 'Bearer new' ? Response.json({ name: 'Acme' }) : Response.json({ error: { message: 'expired' } }, { status: 401 })
  })
  const client = new Client('env1', portal, 'org1', vi.fn())
  const [a, b] = await Promise.all([client.get<{ name: string }>(''), client.get<{ name: string }>('')])
  expect(a.name).toBe('Acme')
  expect(b.name).toBe('Acme')
  expect(fetchMock.mock.calls.filter(c => c[0] === '/oauth/token')).toHaveLength(1)
  expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/environments/env1/organizations/org1/admin')
  expect(readTokens('env1')?.refresh_token).toBe('rt2')
})

it('signs out when the refresh token is refused', async () => {
  sessionStorage.setItem('iamkit-org-admin:env1', JSON.stringify({ access_token: 'old', refresh_token: 'rt1', expires_at: 0 }))
  fetchMock.mockImplementation(async (url: string) => url === '/oauth/token'
    ? Response.json({ error: 'invalid_grant' }, { status: 400 })
    : Response.json({ error: { message: 'expired' } }, { status: 401 }))
  const expired = vi.fn()
  await expect(new Client('env1', portal, 'org1', expired).get('')).rejects.toThrow('expired')
  expect(expired).toHaveBeenCalled()
  expect(readTokens('env1')).toBeNull()
  expect(await refresh('env1', 'client1')).toBeNull()
})

it('decodes token claims and tolerates garbage', () => {
  expect(decode(jwt({ organization_id: 'org1', permissions: ['iam:org:read'], name: 'Zoë' }))).toEqual({ organization_id: 'org1', permissions: ['iam:org:read'], name: 'Zoë' })
  expect(decode('not-a-jwt')).toEqual({})
  expect(decode(undefined)).toEqual({})
})
