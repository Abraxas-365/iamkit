// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let role = 'owner'
const env = '/environments/env1'
const console = '/projects/project1/environments/env1'
const client = { id: 'c1', application_id: 'a1', application_name: 'Web', resource_id: 'r1', resource_name: 'Billing', redirect_uris: ['https://app.example/callback', 'https://app.example/alt'], public: false, hosted_login: true, active: true }
const account = { id: 'sa1', name: 'worker', application_id: 'a1', application_name: 'Web', resource_id: 'r1', resource_name: 'Billing', permissions: ['invoices:read'], expires_at: '2099-01-01T00:00:00Z', revoked_at: null, token_endpoint_auth_method: 'client_secret_basic', token_endpoint_auth_signing_alg: 'RS256', jwks_uri: '' }
const connection = { id: 'f1', organization_id: 'o1', organization_name: 'Acme Corp', name: 'Acme Entra', provider: 'oidc', issuer: 'https://login.microsoftonline.com/x/v2.0', client_id: 'abc', active: true, linked: 3, jit_provisioning: true, enforcement: 'enforced', signup: false, link_email: false }
const token = { id: 'p1', name: 'Acme directory', organization_id: 'o1', organization_name: 'Acme Corp', connection_id: 'sc1', connection_name: 'Acme directory', expires_at: '2099-01-01T00:00:00Z', revoked_at: null, adopt_existing_members: true, adopt_scope: 'verified_domains' }

beforeEach(() => {
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method === 'PATCH' || init.method === 'DELETE') return new Response(null, { status: 204 })
    if (init.method === 'PUT' && path === `${env}/service-accounts/sa1/authentication`) return Response.json({ ...account, ...JSON.parse(String(init.body)) })
    if (init.method === 'PUT' && path === `${env}/service-accounts/sa1/impersonation`) return Response.json({ ...account, can_impersonate: JSON.parse(String(init.body)).allowed })
    if (init.method === 'POST' && path === `${env}/oauth-clients`) return Response.json({ id: 'c9', client_id: 'c9', client_secret: 'ik_client_s3cret' }, { status: 201 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/oauth-clients` ? page([client]) :
            path === `${env}/service-accounts` ? page([account]) :
            path === `${env}/oauth-clients/c1` ? client :
              path === `${env}/login-settings/clients/c1/sign-in` ? { client_id: 'c1', password: true, email_code: false, organization_sso: true, all_connections: true, connection_ids: [], signup: true, custom: true } :
                path === `${env}/federation-connections` ? page(url.includes('scope=environment') ? [] : [connection]) :
                  path === `${env}/provisioning-credentials` ? page([token]) :
                    path === `${env}/applications` ? page([{ id: 'a1', name: 'Web' }]) :
                      path === `${env}/resources` ? page([{ id: 'r1', name: 'Billing' }]) : page([])
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(page: string) {
  render(<MemoryRouter initialEntries={[`${console}/${page}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('lists OAuth clients by name and links to the detail page', async () => {
  open('oauth-clients')
  const link = await screen.findByRole('link', { name: 'Web' })
  expect(link.getAttribute('href')).toBe(`${console}/oauth-clients/c1`)
  expect(screen.getByText('Hosted page')).toBeTruthy()
  expect(screen.getByText('+1 more')).toBeTruthy()
  // Destructive actions live in the row menu, not as inline buttons.
  expect(screen.queryByRole('button', { name: /Disable/ })).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: 'Actions for Web' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Disable client' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Disable client' }))
  await waitFor(() => expect(calls('DELETE')).toEqual([{ url: `/management/v1${env}/oauth-clients/c1`, body: undefined }]))
})

it('creates a confidential client and shows its secret once', async () => {
  open('oauth-clients')
  await screen.findByRole('link', { name: 'Web' })
  await userEvent.click(screen.getByRole('button', { name: 'Create client' }))
  const dialog = await screen.findByRole('dialog')
  for (const [label, option] of [['Application', 'Web'], ['Resource', 'Billing']]) {
    const box = within(dialog).getByLabelText(label)
    await waitFor(() => expect((box as HTMLInputElement).disabled).toBe(false))
    await userEvent.click(box)
    await userEvent.pointer({ keys: '[MouseLeft>]', target: (await screen.findAllByText(option)).find(el => el.closest('li'))! })
  }
  await userEvent.type(within(dialog).getByPlaceholderText('Type and press Enter…'), 'https://app.example/cb{Enter}')
  await userEvent.click(within(dialog).getByLabelText(/Confidential/))
  await userEvent.click(within(dialog).getByLabelText(/Your own sign-in UI/))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Create client' }))
  await waitFor(() => expect(calls('POST')[0]?.body).toMatchObject({ public: false, hosted_login: false, application_id: 'a1', resource_id: 'r1', redirect_uris: ['https://app.example/cb'] }))
  expect(await screen.findByText('OAuth client created')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'I have saved the secret' })).toBeTruthy()
})

it('edits redirect URIs and the sign-in experience on the client page', async () => {
  open('oauth-clients/c1')
  expect(await screen.findByRole('heading', { name: 'Web' })).toBeTruthy()
  expect(screen.getByText('https://app.example/alt')).toBeTruthy()
  expect(await screen.findByText('Password · Organization SSO · All social')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Edit' }))
  await userEvent.click(screen.getByRole('button', { name: 'Remove https://app.example/alt' }))
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PATCH')[0]?.body).toEqual({ redirect_uris: ['https://app.example/callback'] }))
  await userEvent.click(screen.getByLabelText(/Your own sign-in UI/))
  await waitFor(() => expect(calls('PATCH')[1]?.body).toEqual({ hosted_login: false }))
})

it('edits post-logout redirect URIs on the client page', async () => {
  open('oauth-clients/c1')
  expect(await screen.findByText(/users see IAMKit's signed-out page/)).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Edit post-logout redirect URIs' }))
  await userEvent.type(screen.getByPlaceholderText(/signed-out — press Enter/), 'https://app.example/bye{Enter}')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PATCH')[0]?.body).toEqual({ post_logout_redirect_uris: ['https://app.example/bye'] }))
})

it('warns about http loopback redirect URIs without blocking them', async () => {
  const loopback = { ...client, redirect_uris: ['http://127.0.0.1/callback'], warnings: [{ code: 'loopback_redirect', field: 'redirect_uris', value: 'http://127.0.0.1/callback' }] }
  const base = fetchMock.getMockImplementation()!
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (!init.method && path === `${env}/oauth-clients/c1`) return Response.json(loopback)
    if (!init.method && path === `${env}/oauth-clients`) return Response.json({ items: [loopback], page: { total: 1, limit: 50, offset: 0 } })
    return base(url, init)
  })
  open('oauth-clients')
  expect(await screen.findByRole('img', { name: 'Uses http redirect URIs' })).toBeTruthy()
  cleanup()
  open('oauth-clients/c1')
  const note = await screen.findByRole('note', { name: 'Redirect URI warning' })
  expect(within(note).getByText('http://127.0.0.1/callback')).toBeTruthy()
  // While editing, the warning follows the URIs being typed.
  await userEvent.click(screen.getByRole('button', { name: 'Edit' }))
  await userEvent.click(screen.getByRole('button', { name: 'Remove http://127.0.0.1/callback' }))
  await waitFor(() => expect(screen.queryByRole('note', { name: 'Redirect URI warning' })).toBeNull())
  await userEvent.type(screen.getByPlaceholderText(/callback — press Enter/), 'http://localhost:3000/cb{Enter}')
  expect(within(await screen.findByRole('note', { name: 'Redirect URI warning' })).getByText('http://localhost:3000/cb')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PATCH')[0]?.body).toEqual({ redirect_uris: ['http://localhost:3000/cb'] }))
})

it('is read-only for viewers on the client page', async () => {
  role = 'viewer'
  open('oauth-clients/c1')
  await screen.findByRole('heading', { name: 'Web' })
  expect(screen.queryByRole('button', { name: 'Edit' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Edit post-logout redirect URIs' })).toBeNull()
  expect(screen.queryByRole('button', { name: /Disable/ })).toBeNull()
  expect(screen.getByLabelText(/Your own sign-in UI/).matches(":disabled")).toBe(true)
})

it('shows organization names instead of IDs for connections and SCIM tokens', async () => {
  open('federation')
  expect(await screen.findByText('Acme Corp')).toBeTruthy()
  expect(screen.getByText('SSO required')).toBeTruthy()
  cleanup()
  open('provisioning')
  expect(await screen.findByRole('link', { name: 'Acme Corp' })).toBeTruthy()
  expect(screen.getByText('Adopted (verified domains)')).toBeTruthy()
  expect(screen.getAllByText(/\/scim\/v2$/).length).toBeGreaterThan(0)
})

it('enables a disabled connection from its row', async () => {
  const active = fetchMock.getMockImplementation()!
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    if (!init.method && url.includes('/federation-connections') && url.includes('scope=organization')) return Response.json({ items: [{ ...connection, active: false }], page: { total: 1, limit: 50, offset: 0 } })
    if (init.method === 'POST' && url.endsWith('/enable')) return new Response(null, { status: 204 })
    return active(url, init)
  })
  open('federation')
  await userEvent.click(await screen.findByRole('button', { name: 'Actions for Acme Entra' }))
  expect(screen.queryByRole('menuitem', { name: 'Disable' })).toBeNull()
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Enable' }))
  await waitFor(() => expect(calls('POST')).toEqual([{ url: `/management/v1${env}/federation-connections/f1/enable`, body: undefined }]))
})

it('lands on the environment home with counts, setup steps and recent changes', async () => {
  open('')
  expect(await screen.findByRole('heading', { name: 'Environment home' })).toBeTruthy()
  // Applications and resources exist in the fixture; organizations do not.
  expect(await screen.findByText('3 of 4 required steps done')).toBeTruthy()
  expect(screen.getByRole('link', { name: /Add your first organization/ }).getAttribute('href')).toBe(`${console}/organizations`)
  expect(screen.getByRole('link', { name: 'Environment home' }).getAttribute('aria-current')).toBe('page')
  cleanup()
  open('oauth-clients')
  await screen.findByRole('link', { name: 'Web' })
  expect(screen.getByRole('link', { name: 'Environment home' }).getAttribute('aria-current')).toBeNull()
})

it('switches a service account to private_key_jwt with a key set URL', async () => {
  open('service-accounts')
  expect(await screen.findByText('Client secret (HTTP Basic)')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Actions for worker' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Authentication' }))
  const dialog = await screen.findByRole('dialog')
  await userEvent.click(within(dialog).getByLabelText(/Private key JWT/))
  await userEvent.selectOptions(within(dialog).getByLabelText('Signing algorithm'), 'ES256')
  await userEvent.click(within(dialog).getByLabelText(/Key set URL/))
  await userEvent.type(within(dialog).getByLabelText('JWKS URL'), 'https://svc.example/jwks')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toEqual([{ url: `/management/v1${env}/service-accounts/sa1/authentication`, body: { token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_signing_alg: 'ES256', jwks_uri: 'https://svc.example/jwks' } }]))
})

it('changes an OAuth client to private_key_jwt with an inline key set', async () => {
  open('oauth-clients/c1')
  await userEvent.click(await screen.findByRole('button', { name: 'Change' }))
  const dialog = await screen.findByRole('dialog')
  await userEvent.click(within(dialog).getByLabelText(/Private key JWT/))
  const jwks = within(dialog).getByLabelText('JSON Web Key Set')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
  expect(calls('PATCH')).toEqual([])
  await userEvent.click(jwks)
  await userEvent.paste('not json')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
  expect(await within(dialog).findByText('The key set is not valid JSON.')).toBeTruthy()
  await userEvent.clear(jwks)
  await userEvent.click(jwks)
  await userEvent.paste('{"keys":[{"kty":"EC","kid":"k"}]}')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PATCH')).toEqual([{ url: `/management/v1${env}/oauth-clients/c1`, body: { token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_signing_alg: 'RS256', jwks: { keys: [{ kty: 'EC', kid: 'k' }] } } }]))
})

it('warns before switching an OAuth client to opaque access tokens', async () => {
  open('oauth-clients/c1')
  const jwt = await screen.findByRole('radio', { name: /JWT/ })
  expect((jwt as HTMLInputElement).checked).toBe(true)
  await userEvent.click(screen.getByRole('radio', { name: /Opaque/ }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText(/accept only JWTs/)).toBeTruthy()
  expect(calls('PATCH')).toEqual([])
  await userEvent.click(within(dialog).getByRole('button', { name: 'Use opaque tokens' }))
  await waitFor(() => expect(calls('PATCH')).toEqual([{ url: `/management/v1${env}/oauth-clients/c1`, body: { access_token_format: 'opaque' } }]))
})

it('turns on the device authorization grant on the client page', async () => {
  open('oauth-clients/c1')
  const device = await screen.findByRole('switch', { name: 'Device authorization' })
  expect((device as HTMLInputElement).checked).toBe(false)
  expect((screen.getByRole('switch', { name: 'Authorization code' }) as HTMLInputElement).checked).toBe(true)
  await userEvent.click(device)
  await waitFor(() => expect(calls('PATCH')).toEqual([{ url: `/management/v1${env}/oauth-clients/c1`, body: { grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'] } }]))
})

it('turns on token exchange for a confidential client', async () => {
  open('oauth-clients/c1')
  const exchange = await screen.findByRole('switch', { name: 'Token exchange' })
  expect((exchange as HTMLInputElement).checked).toBe(false)
  await userEvent.click(exchange)
  await waitFor(() => expect(calls('PATCH')).toEqual([{ url: `/management/v1${env}/oauth-clients/c1`, body: { grant_types: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:token-exchange'] } }]))
})

it('lets owners allow a service account to impersonate users after confirming', async () => {
  open('service-accounts')
  await userEvent.click(await screen.findByRole('button', { name: 'Actions for worker' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Allow impersonation' }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText(/Every impersonation is audited/)).toBeTruthy()
  expect(calls('PUT')).toEqual([])
  await userEvent.click(within(dialog).getByRole('button', { name: 'Allow impersonation' }))
  await waitFor(() => expect(calls('PUT')).toEqual([{ url: `/management/v1${env}/service-accounts/sa1/impersonation`, body: { allowed: true } }]))
})

it('hides the impersonation switch from admins', async () => {
  role = 'admin'
  open('service-accounts')
  await userEvent.click(await screen.findByRole('button', { name: 'Actions for worker' }))
  expect(await screen.findByRole('menuitem', { name: 'Authentication' })).toBeTruthy()
  expect(screen.queryByRole('menuitem', { name: 'Allow impersonation' })).toBeNull()
})

it('turns on mobile phone sync when issuing another SCIM token', async () => {
  const base = fetchMock.getMockImplementation()!
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => init.method === 'POST' && url.includes('/provisioning-credentials')
    ? Response.json({ id: 'p2', secret: 'ik_scim_s3cret', expires_at: '2099-01-01T00:00:00Z', connection_id: 'sc1' }, { status: 201 })
    : base(url, init))
  open('provisioning')
  await userEvent.click(await screen.findByRole('button', { name: 'Actions for Acme directory' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Issue another token' }))
  const dialog = await screen.findByRole('dialog')
  await userEvent.click(within(dialog).getByRole('switch', { name: /Sync mobile phone numbers/ }))
  await userEvent.click(within(dialog).getByRole('button', { name: /Issue token/ }))
  await waitFor(() => expect(calls('POST')[0]?.body).toMatchObject({ connection_id: 'sc1', map_phone: true, adopt_existing_members: true }))
})
