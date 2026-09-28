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
    if (init.method === 'POST' && path === `${env}/oauth-clients`) return Response.json({ id: 'c9', client_id: 'c9', client_secret: 'ik_client_s3cret' }, { status: 201 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/oauth-clients` ? page([client]) :
            path === `${env}/oauth-clients/c1` ? client :
              path === `${env}/login-settings/clients/c1/sign-in` ? { client_id: 'c1', password: true, email_code: false, organization_sso: true, all_connections: true, connection_ids: [], custom: true } :
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

it('is read-only for viewers on the client page', async () => {
  role = 'viewer'
  open('oauth-clients/c1')
  await screen.findByRole('heading', { name: 'Web' })
  expect(screen.queryByRole('button', { name: 'Edit' })).toBeNull()
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
