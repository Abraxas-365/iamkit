// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { connectionBody, type ConnectionValues } from './federation-connection-form'
import { connectionPatch, type ConnectionDetail } from './federation-detail'
import { signInBody, summary } from './sign-in-options'

const fetchMock = vi.fn()
const env = '/environments/env1'
const client = { id: 'c1', application_id: 'a1', application_name: 'Shop', resource_id: 'r1', resource_name: 'Store', redirect_uris: ['https://shop.example/cb'], public: true, hosted_login: true, active: true }
const google = { id: 'g1', organization_id: null, name: 'Google', provider: 'google', issuer: 'https://accounts.google.com', client_id: 'gid', active: true, linked: 0, jit_provisioning: false, enforcement: 'optional', signup: true, link_email: true }
const github = { ...google, id: 'h1', name: 'GitHub', provider: 'github', issuer: 'https://github.com', signup: false }
let signIns: unknown[] = []

beforeEach(() => {
  signIns = []
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method === 'POST') return Response.json({ id: 'new', ...JSON.parse(String(init.body)) }, { status: 201 })
    if (init.method === 'PUT') return Response.json({ client_id: 'c1', custom: true, ...JSON.parse(String(init.body)) })
    if (init.method) return new Response(null, { status: 204 })
    if (path.endsWith('/login-settings/preview')) return Response.json({ html: '<!doctype html><title>preview</title>' })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role: 'owner' } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/login-settings` ? { environment_id: 'env1', display_name: 'Acme' } :
            path === `${env}/login-settings/sign-in` ? page(signIns) :
              path === `${env}/login-settings/clients/c1/sign-in` ? { client_id: 'c1', password: true, email_code: true, organization_sso: true, all_connections: true, connection_ids: [], custom: false } :
                path === `${env}/oauth-clients` ? page([client]) :
                  path === `${env}/federation-connections` ? page(url.includes('scope=organization') ? [] : [google, github]) :
                    path === `${env}/organizations` ? page([{ id: 'o1', name: 'Customers' }]) : page([])
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(page: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${page}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

const values: ConnectionValues = {
  provider: 'google', scope: 'environment', organization_id: '', name: 'Google', issuer: 'ignored', client_id: ' gid ', client_secret: 's', secret_env: '',
  tenant: 'common', tenant_id: '', tenants: [], domains: [], team_id: '', key_id: '', signup: false, signup_organization_id: '', signup_group_id: '', link_email: true,
}

it('builds the create request of each provider', () => {
  expect(connectionBody(values)).toEqual({ provider: 'google', name: 'Google', client_id: 'gid', client_secret: 's', link_email: true })
  expect(connectionBody({ ...values, provider: 'oidc', issuer: 'https://idp.example ', scope: 'organization', organization_id: 'o1', link_email: true })).toEqual({ provider: 'oidc', name: 'Google', client_id: 'gid', client_secret: 's', issuer: 'https://idp.example', organization_id: 'o1' })
  expect(connectionBody({ ...values, provider: 'microsoft', tenants: ['t1'] }).options).toEqual({ tenant: 'common', tenants: ['t1'] })
  expect(connectionBody({ ...values, provider: 'microsoft', tenant: 'tenant', tenant_id: 't9', tenants: ['t1'] }).options).toEqual({ tenant: 't9' })
  expect(connectionBody({ ...values, domains: ['acme.com'] }).options).toEqual({ domains: ['acme.com'] })
  expect(connectionBody({ ...values, provider: 'microsoft', domains: ['acme.com'] }).options).toEqual({ tenant: 'common' })
  expect(connectionBody({ ...values, provider: 'apple', team_id: 'TEAM', key_id: 'KEY', secret_env: 'X' })).toMatchObject({ options: { team_id: 'TEAM', key_id: 'KEY' }, client_secret: 's' })
  expect(connectionBody({ ...values, signup: true, signup_organization_id: 'o1', signup_group_id: 'g1', link_email: false })).toMatchObject({ signup: true, signup_organization_id: 'o1', signup_group_id: 'g1' })
})

it('patches social settings of an environment connection', () => {
  const conn: ConnectionDetail = { ...google, secret_env: '', secret_source: 'sealed', jit_group_id: null, enforcement: 'optional', signup_organization_id: 'o1', signup_group_id: null, created_at: '' }
  const same = { name: 'Google', client_secret: '', link_email: true, signup: true, signup_organization_id: 'o1', signup_group_id: '' }
  expect(connectionPatch(conn, same)).toEqual({})
  expect(connectionPatch(conn, { ...same, signup: false })).toEqual({ signup: false })
  expect(connectionPatch(conn, { ...same, signup_organization_id: 'o2', signup_group_id: 'g1' })).toEqual({ signup_organization_id: 'o2', signup_group_id: '' })
  expect(connectionPatch(conn, { ...same, signup_group_id: 'g1' })).toEqual({ signup_group_id: 'g1' })
  const apple: ConnectionDetail = { ...conn, provider: 'apple', options: { team_id: 'T', key_id: 'K1' } }
  expect(connectionPatch(apple, { ...same, key_id: 'K2', client_secret: 'pem' })).toMatchObject({ client_secret: 'pem', options: { team_id: 'T', key_id: 'K2' } })
})

it('creates a Google connection from the preset form', async () => {
  open('federation')
  await screen.findByRole('link', { name: 'GitHub' })
  await userEvent.click(screen.getByRole('button', { name: 'Add social login' }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).queryByLabelText('Issuer URL')).toBeNull()
  expect(within(dialog).getByText(/\/identity\/v1\/federation\/callback$/)).toBeTruthy()
  await userEvent.type(within(dialog).getByLabelText('Client ID'), 'gid')
  await userEvent.type(within(dialog).getByLabelText('Client secret'), 'secret')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }))
  await waitFor(() => expect(calls('POST')).toEqual([{ url: `/management/v1${env}/federation-connections`, body: { provider: 'google', name: 'Google', client_id: 'gid', client_secret: 'secret', link_email: true } }]))
})

it('keeps the server-variable secret under Advanced', async () => {
  open('federation')
  await screen.findByRole('link', { name: 'GitHub' })
  await userEvent.click(screen.getByRole('button', { name: 'Add social login' }))
  const dialog = await screen.findByRole('dialog')
  const toggle = within(dialog).getByRole('button', { name: 'Advanced' })
  expect(toggle.getAttribute('aria-expanded')).toBe('false')
  expect(within(dialog).queryByLabelText(/Server environment variable/)).toBeNull()
  await userEvent.click(toggle)
  await userEvent.type(within(dialog).getByLabelText('Client ID'), 'gid')
  await userEvent.type(within(dialog).getByLabelText(/Server environment variable/), 'IAMKIT_PROVIDER_GOOGLE')
  // The pasted secret is no longer required, and cannot be combined with the variable.
  expect(within(dialog).getByLabelText('Client secret').matches(':disabled')).toBe(true)
  await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }))
  await waitFor(() => expect(calls('POST')).toEqual([{ url: `/management/v1${env}/federation-connections`, body: { provider: 'google', name: 'Google', client_id: 'gid', secret_env: 'IAMKIT_PROVIDER_GOOGLE', link_email: true } }]))
})

it('asks for the Apple key, team and key ID', async () => {
  open('federation')
  await screen.findByRole('link', { name: 'GitHub' })
  await userEvent.click(screen.getByRole('button', { name: 'Add social login' }))
  const dialog = await screen.findByRole('dialog')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Apple' }))
  expect(within(dialog).getByLabelText('Services ID')).toBeTruthy()
  expect(within(dialog).getByLabelText('Private key (.p8)')).toBeTruthy()
  expect(within(dialog).getByLabelText('Team ID')).toBeTruthy()
  expect(within(dialog).queryByRole('button', { name: 'Advanced' })).toBeNull()
  expect((within(dialog).getByLabelText('Name') as HTMLInputElement).value).toBe('Apple')
})

it('separates social login from organization SSO', async () => {
  open('federation')
  expect(await screen.findByRole('heading', { name: 'Sign-in providers' })).toBeTruthy()
  const social = (await screen.findByRole('heading', { name: 'Social login', level: 2 })).closest('section')!
  expect(await within(social).findByRole('link', { name: 'GitHub' })).toBeTruthy()
  expect(within(social).getByText('Can sign up · links by email')).toBeTruthy()
  const sso = screen.getByRole('heading', { name: 'Organization SSO', level: 2 }).closest('section')!
  expect(await within(sso).findByText('No organization SSO yet')).toBeTruthy()
  expect(fetchMock.mock.calls.some(([url]) => String(url).includes('federation-connections?') && String(url).includes('scope=organization'))).toBe(true)

  await userEvent.click(within(sso).getByRole('button', { name: 'Add organization SSO' }))
  const dialog = await screen.findByRole('dialog', { name: 'Add organization SSO' })
  // Personal-account providers are not offered for company SSO.
  expect(within(dialog).getAllByRole('button').filter(b => b.hasAttribute('aria-pressed')).map(b => b.textContent)).toEqual(['Microsoft Entra ID', 'Google Workspace', 'Other (OIDC)'])
  expect(within(dialog).getByLabelText('Organization')).toBeTruthy()
  expect(within(dialog).queryByLabelText('Used by')).toBeNull()
})

it('chooses the sign-in methods of a client', async () => {
  open('hosted-login')
  expect(await screen.findByText('All methods')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Actions for Shop · Store' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Choose sign-in methods' }))
  const dialog = await screen.findByRole('dialog')
  await userEvent.click(await within(dialog).findByLabelText(/^Password/))
  await userEvent.click(within(dialog).getByLabelText(/^Every environment connection/))
  await userEvent.click(within(dialog).getByLabelText(/^Google/))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toEqual([{ url: `/management/v1${env}/login-settings/clients/c1/sign-in`, body: { password: false, email_code: true, organization_sso: true, all_connections: false, connection_ids: ['g1'] } }]))
})

it('summarizes sign-in options', () => {
  const s = { client_id: 'c1', password: true, email_code: false, organization_sso: false, all_connections: false, connection_ids: ['g1', 'x'], signup: true, custom: true }
  expect(summary(s, [{ id: 'g1', name: 'Google', provider: 'google', organization_id: null, active: true }])).toBe('Password · Google · Unknown connection')
  expect(summary({ ...s, connection_ids: [], signup: false }, [])).toBe('Password · No sign-up')
  expect(signInBody({ ...s, all_connections: true })).toMatchObject({ all_connections: true, connection_ids: [], signup: true })
})
