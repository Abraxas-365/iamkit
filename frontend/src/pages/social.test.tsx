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
  base_url: '', authorize_url: '', token_url: '', userinfo_url: '', scopes: [], claim_subject: 'id', claim_email: 'email', claim_email_verified: '', claim_name: 'name', update_profile: false,
  metadata_url: '', metadata_xml: '', name_id_format: 'unspecified', attr_subject: '', attr_email: '', attr_name: '', sign_requests: false,
  ldap_url: '', start_tls: false, bind_dn: '', user_base_dn: '', user_filter: '', ca_pem: '',
}

it('builds and patches an LDAP connection', () => {
  const ldap = { ...values, provider: 'ldap' as const, scope: 'organization' as const, organization_id: 'o1', name: 'AD', client_secret: 'svc', ldap_url: ' ldaps://dc1.acme.com ', bind_dn: 'cn=iam', user_base_dn: 'ou=people', start_tls: true }
  // StartTLS only applies to ldap:// URLs; the secret goes with a bind DN.
  expect(connectionBody(ldap)).toEqual({ provider: 'ldap', name: 'AD', organization_id: 'o1', client_secret: 'svc', options: { url: 'ldaps://dc1.acme.com', bind_dn: 'cn=iam', user_base_dn: 'ou=people' } })
  expect(connectionBody({ ...ldap, ldap_url: 'ldap://dc1', bind_dn: '', user_filter: '(uid={username})', attr_subject: 'uid' })).toEqual({
    provider: 'ldap', name: 'AD', organization_id: 'o1', options: { url: 'ldap://dc1', start_tls: true, user_base_dn: 'ou=people', user_filter: '(uid={username})', attributes: { subject: 'uid' } },
  })
  const conn: ConnectionDetail = { ...google, provider: 'ldap', organization_id: 'o1', issuer: 'ldaps://dc1:636', secret_env: '', secret_source: 'sealed', jit_group_id: null, jit_provisioning: true, enforcement: 'optional', created_at: '', options: { url: 'ldaps://dc1', bind_dn: 'cn=iam', user_base_dn: 'ou=people' } }
  const same = { name: 'Google', ldap_url: 'ldaps://dc1', start_tls: false, user_base_dn: 'ou=people', user_filter: '', bind_dn: 'cn=iam', client_secret: '', ca_pem: '', attr_subject: '', attr_email: '', attr_name: '', jit_provisioning: true, jit_group_id: '', enforcement: 'optional' }
  expect(connectionPatch(conn, same)).toEqual({})
  expect(connectionPatch(conn, { ...same, user_filter: '(sAMAccountName={username})', client_secret: 'new' })).toEqual({ client_secret: 'new', options: { url: 'ldaps://dc1', bind_dn: 'cn=iam', user_base_dn: 'ou=people', user_filter: '(sAMAccountName={username})' } })
  // Going anonymous drops the password.
  expect(connectionPatch(conn, { ...same, bind_dn: '', client_secret: 'stale' })).toEqual({ options: { url: 'ldaps://dc1', user_base_dn: 'ou=people' } })
})

it('builds and patches a SAML connection', () => {
  const saml = { ...values, provider: 'saml' as const, scope: 'organization' as const, organization_id: 'o1', name: 'Okta', metadata_url: ' https://idp.example/metadata ' }
  expect(connectionBody(saml)).toEqual({ provider: 'saml', name: 'Okta', organization_id: 'o1', options: { metadata_url: 'https://idp.example/metadata' } })
  expect(connectionBody({ ...saml, metadata_xml: '<EntityDescriptor/>', name_id_format: 'transient', attr_subject: 'uid', attr_email: 'mail', sign_requests: true }).options).toEqual({
    metadata_xml: '<EntityDescriptor/>', name_id_format: 'transient', attributes: { subject: 'uid', email: 'mail' }, sign_requests: true,
  })
  const conn: ConnectionDetail = { ...google, provider: 'saml', organization_id: 'o1', secret_env: '', secret_source: 'none', jit_group_id: null, jit_provisioning: true, enforcement: 'optional', created_at: '', options: { metadata_xml: '<x/>', name_id_format: 'persistent' } }
  const same = { name: 'Google', metadata_url: '', metadata_xml: '', name_id_format: 'persistent', attr_subject: '', attr_email: '', attr_name: '', sign_requests: false, jit_provisioning: true, jit_group_id: '', enforcement: 'optional' }
  expect(connectionPatch(conn, same)).toEqual({})
  // The stored XML is kept when only a mapping changes.
  expect(connectionPatch(conn, { ...same, attr_email: 'mail' })).toEqual({ options: { metadata_xml: '<x/>', name_id_format: 'persistent', attributes: { email: 'mail' } } })
  expect(connectionPatch(conn, { ...same, metadata_url: 'https://idp/m' })).toEqual({ options: { metadata_url: 'https://idp/m', name_id_format: 'persistent' } })
  // A URL connection refetches at every save.
  const byURL: ConnectionDetail = { ...conn, options: { metadata_url: 'https://idp/m', metadata_xml: '<x/>' } }
  expect(connectionPatch(byURL, { ...same, name_id_format: 'unspecified', metadata_url: 'https://idp/m' })).toEqual({ options: { metadata_url: 'https://idp/m' } })
})

it('builds the create request of each provider', () => {
  expect(connectionBody(values)).toEqual({ provider: 'google', name: 'Google', client_id: 'gid', client_secret: 's', link_email: true })
  expect(connectionBody({ ...values, provider: 'oidc', issuer: 'https://idp.example ', scope: 'organization', organization_id: 'o1', link_email: true })).toEqual({ provider: 'oidc', name: 'Google', client_id: 'gid', client_secret: 's', issuer: 'https://idp.example', organization_id: 'o1' })
  expect(connectionBody({ ...values, provider: 'microsoft', tenants: ['t1'] }).options).toEqual({ tenant: 'common', tenants: ['t1'] })
  expect(connectionBody({ ...values, provider: 'microsoft', tenant: 'tenant', tenant_id: 't9', tenants: ['t1'] }).options).toEqual({ tenant: 't9' })
  expect(connectionBody({ ...values, domains: ['acme.com'] }).options).toEqual({ domains: ['acme.com'] })
  expect(connectionBody({ ...values, provider: 'microsoft', domains: ['acme.com'] }).options).toEqual({ tenant: 'common' })
  expect(connectionBody({ ...values, provider: 'apple', team_id: 'TEAM', key_id: 'KEY', secret_env: 'X' })).toMatchObject({ options: { team_id: 'TEAM', key_id: 'KEY' }, client_secret: 's' })
  expect(connectionBody({ ...values, signup: true, signup_organization_id: 'o1', signup_group_id: 'g1', link_email: false })).toMatchObject({ signup: true, signup_organization_id: 'o1', signup_group_id: 'g1' })
  expect(connectionBody({ ...values, provider: 'gitlab' }).options).toBeUndefined()
  expect(connectionBody({ ...values, provider: 'gitlab', base_url: ' https://git.example ' }).options).toEqual({ base_url: 'https://git.example' })
  expect(connectionBody({ ...values, provider: 'github_enterprise', base_url: 'https://ghe.example' }).options).toEqual({ base_url: 'https://ghe.example' })
  expect(connectionBody({ ...values, update_profile: true }).update_profile).toBe(true)
  expect(connectionBody({ ...values, provider: 'oauth2', authorize_url: 'https://p/a', token_url: 'https://p/t', userinfo_url: 'https://p/me', scopes: ['identify'], claim_email_verified: 'verified ' })).toMatchObject({
    provider: 'oauth2', options: { authorize_url: 'https://p/a', token_url: 'https://p/t', userinfo_url: 'https://p/me', scopes: ['identify'], claims: { subject: 'id', email: 'email', email_verified: 'verified', name: 'name' } },
  })
  expect((connectionBody({ ...values, provider: 'oauth2', claim_email: '', claim_name: '' }).options as { claims: unknown }).claims).toEqual({ subject: 'id' })
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
  expect(connectionPatch(conn, { ...same, update_profile: true })).toEqual({ update_profile: true })
  const oauth: ConnectionDetail = { ...conn, provider: 'oauth2', options: { authorize_url: 'https://p/a', token_url: 'https://p/t', userinfo_url: 'https://p/me', claims: { subject: 'id' } } }
  const form = { ...same, authorize_url: 'https://p/a', token_url: 'https://p/t', userinfo_url: 'https://p/me', scopes: '', claim_subject: 'id', claim_email: '', claim_email_verified: '', claim_name: '' }
  expect(connectionPatch(oauth, form)).toEqual({})
  expect(connectionPatch(oauth, { ...form, claim_email: 'email', claim_email_verified: 'verified' })).toEqual({ options: { authorize_url: 'https://p/a', token_url: 'https://p/t', userinfo_url: 'https://p/me', claims: { subject: 'id', email: 'email', email_verified: 'verified' } } })
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
  expect(within(dialog).getAllByRole('button').filter(b => b.hasAttribute('aria-pressed')).map(b => b.textContent)).toEqual(['Microsoft Entra ID', 'Google Workspace', 'GitLab self-managed', 'Other (OIDC)', 'SAML 2.0', 'LDAP / AD'])
  expect(within(dialog).getByLabelText('Organization')).toBeTruthy()
  expect(within(dialog).queryByLabelText('Used by')).toBeNull()
  // SAML asks for metadata instead of a client ID and secret.
  await userEvent.click(within(dialog).getByRole('button', { name: 'SAML 2.0' }))
  expect(within(dialog).getByLabelText('Metadata URL')).toBeTruthy()
  expect(within(dialog).queryByLabelText('Client ID')).toBeNull()
  expect(within(dialog).queryByLabelText('Client secret')).toBeNull()
  await userEvent.type(within(dialog).getByLabelText('Metadata XML'), '<x/>')
  expect(within(dialog).getByLabelText('Metadata URL').matches(':disabled')).toBe(true)
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
  const s = { client_id: 'c1', password: true, email_code: false, organization_sso: false, all_connections: false, connection_ids: ['g1', 'x'], signup: true, passkey: false, custom: true }
  expect(summary(s, [{ id: 'g1', name: 'Google', provider: 'google', organization_id: null, active: true }])).toBe('Password · Google · Unknown connection')
  expect(summary({ ...s, connection_ids: [], signup: false }, [])).toBe('Password · No sign-up')
  expect(summary({ ...s, connection_ids: [], passkey: true }, [])).toBe('Password · Passkey')
  expect(signInBody({ ...s, all_connections: true })).toMatchObject({ all_connections: true, connection_ids: [], signup: true, passkey: false })
})
