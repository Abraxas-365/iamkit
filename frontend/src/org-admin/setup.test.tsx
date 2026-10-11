// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import OrgAdminPortal from './portal'

const fetchMock = vi.fn()
let calls: { url: string; method: string; body?: unknown; auth?: string }[] = []
let exchange: (body: { token: string }) => Response = () => Response.json({})
const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
const ok = (intents: string[]) => Response.json({ access_token: 'ik_setupsess_abc', token_type: 'Bearer', expires_in: 3600, environment_id: 'env1', organization_id: 'org1', intents, organization_name: 'Acme' })

beforeEach(() => {
  calls = []
  sessionStorage.clear()
  window.history.replaceState(null, '', '/')
  exchange = () => ok(['sso', 'directory', 'domains'])
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET'
    const headers = (init.headers ?? {}) as Record<string, string>
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ url, method, body, auth: headers.Authorization })
    if (url === '/identity/v1/org-admin/env1') return Response.json({ client_id: 'client1', environment_id: 'env1', url: 'https://iam.example/org-admin/env1' })
    if (url === '/identity/v1/org-admin/setup') return exchange(body)
    const path = url.replace('/api/v1/environments/env1/organizations/org1/admin', '').split('?')[0]
    if (path === '/connections') return Response.json(page([{ id: 'c1', name: 'Okta SAML', provider: 'saml', enforcement: 'optional', active: true, linked: 0 }]))
    if (path === '/connections/c1') return Response.json({ id: 'c1', name: 'Okta SAML', provider: 'saml', saml: { entity_id: 'https://iam.example/sp', acs_url: 'https://iam.example/acs', metadata_url: 'https://iam.example/sp' } })
    if (path === '/directories') return Response.json({ items: [], scim_url: 'https://iam.example/scim/v2' })
    return Response.json(page([]))
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })

function open(fragment = '#ik_setup_secret') {
  window.history.replaceState(null, '', `/org-admin/env1/setup${fragment}`)
  const router = createMemoryRouter([{ path: '/org-admin/*', element: <OrgAdminPortal /> }], { initialEntries: ['/org-admin/env1/setup'] })
  render(<RouterProvider router={router} />)
}

it('exchanges the fragment, clears it and shows only the setup steps without member UI', async () => {
  open()
  expect(await screen.findByRole('heading', { name: 'Domains' }, { timeout: 3000 })).toBeTruthy()
  expect(window.location.hash).toBe('')
  expect(calls.find(c => c.url === '/identity/v1/org-admin/setup')?.body).toEqual({ token: 'ik_setup_secret' })
  expect(screen.getByText('Acme')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Sign out' })).toBeNull()
  expect(screen.queryByRole('link', { name: 'Members' })).toBeNull()
  expect(screen.queryByRole('navigation', { name: 'Organization administration' })).toBeNull()
  expect(sessionStorage.getItem('iamkit-org-admin-setup:env1')).toContain('ik_setupsess_abc')
  // Calls use the setup bearer.
  await waitFor(() => expect(calls.some(c => c.url.includes('/admin/domains') && c.auth === 'Bearer ik_setupsess_abc')).toBe(true))
})

it('steps through the intents to a Done screen', async () => {
  const user = userEvent.setup()
  open()
  const steps = await screen.findByRole('list', { name: 'Setup steps' })
  expect(within(steps).getAllByRole('listitem')).toHaveLength(3)
  await user.click(screen.getByRole('button', { name: 'Next' }))
  expect(await screen.findByText('Okta SAML')).toBeTruthy()
  // SP details for the customer's identity provider.
  expect(await screen.findByText('https://iam.example/acs')).toBeTruthy()
  await user.click(screen.getByRole('button', { name: 'Next' }))
  expect(await screen.findByText('https://iam.example/scim/v2')).toBeTruthy()
  await user.click(screen.getByRole('button', { name: 'Done' }))
  expect(await screen.findByRole('heading', { name: 'All done' })).toBeTruthy()
})

it('shows only Log streams for a log_streams link, without sources', async () => {
  exchange = () => ok(['log_streams'])
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ url, method: init.method ?? 'GET', body, auth: (init.headers as Record<string, string> | undefined)?.Authorization })
    if (url === '/identity/v1/org-admin/env1') return Response.json({ client_id: 'client1', environment_id: 'env1', url: 'https://iam.example/org-admin/env1' })
    if (url === '/identity/v1/org-admin/setup') return exchange(body)
    if (url.endsWith('/admin/log-streams')) return Response.json({ items: [] })
    return Response.json(page([]))
  })
  open()
  const steps = await screen.findByRole('list', { name: 'Setup steps' })
  expect(within(steps).getAllByRole('listitem')).toHaveLength(1)
  expect(await screen.findByRole('heading', { name: 'Log streams' })).toBeTruthy()
  expect(screen.queryByRole('link', { name: 'Audit logs' })).toBeNull()
  const user = userEvent.setup()
  await user.click((await screen.findAllByRole('button', { name: 'Add log stream' }))[0])
  expect(screen.queryByText('Sources')).toBeNull()
  expect(calls.some(c => c.url.includes('/admin/log-streams') && c.auth === 'Bearer ik_setupsess_abc')).toBe(true)
})

it('shows only the intents the link allows', async () => {
  exchange = () => ok(['domains'])
  open()
  const steps = await screen.findByRole('list', { name: 'Setup steps' })
  expect(within(steps).getAllByRole('listitem')).toHaveLength(1)
  expect(screen.getByRole('button', { name: 'Done' })).toBeTruthy()
})

it('explains an invalid or expired link', async () => {
  exchange = () => Response.json({ error: { message: 'unauthorized' } }, { status: 401 })
  open()
  expect(await screen.findByText('This setup link cannot be used')).toBeTruthy()
  expect(screen.getByText('This setup link is invalid, has expired or was revoked.')).toBeTruthy()
  expect(calls.some(c => c.url.includes('/admin'))).toBe(false)
  expect(sessionStorage.getItem('iamkit-org-admin-setup:env1')).toBeNull()
})

it('ends the setup when the server refuses the bearer', async () => {
  exchange = () => ok(['domains'])
  open()
  await screen.findByRole('list', { name: 'Setup steps' })
  fetchMock.mockImplementation(async () => Response.json({ error: { message: 'unauthorized' } }, { status: 401 }))
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: 'Add domain' }))
  await user.type(await screen.findByLabelText('Domain'), 'acme.com')
  await user.click(screen.getByRole('button', { name: 'Add' }))
  expect(await screen.findByText('This setup link cannot be used')).toBeTruthy()
  expect(sessionStorage.getItem('iamkit-org-admin-setup:env1')).toBeNull()
})

it('does not offer adopting members or a token without expiry to a setup link', async () => {
  exchange = () => ok(['directory'])
  const user = userEvent.setup()
  open()
  await screen.findByRole('list', { name: 'Setup steps' })
  await user.click((await screen.findAllByRole('button', { name: 'Add token' }))[0])
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText('Sync mobile phone numbers')).toBeTruthy()
  expect(within(dialog).queryByText('Adopt existing members')).toBeNull()
  expect(within(dialog).queryByText('Which emails can be adopted')).toBeNull()
  expect(within(dialog).queryAllByText('1 year').length).toBe(1)
  expect(within(dialog).queryAllByText('No expiry').length).toBe(0)
}, 20000)
