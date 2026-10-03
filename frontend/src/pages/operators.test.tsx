// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let options: unknown
let role = 'owner'
const operators = () => ({ items: [
  { id: 'op-owner', email: 'owner@example.com', role: 'owner', active: true, password_allowed: true, sso_providers: [], last_sso_login_at: null },
  { id: 'op-ann', email: 'ann@acme.com', role: 'admin', active: true, password_allowed: false, sso_providers: ['okta'], last_sso_login_at: '2026-09-27T12:00:00Z' },
  { id: 'op-bob', email: 'bob@acme.com', role: 'owner', active: true, password_allowed: true, sso_providers: [], last_sso_login_at: null },
], page: { total: 3, limit: 50, offset: 0 } })
beforeEach(() => {
  role = 'owner'
  options = { password: true, providers: [{ id: 'okta', name: 'Acme Okta', type: 'oidc' }] }
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method === 'DELETE' || init.method === 'PUT') return new Response(null, { status: 204 })
    if (path === '/login-options') return Response.json(options)
    if (path === '/me') return Response.json({ operator_id: 'op-owner', workspace_id: 'ws1', role })
    if (path === '/operators') return Response.json(operators())
    return Response.json([])
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[path]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('shows linked single sign-on providers and resets a link', async () => {
  const user = userEvent.setup()
  open('/operators')
  await screen.findByText('ann@acme.com')
  expect(screen.getByRole('columnheader', { name: 'Single sign-on' })).toBeTruthy()
  expect(screen.getByText('Acme Okta')).toBeTruthy()
  expect(screen.getAllByText('Not linked')).toHaveLength(2)
  await user.click(screen.getByRole('button', { name: 'Actions for ann@acme.com' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Reset SSO link' }))
  const dialog = await screen.findByRole('dialog')
  await user.click(within(dialog).getByRole('button', { name: 'Reset SSO link' }))
  await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url).endsWith('/operators/op-ann/identities') && init?.method === 'DELETE')).toBe(true))
})

it('hides the single sign-on column when it is not configured', async () => {
  options = { password: true, providers: [] }
  open('/operators')
  await screen.findByText('ann@acme.com')
  expect(screen.queryByRole('columnheader', { name: 'Single sign-on' })).toBeNull()
})

it('offers no reset to admins', async () => {
  role = 'admin'
  open('/operators')
  await screen.findByText('ann@acme.com')
  expect(screen.queryByRole('button', { name: 'Actions for ann@acme.com' })).toBeNull()
})

it('tells the owner how an invited operator signs in', async () => {
  const user = userEvent.setup()
  options = { password: false, providers: [{ id: 'okta', name: 'Acme Okta', type: 'oidc' }] }
  open('/operators')
  await user.click(await screen.findByRole('button', { name: 'Invite operator' }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText(/They can sign in with Acme Okta using this email/)).toBeTruthy()
  expect(within(dialog).getByText(/Password sign-in is disabled/)).toBeTruthy()
  expect(within(dialog).queryByText('/setup')).toBeNull()
})

it('replaces the password form in settings when password sign-in is off', async () => {
  options = { password: false, providers: [{ id: 'okta', name: 'Acme Okta', type: 'oidc' }] }
  open('/settings')
  expect(await screen.findByText('Password sign-in is disabled')).toBeTruthy()
  expect(screen.queryByLabelText('New password')).toBeNull()
})

it('manages emergency access in break-glass mode', async () => {
  const user = userEvent.setup()
  options = { password: true, password_mode: 'break_glass', providers: [{ id: 'okta', name: 'Acme Okta', type: 'oidc' }] }
  open('/operators')
  await screen.findByText('ann@acme.com')
  expect(screen.getAllByText('Emergency access')).toHaveLength(2)
  await user.click(screen.getByRole('button', { name: 'Actions for ann@acme.com' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Allow emergency access' }))
  await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Allow emergency access' }))
  await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url).endsWith('/operators/op-ann/password-access') && init?.method === 'PUT' && init.body === JSON.stringify({ allowed: true }))).toBe(true))
  await user.click(screen.getByRole('button', { name: 'Actions for bob@acme.com' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Remove emergency access' }))
  await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Remove emergency access' }))
  await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url).endsWith('/operators/op-bob/password-access') && init?.method === 'PUT' && init.body === JSON.stringify({ allowed: false }))).toBe(true))
  // Never one's own: it would end this session.
  expect(screen.queryByRole('button', { name: 'Actions for owner@example.com' })).toBeNull()
})

it('offers no emergency access outside break-glass mode', async () => {
  const user = userEvent.setup()
  open('/operators')
  await screen.findByText('ann@acme.com')
  expect(screen.queryByText('Emergency access')).toBeNull()
  await user.click(screen.getByRole('button', { name: 'Actions for ann@acme.com' }))
  await screen.findByRole('menuitem', { name: 'Reset SSO link' })
  expect(screen.queryByRole('menuitem', { name: 'Allow emergency access' })).toBeNull()
})
