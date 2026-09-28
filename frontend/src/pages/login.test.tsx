// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let options: unknown
beforeEach(() => {
  options = { password: true, providers: [] }
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  fetchMock.mockImplementation(async (url: string) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (path === '/login-options') return options === 'error' ? new Response('down', { status: 503 }) : Response.json(options)
    return Response.json({ error: { message: 'management credential required' } }, { status: 401 })
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[path]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('shows only the password form without single sign-on', async () => {
  open('/login')
  await screen.findByLabelText('Password')
  expect(screen.queryByRole('link', { name: /Continue with/ })).toBeNull()
  expect(screen.queryByRole('separator', { name: 'or' })).toBeNull()
  expect(screen.getByRole('link', { name: 'Set up your account' })).toBeTruthy()
})

it('shows a button per provider next to the password form', async () => {
  options = { password: true, providers: [{ id: 'okta', name: 'Acme Okta', type: 'oidc' }, { id: 'google', name: 'Google', type: 'google' }, { id: 'entra', name: 'Microsoft', type: 'microsoft' }] }
  open('/login')
  const okta = await screen.findByRole('link', { name: 'Continue with Acme Okta' })
  expect(okta.getAttribute('href')).toBe('/management/v1/sso/okta/start')
  expect(screen.getByRole('link', { name: 'Continue with Google' }).getAttribute('href')).toBe('/management/v1/sso/google/start')
  expect(screen.getByRole('link', { name: 'Continue with Microsoft' }).getAttribute('href')).toBe('/management/v1/sso/entra/start')
  expect(screen.getByRole('separator', { name: 'or' })).toBeTruthy()
  expect(screen.getByLabelText('Password')).toBeTruthy()
})

it('hides the password form and setup when password sign-in is off', async () => {
  options = { password: false, providers: [{ id: 'okta', name: 'Acme Okta', type: 'oidc' }] }
  open('/login')
  await screen.findByRole('link', { name: 'Continue with Acme Okta' })
  expect(screen.queryByLabelText('Password')).toBeNull()
  expect(screen.queryByRole('separator', { name: 'or' })).toBeNull()
  expect(screen.queryByRole('link', { name: 'Set up your account' })).toBeNull()
  expect(screen.getByText(/Ask a workspace owner to invite your work email/)).toBeTruthy()
})

it('redirects /setup to the login page when password sign-in is off', async () => {
  options = { password: false, providers: [{ id: 'okta', name: 'Acme Okta', type: 'oidc' }] }
  open('/setup')
  await screen.findByRole('link', { name: 'Continue with Acme Okta' })
  expect(screen.queryByLabelText('Management API key')).toBeNull()
})

it('explains single sign-on errors from the callback', async () => {
  open('/login?sso_error=not_authorized')
  expect(await screen.findByText(/This account cannot sign in to the console/)).toBeTruthy()
  cleanup()
  open('/login?sso_error=something-new')
  expect(await screen.findByText('Single sign-on failed. Please try again.')).toBeTruthy()
})

it('falls back to password sign-in when login options are unavailable', async () => {
  options = 'error'
  open('/login')
  expect(await screen.findByLabelText('Password')).toBeTruthy()
})

it('signs in with a password', async () => {
  const user = userEvent.setup()
  let signedIn = false
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (path === '/login-options') return Response.json(options)
    if (path === '/login' && init.method === 'POST') { signedIn = true; return Response.json({ operator_id: 'op1', workspace_id: 'ws1', role: 'owner' }) }
    if (path === '/me' && signedIn) return Response.json({ operator_id: 'op1', workspace_id: 'ws1', role: 'owner' })
    if (!signedIn) return Response.json({ error: { message: 'unauthorized' } }, { status: 401 })
    return Response.json([])
  })
  open('/login')
  await user.type(await screen.findByLabelText('Operator email'), 'owner@example.com')
  await user.type(screen.getByLabelText('Password'), 'Owner-Passw0rd-2026')
  await user.click(screen.getByRole('button', { name: 'Sign in' }))
  await waitFor(() => expect(screen.queryByLabelText('Password')).toBeNull())
})

it('asks for a new password when the current one must change', async () => {
  const user = userEvent.setup()
  let signedIn = false
  const logins: Record<string, string>[] = []
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (path === '/login-options') return Response.json(options)
    if (path === '/login' && init.method === 'POST') {
      const body = JSON.parse(String(init.body)) as Record<string, string>
      logins.push(body)
      if (!body.new_password) return Response.json({ error: { code: 'PASSWORD_CHANGE_REQUIRED', message: 'choose a new password to finish signing in' } }, { status: 403 })
      signedIn = true; return Response.json({ operator_id: 'op1', workspace_id: 'ws1', role: 'owner' })
    }
    if (path === '/me' && signedIn) return Response.json({ operator_id: 'op1', workspace_id: 'ws1', role: 'owner' })
    if (!signedIn) return Response.json({ error: { message: 'unauthorized' } }, { status: 401 })
    return Response.json([])
  })
  open('/login')
  await user.type(await screen.findByLabelText('Operator email'), 'owner@example.com')
  await user.type(screen.getByLabelText('Password'), 'bootstrap password')
  await user.click(screen.getByRole('button', { name: 'Sign in' }))
  expect(await screen.findByRole('heading', { name: 'Choose a new password' })).toBeTruthy()
  await user.type(screen.getByLabelText('New password'), 'bootstrap password')
  await user.type(screen.getByLabelText('Confirm password'), 'bootstrap password')
  await user.click(screen.getByRole('button', { name: 'Set password and sign in' }))
  expect(await screen.findByText('Choose a password different from the current one.')).toBeTruthy()
  expect(logins).toHaveLength(1)
  await user.clear(screen.getByLabelText('New password'))
  await user.clear(screen.getByLabelText('Confirm password'))
  await user.type(screen.getByLabelText('New password'), 'owner chosen password')
  await user.type(screen.getByLabelText('Confirm password'), 'owner chosen password')
  await user.click(screen.getByRole('button', { name: 'Set password and sign in' }))
  await waitFor(() => expect(screen.queryByLabelText('New password')).toBeNull())
  expect(logins[1]).toEqual({ email: 'owner@example.com', password: 'bootstrap password', new_password: 'owner chosen password' })
})
