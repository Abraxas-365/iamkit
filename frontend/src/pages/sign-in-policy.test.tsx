// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
const defaults = { allow_password: true, allow_email_code: true, allow_social: true, allow_passkey: true, allow_password_reset: true, mfa_required: false, mfa_for_federated: false, allow_signup: false, signup_organization_id: '', signup_group_id: '', allowed_factors: ['totp', 'webauthn'], custom: false }
const noRequirements = { min_length: 0, require_upper: false, require_lower: false, require_digit: false, require_symbol: false, max_age_days: 0, breach_check: false, custom: false }
let policy: Record<string, unknown>
let requirements: Record<string, unknown>
let calls: { method: string; path: string; body?: Record<string, unknown> }[]
let role = 'owner'

beforeEach(() => {
  policy = { ...defaults }
  requirements = { ...noRequirements }
  calls = []
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    const method = init.method ?? 'GET'
    if (method !== 'GET') calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined })
    if (path === `${env}/sign-in-policy` && method === 'PUT') { policy = { ...JSON.parse(String(init.body)), custom: true }; return Response.json(policy) }
    if (path === `${env}/sign-in-policy` && method === 'DELETE') { policy = { ...defaults }; return new Response(null, { status: 204 }) }
    if (path === `${env}/organizations/org1/password-policy` && method === 'PUT') { requirements = { ...JSON.parse(String(init.body)), custom: true }; return Response.json(requirements) }
    if (path === `${env}/organizations/org1/password-policy` && method === 'DELETE') { requirements = { ...noRequirements }; return new Response(null, { status: 204 }) }
    if (method !== 'GET') return new Response(null, { status: 204 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/sign-in-policy` ? policy :
            path === `${env}/organizations/org1` ? { id: 'org1', name: 'Acme', active: true, mfa_required: false, mfa_for_federated: false, allow_password: true, allow_email_code: true, allow_social: false, allow_passkey: true } :
              path === `${env}/organizations/org1/password-policy` ? requirements :
                path === `${env}/organizations` ? page([{ id: 'org1', name: 'Acme', active: true }]) :
                  path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('turns password sign-in off, which also turns off reset', async () => {
  const u = userEvent.setup()
  open('sign-in-policy')
  const password = await screen.findByRole('switch', { name: 'Password' })
  expect(screen.getByText(/every method allowed/)).toBeTruthy()
  await u.click(password)
  expect((screen.getByRole('switch', { name: 'Password reset' }) as HTMLButtonElement).disabled).toBe(true)
  await u.click(screen.getByRole('switch', { name: 'Require a second factor everywhere' }))
  await u.click(screen.getByRole('button', { name: 'Save methods' }))
  const { custom: _custom, ...unchanged } = defaults
  await waitFor(() => expect(calls).toEqual([{ method: 'PUT', path: `${env}/sign-in-policy`, body: { ...unchanged, allow_password: false, allow_password_reset: false, mfa_required: true } }]))
  expect(await screen.findByText(/Custom policy/)).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'Restore default' }))
  await u.click(await screen.findByRole('button', { name: 'Restore default' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'DELETE', path: `${env}/sign-in-policy`, body: undefined }))
})

it('warns when only organization SSO remains', async () => {
  const u = userEvent.setup()
  open('sign-in-policy')
  await u.click(await screen.findByRole('switch', { name: 'Password' }))
  await u.click(screen.getByRole('switch', { name: 'Email code' }))
  await u.click(screen.getByRole('switch', { name: 'Social connections' }))
  expect(screen.queryByRole('note')).toBeNull() // passkeys still sign users in
  await u.click(screen.getByRole('switch', { name: 'Passkeys' }))
  expect(screen.getByRole('note').textContent).toMatch(/Only organization SSO/)
})

it('ties passkeys to the security key factor', async () => {
  const u = userEvent.setup()
  open('sign-in-policy')
  const passkeys = await screen.findByRole('switch', { name: 'Passkeys' }) as HTMLButtonElement
  expect(passkeys.disabled).toBe(false)
  await u.click(screen.getByRole('switch', { name: 'Security keys and passkeys' }))
  expect(passkeys.disabled).toBe(true)
  await u.click(screen.getByRole('switch', { name: 'Security keys and passkeys' }))
  await u.click(passkeys)
  await u.click(screen.getByRole('button', { name: 'Save methods' }))
  const { custom: _custom, ...unchanged } = defaults
  await waitFor(() => expect(calls).toEqual([{ method: 'PUT', path: `${env}/sign-in-policy`, body: { ...unchanged, allow_passkey: false } }]))
})

it('turns sign-up on into an organization', async () => {
  const u = userEvent.setup()
  open('sign-in-policy')
  await u.click(await screen.findByRole('switch', { name: 'Allow sign-up' }))
  const save = screen.getByRole('button', { name: 'Save methods' }) as HTMLButtonElement
  expect(save.disabled).toBe(true)
  await u.click(await screen.findByLabelText('Organization new accounts join'))
  fireEvent.mouseDown(await screen.findByText('Acme'))
  expect(await screen.findByLabelText('Default group (optional)')).toBeTruthy()
  await waitFor(() => expect(save.disabled).toBe(false))
  await u.click(save)
  const { custom: _custom, ...unchanged } = defaults
  await waitFor(() => expect(calls).toEqual([{ method: 'PUT', path: `${env}/sign-in-policy`, body: { ...unchanged, allow_signup: true, signup_organization_id: 'org1' } }]))
})

it('allows more second factors and keeps at least one', async () => {
  const u = userEvent.setup()
  open('sign-in-policy')
  await u.click(await screen.findByRole('switch', { name: 'Code by text message (SMS)' }))
  await u.click(screen.getByRole('switch', { name: 'Code by email' }))
  expect(screen.getByText(/purpose/).textContent).toContain('a custom webhook must handle it')
  await u.click(screen.getByRole('switch', { name: 'Authenticator app' }))
  await u.click(screen.getByRole('switch', { name: 'Security keys and passkeys' }))
  await u.click(screen.getByRole('switch', { name: 'Code by email' }))
  expect((screen.getByRole('switch', { name: 'Code by text message (SMS)' }) as HTMLButtonElement).disabled).toBe(true)
  await u.click(screen.getByRole('button', { name: 'Save methods' }))
  const { custom: _custom, ...unchanged } = defaults
  await waitFor(() => expect(calls).toEqual([{ method: 'PUT', path: `${env}/sign-in-policy`, body: { ...unchanged, allowed_factors: ['sms'] } }]))
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  open('sign-in-policy')
  expect(((await screen.findByRole('switch', { name: 'Password' })) as HTMLButtonElement).disabled).toBe(true)
  expect(screen.queryByRole('button', { name: 'Save methods' })).toBeNull()
})

it('narrows an organization\'s methods and tightens its passwords', async () => {
  const u = userEvent.setup()
  open('organizations/org1')
  const social = await screen.findByRole('switch', { name: 'Social' }) as HTMLInputElement
  expect(social.checked).toBe(false)
  await u.click(screen.getByRole('switch', { name: 'Password' }))
  await waitFor(() => expect(calls).toEqual([{ method: 'PATCH', path: `${env}/organizations/org1`, body: { allow_password: false } }]))
  await u.click(screen.getByRole('switch', { name: 'Passkey' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'PATCH', path: `${env}/organizations/org1`, body: { allow_passkey: false } }))
  await u.click(screen.getByRole('switch', { name: 'Code by email' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'PATCH', path: `${env}/organizations/org1`, body: { allowed_factors: ['totp', 'webauthn', 'sms'] } }))

  const length = await screen.findByLabelText('Minimum length')
  await u.clear(length); await u.type(length, '16')
  await u.click(screen.getByRole('switch', { name: 'Require a symbol' }))
  await u.click(screen.getByRole('button', { name: 'Save requirements' }))
  const { custom: _custom, ...unchanged } = noRequirements
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'PUT', path: `${env}/organizations/org1/password-policy`, body: { ...unchanged, min_length: 16, require_symbol: true } }))
  await u.click(await screen.findByRole('button', { name: 'Remove requirements' }))
  await u.click(await screen.findByRole('button', { name: 'Remove' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'DELETE', path: `${env}/organizations/org1/password-policy`, body: undefined }))
})
