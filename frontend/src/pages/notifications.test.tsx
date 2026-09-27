// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let role = 'owner'
let config: Record<string, unknown> | null = null
let status: Record<string, unknown>
const delivery = '/environments/env1/delivery'
const hosted = 'https://iam.example/hosted/invite'

beforeEach(() => {
  role = 'owner'
  config = null
  status = { source: 'global', global_configured: true, hosted_invitation_url: hosted, last_attempt: null, last_failure: null }
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method === 'POST' && path === `${delivery}/test`) {
      return Response.json({ source: 'environment', purpose: 'test', delivered: false, status: 503, reason: 'webhook rejected the request', latency_ms: 12, at: '2026-09-27T10:00:00Z' })
    }
    if (init.method === 'PUT') return new Response(null, { status: 204 })
    if (path === delivery) return config ? Response.json(config) : Response.json({ error: { message: 'delivery config not found' } }, { status: 404 })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${delivery}/status` ? status : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/notifications']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('shows the global fallback, every message type and a correct description', async () => {
  open()
  await screen.findByText('Global fallback')
  expect(screen.getByText(/login codes, password resets, email verification and invitations/)).toBeTruthy()
  expect(screen.getByText('No deliveries yet.')).toBeTruthy()
  for (const p of ['login', 'password_reset', 'email_verification', 'invitation', 'test']) expect(screen.getByText(p)).toBeTruthy()
  await userEvent.click(screen.getAllByRole('button', { name: 'Example' })[3])
  expect(screen.getByLabelText('invitation example payload').textContent).toContain('"expires_at"')
})

it('warns when nothing can deliver and hides the test button', async () => {
  status = { ...status, source: 'none', global_configured: false }
  open()
  await screen.findByText('Not configured')
  expect(screen.queryByRole('button', { name: /Send test email/ })).toBeNull()
})

it('shows the last attempt and the sticky last failure', async () => {
  config = { environment_id: 'env1', webhook_url: 'https://mail.example/hook', has_token: true, invitation_url: hosted, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }
  status = {
    ...status, source: 'environment',
    last_attempt: { source: 'environment', purpose: 'login', delivered: true, latency_ms: 42, at: '2026-09-27T10:00:00Z' },
    last_failure: { source: 'environment', purpose: 'invitation', delivered: false, status: 500, reason: 'webhook rejected the request', latency_ms: 0, at: '2026-09-26T10:00:00Z' },
  }
  open()
  await screen.findByText('This environment')
  expect(screen.getByText('Delivered in 42 ms')).toBeTruthy()
  expect(screen.getByText('webhook rejected the request (HTTP 500)')).toBeTruthy()
  expect(screen.getByText('Hosted page')).toBeTruthy()
})

it('sends a test email and shows the rejection', async () => {
  config = { environment_id: 'env1', webhook_url: 'https://mail.example/hook', has_token: true, invitation_url: '', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }
  status = { ...status, source: 'environment' }
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Send test email/ }))
  await userEvent.type(screen.getByLabelText('Recipient'), 'ops@example.com')
  await userEvent.click(screen.getByRole('button', { name: /^Send$/ }))
  expect((await screen.findByRole('status')).textContent).toContain('webhook rejected the request (HTTP 503)')
  expect(calls('POST')).toEqual([{ url: `/management/v1${delivery}/test`, body: { email: 'ops@example.com' } }])
})

it('fills the hosted invitation page', async () => {
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Configure webhook/ }))
  await userEvent.type(screen.getByLabelText('Webhook URL'), 'https://mail.example/hook')
  await userEvent.type(screen.getByLabelText('Webhook token'), 'secret')
  await userEvent.click(screen.getByRole('button', { name: 'Use hosted invite page' }))
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toEqual([{ url: `/management/v1${delivery}`, body: { webhook_url: 'https://mail.example/hook', webhook_token: 'secret', invitation_url: hosted } }]))
})

it('lets viewers read but not change or test delivery', async () => {
  role = 'viewer'
  open()
  await screen.findByText('Global fallback')
  expect(screen.queryByRole('button', { name: /Send test email/ })).toBeNull()
  expect(screen.queryByRole('button', { name: /Configure webhook/ })).toBeNull()
})
