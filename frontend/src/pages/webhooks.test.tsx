// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { subscriptionState, type Subscription, type WebhookDelivery } from './webhooks'

const fetchMock = vi.fn()
const env = '/environments/env1'
let subs: Subscription[]
let deliveries: WebhookDelivery[]
let calls: { method: string; path: string; body?: Record<string, unknown> }[]
let role = 'owner'

const sub = (id: string, extra: Partial<Subscription> = {}): Subscription => ({
  id, name: `Hook ${id}`, url: `https://hooks.example/${id}`, types: ['user.*'], active: true, pending: 0,
  created_at: new Date().toISOString(), updated_at: new Date().toISOString(), ...extra,
})

beforeEach(() => {
  subs = [sub('s1'), sub('s2', { failing_since: new Date().toISOString(), pending: 3 })]
  deliveries = [
    { id: 1, event_id: 10, event_type: 'user.created', status: 'delivered', attempts: 1, response_status: 204, queued_at: new Date().toISOString() },
    { id: 2, event_id: 11, event_type: 'user.updated', status: 'failed', attempts: 9, response_status: 500, last_error: 'endpoint answered 500', queued_at: new Date().toISOString() },
  ]
  calls = []
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [path, query = ''] = url.replace('/management/v1', '').split('?')
    const method = init.method ?? 'GET'
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    if (method !== 'GET') calls.push({ method, path, body })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    if (path === `${env}/webhooks` && method === 'POST') return Response.json({ id: 's3', secret: 'whsec_c2VjcmV0' }, { status: 201 })
    if (path === `${env}/webhooks`) return Response.json({ items: subs })
    if (path === `${env}/webhooks/s2/deliveries`) {
      const status = new URLSearchParams(query).get('status')
      return Response.json(page(deliveries.filter(d => !status || d.status === status)))
    }
    if (path === `${env}/webhooks/s2/test`) return Response.json({ delivered: false, status: 503, error: 'endpoint answered 503' })
    if (path === `${env}/webhooks/s2/rotate-secret`) return Response.json({ id: 's2', secret: 'whsec_bmV3' })
    if (path === `${env}/webhooks/s2/replay`) return Response.json({ queued: 4 }, { status: 202 })
    if (path.endsWith('/retry')) return new Response(null, { status: 202 })
    if (path === `${env}/webhooks/s2` && method === 'PATCH') { subs[1] = { ...subs[1], ...body }; return Response.json(subs[1]) }
    if (path === `${env}/webhooks/s2`) return Response.json(subs[1])
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('names subscription states', () => {
  expect(subscriptionState(sub('a'))[0]).toBe('Active')
  expect(subscriptionState(sub('a', { failing_since: '2026-01-01T00:00:00Z' }))[0]).toBe('Failing')
  expect(subscriptionState(sub('a', { active: false, disabled_reason: 'failing' }))[0]).toBe('Disabled (failing)')
})

it('lists webhooks and creates one, showing its secret once', async () => {
  const u = userEvent.setup()
  open('webhooks')
  expect(await screen.findByText('Hook s1')).toBeTruthy()
  expect(within(screen.getByText('Hook s2').closest('tr')!).getByText('Failing')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'Add webhook' }))
  await u.type(screen.getByLabelText('Name'), 'CRM')
  await u.type(screen.getByLabelText('Endpoint URL'), 'https://crm.example/hook')
  await u.type(screen.getByLabelText(/Events/), 'user.created, membership.*')
  await u.click(screen.getByRole('button', { name: 'Add' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'POST', path: `${env}/webhooks`, body: { name: 'CRM', url: 'https://crm.example/hook', types: ['user.created', 'membership.*'] } }))
  expect(await screen.findByText('Signing secret')).toBeTruthy()
})

it('tests, rotates, replays and retries on the detail page', async () => {
  const u = userEvent.setup()
  open('webhooks/s2')
  expect(await screen.findByText('endpoint answered 500', { exact: false })).toBeTruthy()
  await u.click(screen.getByRole('button', { name: /Send test event/ }))
  await waitFor(() => expect(calls.at(-1)?.path).toBe(`${env}/webhooks/s2/test`))

  await u.click(screen.getByRole('button', { name: /Rotate secret/ }))
  await u.click(await screen.findByRole('button', { name: 'Rotate' }))
  expect(await screen.findByText('Signing secret')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'I have saved the secret' }))

  await u.click(screen.getByRole('button', { name: /Replay events/ }))
  await u.type(screen.getByLabelText('From event id'), '10')
  await u.click(screen.getByRole('button', { name: 'Replay' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'POST', path: `${env}/webhooks/s2/replay`, body: { from: 10 } }))

  await u.click(screen.getByRole('button', { name: 'Actions for delivery 2' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Retry delivery' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'POST', path: `${env}/webhooks/s2/deliveries/2/retry`, body: {} }))

  await u.click(screen.getByRole('button', { name: /Disable/ }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'PATCH', path: `${env}/webhooks/s2`, body: { active: false } }))
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  open('webhooks/s2')
  expect(await screen.findByText('user.updated')).toBeTruthy()
  expect(screen.queryByRole('button', { name: /Send test event/ })).toBeNull()
  expect(screen.queryByRole('button', { name: /Actions for delivery/ })).toBeNull()
})
