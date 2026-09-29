// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { deliveryDetail, type LogoutDelivery } from './logout-deliveries'

const fetchMock = vi.fn()
const env = '/environments/env1'
let deliveries: LogoutDelivery[]
let client: Record<string, unknown>
let calls: { method: string; path: string; body?: Record<string, unknown> }[]
let queries: string[]
let role = 'owner'

const delivery = (id: string, status: LogoutDelivery['status'], extra: Partial<LogoutDelivery> = {}): LogoutDelivery => ({
  id, client_id: 'client1', application_name: 'Web', session_id: `s${id}`, user_id: `u${id}`, user_email: `user${id}@example.com`,
  status, attempts: 1, last_error: '', created_at: new Date().toISOString(), next_attempt_at: null, delivered_at: null, failed_at: null, ...extra,
})

beforeEach(() => {
  deliveries = [delivery('1', 'delivered'), delivery('2', 'failed', { attempts: 8, last_error: 'back-channel logout answered HTTP 500' })]
  client = { id: 'client1', application_id: 'app1', application_name: 'Web', resource_id: 'res1', resource_name: 'API', redirect_uris: ['https://app.example/cb'], public: false, hosted_login: false, active: true, access_token_format: 'jwt', backchannel_logout_uri: '', backchannel_logout_session_required: false, token_endpoint_auth_method: 'client_secret_basic' }
  calls = []
  queries = []
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [raw, query = ''] = url.replace('/management/v1', '').split('?')
    const path = raw
    const method = init.method ?? 'GET'
    if (method !== 'GET') calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined })
    const retry = path.match(/logout-deliveries\/(\w+)\/retry$/)
    if (retry && method === 'POST') {
      deliveries = deliveries.map(d => d.id === retry[1] ? { ...d, status: 'pending', attempts: 0, failed_at: null } : d)
      return new Response(null, { status: 202 })
    }
    if (path === `${env}/oauth-clients/client1` && method === 'PATCH') {
      client = { ...client, ...JSON.parse(String(init.body)) }
      return new Response(null, { status: 204 })
    }
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    if (path === `${env}/logout-deliveries`) {
      queries.push(query)
      const status = new URLSearchParams(query).get('status')
      return Response.json(page(deliveries.filter(d => !status || d.status === status)))
    }
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/oauth-clients/client1` ? client :
            path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('summarizes a delivery', () => {
  expect(deliveryDetail(delivery('1', 'delivered'))).toBe('1 attempt')
  expect(deliveryDetail(delivery('1', 'pending', { attempts: 0 }))).toBe('Queued')
  expect(deliveryDetail(delivery('1', 'failed', { attempts: 8, last_error: 'HTTP 500' }))).toBe('8 attempts · HTTP 500')
})

it('lists deliveries, filters by status and retries a failed one', async () => {
  const u = userEvent.setup()
  open('logout-deliveries')
  expect(await screen.findByText('user1@example.com')).toBeTruthy()
  const failed = screen.getByText('user2@example.com').closest('tr')!
  expect(within(failed).getByText('Failed')).toBeTruthy()
  expect(within(failed).getByText(/HTTP 500/)).toBeTruthy()
  expect(within(screen.getByText('user1@example.com').closest('tr')!).queryByRole('button', { name: /Actions for delivery/ })).toBeNull()

  await u.selectOptions(screen.getByRole('combobox', { name: 'Status' }), 'failed')
  await waitFor(() => expect(queries.at(-1)).toContain('status=failed'))
  await waitFor(() => expect(screen.queryByText('user1@example.com')).toBeNull())

  await u.click(within(screen.getByText('user2@example.com').closest('tr')!).getByRole('button', { name: 'Actions for delivery to Web' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Retry delivery' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'POST', path: `${env}/logout-deliveries/2/retry`, body: {} }))
})

it('hides retry from viewers', async () => {
  role = 'viewer'
  open('logout-deliveries')
  expect(await screen.findByText('user2@example.com')).toBeTruthy()
  expect(screen.queryByRole('button', { name: /Actions for delivery/ })).toBeNull()
})

it('configures back-channel logout on an OAuth client', async () => {
  const u = userEvent.setup()
  open('oauth-clients/client1')
  expect(await screen.findByText(/Off — the application is not told/)).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'Edit back-channel logout' }))
  await u.type(screen.getByLabelText('Logout URL'), 'https://app.example/bc')
  await u.click(screen.getByRole('switch', { name: 'Requires sid' }))
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'PATCH', path: `${env}/oauth-clients/client1`, body: { backchannel_logout_uri: 'https://app.example/bc', backchannel_logout_session_required: true } }))
  expect(await screen.findByText('https://app.example/bc')).toBeTruthy()
  expect(screen.getByRole('link', { name: /View delivery log/ }).getAttribute('href')).toBe('/projects/project1/environments/env1/logout-deliveries?client_id=client1')
})
