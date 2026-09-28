// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let role = 'owner'
const record = (name: string) => ({ type: 'TXT', name: `_iamkit-challenge.${name}`, value: 'iamkit-verification=tok' })
const pending = { id: 'd1', organization_id: 'org1', domain: 'acme.com', verified: false, verified_at: null, verified_by: null, verification_method: null, verification: record('acme.com'), created_at: '2026-01-01T00:00:00Z' }
const verified = { ...pending, id: 'd2', domain: 'acme.io', verified: true, verified_at: '2026-01-02T00:00:00Z', verified_by: 'operator1', verification_method: 'manual', verification: record('acme.io') }
const org = '/environments/env1/organizations/org1'

beforeEach(() => {
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method === 'POST' && path === `${org}/domains`) return Response.json({ ...pending, id: 'd3', domain: 'new.example', verification: record('new.example') }, { status: 201 })
    if (init.method === 'POST' && path.endsWith('/verify')) return Response.json({ error: { message: 'TXT record _iamkit-challenge.acme.com not found' } }, { status: 422 })
    if (init.method && init.method !== 'GET') return Response.json(verified)
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === org ? { id: 'org1', name: 'Acme' } :
            path === `${org}/domains` ? page([pending, verified]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/organizations/org1/domains']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('lists domains with their verification status', async () => {
  open()
  await screen.findByText('acme.com')
  expect(screen.getByText('Domains of Acme')).toBeTruthy()
  expect(screen.getByText('Pending')).toBeTruthy()
  expect(screen.getByText('Verified (manual)')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Verify acme.com' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Verify acme.io' })).toBeNull()
})

it('adds a domain and shows the TXT record to publish', async () => {
  open()
  await screen.findByText('acme.com')
  await userEvent.click(screen.getByRole('button', { name: /Add domain/ }))
  await userEvent.type(screen.getByLabelText('Domain'), 'new.example')
  await userEvent.click(screen.getByRole('button', { name: /save|create|submit|add/i, hidden: false }))
  await screen.findByText('Verify new.example')
  expect(screen.getByText('_iamkit-challenge.new.example')).toBeTruthy()
  expect(calls('POST')[0].body).toEqual({ domain: 'new.example' })
})

it('checks DNS on demand for a pending domain', async () => {
  open()
  await screen.findByText('acme.com')
  await userEvent.click(screen.getByRole('button', { name: 'Verify acme.com' }))
  await waitFor(() => expect(calls('POST').some(c => c.url.endsWith('/domains/d1/verify'))).toBe(true))
})

it('hides mutations from viewers', async () => {
  role = 'viewer'
  open()
  await screen.findByText('acme.com')
  expect(screen.queryByRole('button', { name: /Add domain/ })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Verify acme.com' })).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: 'Actions for acme.com' }))
  expect(await screen.findByRole('menuitem', { name: 'Show DNS record' })).toBeTruthy()
  expect(screen.queryByRole('menuitem', { name: 'Remove domain' })).toBeNull()
})
