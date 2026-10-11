// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
const now = new Date().toISOString()
let calls: { method: string; path: string; query: string; body?: Record<string, unknown> }[]
let role = 'owner'

const event = (seq: number, action: string) => ({
  seq, id: `e${seq}`, action, version: 1, occurred_at: now, created_at: now, organization_id: 'org1',
  actor: { type: 'user', id: 'u1', name: 'Alice' }, targets: [{ type: 'invoice', id: 'inv-1' }], metadata: { amount: 12 },
})
const actions = [{ id: 'a1', name: 'invoice.created', description: 'An invoice was issued', target_types: ['invoice'], schema: { metadata: { type: 'object' } }, version: 3, created_at: now, updated_at: now }]

beforeEach(() => {
  calls = []
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [path, query = ''] = url.replace('/management/v1', '').split('?')
    const method = init.method ?? 'GET'
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    if (method !== 'GET') calls.push({ method, path, query, body })
    else if (path.includes('audit-logs')) calls.push({ method, path, query })
    if (path === `${env}/audit-logs/events`) return Response.json(new URLSearchParams(query).get('before') === '5' ? { items: [event(4, 'invoice.paid')], next: 0 } : { items: [event(6, 'invoice.created'), event(5, 'invoice.voided')], next: 5 })
    if (path === `${env}/audit-logs/actions` && method === 'POST') return Response.json({ ...actions[0], id: 'a2', ...body }, { status: 201 })
    if (path === `${env}/audit-logs/actions`) return Response.json({ items: actions })
    if (path.startsWith(`${env}/audit-logs/actions/`) && method === 'PATCH') return Response.json(actions[0])
    if (path.startsWith(`${env}/audit-logs/actions/`) && method === 'DELETE') return new Response(null, { status: 204 })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/organizations` ? { items: [{ id: 'org1', name: 'Acme' }], page: { total: 1, limit: 100, offset: 0 } } :
            path.startsWith(env) ? { items: [], page: { total: 0, limit: 50, offset: 0 } } : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
const open = (path = 'audit-logs') => render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)

it('lists events, loads more with the cursor and opens the JSON detail', async () => {
  const u = userEvent.setup()
  open()
  expect(await screen.findByText('invoice.created')).toBeTruthy()
  expect(screen.getByText('invoice.voided')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'Load more' }))
  expect(await screen.findByText('invoice.paid')).toBeTruthy()
  expect(calls.at(-1)?.query).toContain('before=5')
  expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull()
  await u.click(screen.getByText('invoice.paid'))
  expect(within(await screen.findByLabelText('Event JSON')).getByText(/"amount": 12/)).toBeTruthy()
})

it('filters by organization, action and actor, and exports with the same filters', async () => {
  const u = userEvent.setup()
  open()
  await screen.findByText('invoice.created')
  await u.selectOptions(await screen.findByLabelText('Organization'), 'org1')
  await u.type(screen.getByLabelText('Action'), 'invoice.created')
  await u.type(screen.getByLabelText('Actor ID'), 'u1')
  await u.click(screen.getByRole('button', { name: 'Apply filters' }))
  await waitFor(() => { const q = new URLSearchParams(calls.at(-1)?.query); expect(q.get('organization_id')).toBe('org1'); expect(q.get('action')).toBe('invoice.created'); expect(q.get('actor_id')).toBe('u1') })
  const nd = screen.getByRole('link', { name: /Export NDJSON/ })
  const href = new URL(nd.getAttribute('href')!, 'https://x.test')
  expect(href.pathname).toBe(`/management/v1${env}/audit-logs/events/export`)
  expect(href.searchParams.get('format')).toBe('ndjson')
  expect(href.searchParams.get('actor_id')).toBe('u1')
  expect(new URL(screen.getByRole('link', { name: /Export CSV/ }).getAttribute('href')!, 'https://x.test').searchParams.get('format')).toBe('csv')
})

it('lists actions with their version and creates one with schemas', async () => {
  const u = userEvent.setup()
  open('audit-logs?tab=actions')
  const row = (await screen.findByText('invoice.created')).closest('tr')!
  expect(within(row).getByText('v3')).toBeTruthy()
  await u.click(screen.getAllByRole('button', { name: 'Add action' })[0])
  await u.type(screen.getByLabelText('Name'), 'invoice.paid')
  await u.type(screen.getByLabelText(/Target types/), 'invoice')
  await u.click(screen.getByLabelText(/Metadata schema/))
  await u.paste('{"type":"object"}')
  await u.click(screen.getByRole('button', { name: 'Create action' }))
  await waitFor(() => expect(calls.filter(c => c.method !== 'GET').at(-1)).toEqual({ method: 'POST', path: `${env}/audit-logs/actions`, query: '', body: { name: 'invoice.paid', description: '', target_types: ['invoice'], schema: { metadata: { type: 'object' } } } }))
})

it('rejects invalid schema JSON and deletes after confirmation', async () => {
  const u = userEvent.setup()
  open('audit-logs?tab=actions')
  await screen.findByText('invoice.created')
  await u.click(screen.getByRole('button', { name: 'Actions for invoice.created' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Edit' }))
  await u.click(screen.getByLabelText(/Actor schema/))
  await u.paste('{nope')
  await u.click(screen.getByRole('button', { name: 'Save' }))
  expect(await screen.findByText('Actor schema must be valid JSON')).toBeTruthy()
  expect(calls.some(c => c.method === 'PATCH')).toBe(false)
  await u.click(screen.getByRole('button', { name: 'Cancel' }))
  await u.click(screen.getByRole('button', { name: 'Actions for invoice.created' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Delete' }))
  await u.click(await screen.findByRole('button', { name: 'Delete' }))
  await waitFor(() => expect(calls.filter(c => c.method !== 'GET').at(-1)).toMatchObject({ method: 'DELETE', path: `${env}/audit-logs/actions/a1` }))
})

it('hides action writes from viewers', async () => {
  role = 'viewer'
  open('audit-logs?tab=actions')
  expect(await screen.findByText('invoice.created')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Add action' })).toBeNull()
})
