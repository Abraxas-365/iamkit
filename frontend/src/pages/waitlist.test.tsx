// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
const entry = { environment_id: 'env1', name: '', locale: 'en', created_at: '2026-09-26T00:00:00Z', decided_at: null, decided_by: '', expires_at: null, completed_user_id: '' }
const ana = { ...entry, id: 'w1', email: 'ana@example.com', name: 'Ana', status: 'pending' }
const bob = { ...entry, id: 'w2', email: 'bob@example.com', status: 'pending' }
const cy = { ...entry, id: 'w3', email: 'cy@example.com', status: 'approved', decided_at: '2026-09-27T00:00:00Z' }
let role = 'owner'
let items: unknown[]
let calls: { method: string; path: string; body?: Record<string, unknown> }[]
let bulk: { approved: number; skipped: number; more: boolean }[]

beforeEach(() => {
  role = 'owner'
  items = [ana, bob, cy]
  calls = []
  bulk = [{ approved: 2, skipped: 0, more: false }]
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [path, query = ''] = url.replace('/management/v1', '').split('?')
    const method = init.method ?? 'GET'
    if (method !== 'GET') calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined })
    if (method === 'POST' && path === `${env}/waitlist/approve`) return Response.json(bulk.shift() ?? { approved: 0, skipped: 0, more: false })
    if (method === 'POST') return Response.json({ ...ana, status: 'approved' })
    if (method === 'DELETE') return new Response(null, { status: 204 })
    if (path === `${env}/waitlist`) {
      const params = new URLSearchParams(query)
      const shown = items.filter(i => (!params.get('status') || (i as { status: string }).status === params.get('status')) && (i as { email: string }).email.startsWith(params.get('email') ?? ''))
      return Response.json({ items: shown, page: { total: shown.length, limit: 50, offset: 0 } })
    }
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] : { items: [], page: { total: 0, limit: 50, offset: 0 } }
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/waitlist']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
const listCalls = () => fetchMock.mock.calls.map(([url]) => String(url)).filter(url => url.includes(`${env}/waitlist?`))

it('lists entries with their status and per-row actions', async () => {
  open()
  await screen.findByText('ana@example.com')
  const table = within(screen.getByRole('table'))
  expect(table.getByText('Approved')).toBeTruthy()
  expect(table.getAllByText('Pending')).toHaveLength(2)
  for (const h of ['Email', 'Name', 'Status', 'Created', 'Decided']) expect(table.getByRole('columnheader', { name: h })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Actions for ana@example.com' })).toBeTruthy()
})

it('filters by status and searches by email prefix', async () => {
  const u = userEvent.setup()
  open()
  await screen.findByText('ana@example.com')
  await u.selectOptions(screen.getByRole('combobox', { name: 'Filter by status' }), 'approved')
  await waitFor(() => expect(listCalls().some(url => url.includes('status=approved'))).toBe(true))
  await screen.findByText('cy@example.com')
  expect(screen.queryByText('ana@example.com')).toBeNull()
  await u.selectOptions(screen.getByRole('combobox', { name: 'Filter by status' }), '')
  await u.type(screen.getByRole('textbox', { name: 'Search by email' }), 'bo')
  await waitFor(() => expect(listCalls().some(url => url.includes('email=bo'))).toBe(true))
  await waitFor(() => expect(screen.queryByText('ana@example.com')).toBeNull())
  expect(screen.getByText('bob@example.com')).toBeTruthy()
})

it('approves one entry from its menu', async () => {
  const u = userEvent.setup()
  open()
  await screen.findByText('ana@example.com')
  await u.click(screen.getByRole('button', { name: 'Actions for ana@example.com' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Approve' }))
  await waitFor(() => expect(calls).toEqual([{ method: 'POST', path: `${env}/waitlist/w1/approve`, body: undefined }]))
})

it('rejects with the notify checkbox', async () => {
  const u = userEvent.setup()
  open()
  await screen.findByText('bob@example.com')
  await u.click(screen.getByRole('button', { name: 'Actions for bob@example.com' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Reject' }))
  await u.click(await screen.findByRole('checkbox', { name: /Notify them by email/ }))
  await u.click(screen.getByRole('button', { name: 'Reject' }))
  await waitFor(() => expect(calls).toEqual([{ method: 'POST', path: `${env}/waitlist/w2/reject`, body: { notify: true } }]))
})

it('silently rejects by default', async () => {
  const u = userEvent.setup()
  open()
  await screen.findByText('bob@example.com')
  await u.click(screen.getByRole('button', { name: 'Actions for bob@example.com' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Reject' }))
  await u.click(await screen.findByRole('button', { name: 'Reject' }))
  await waitFor(() => expect(calls[0].body).toEqual({ notify: false }))
})

it('deletes only after confirming', async () => {
  const u = userEvent.setup()
  open()
  await screen.findByText('cy@example.com')
  await u.click(screen.getByRole('button', { name: 'Actions for cy@example.com' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Delete' }))
  expect(calls).toEqual([])
  await u.click(await screen.findByRole('button', { name: 'Delete' }))
  await waitFor(() => expect(calls).toEqual([{ method: 'DELETE', path: `${env}/waitlist/w3`, body: undefined }]))
})

it('approves the selected pending entries in one call', async () => {
  const u = userEvent.setup()
  open()
  await screen.findByText('ana@example.com')
  await u.click(screen.getByRole('checkbox', { name: 'Select ana@example.com' }))
  await u.click(screen.getByRole('checkbox', { name: 'Select bob@example.com' }))
  await u.click(screen.getByRole('button', { name: 'Approve 2 selected' }))
  await waitFor(() => expect(calls).toEqual([{ method: 'POST', path: `${env}/waitlist/approve`, body: { ids: ['w1', 'w2'] } }]))
})

it('approves all pending, repeating while there is more', async () => {
  const u = userEvent.setup()
  bulk = [{ approved: 500, skipped: 1, more: true }, { approved: 3, skipped: 0, more: false }]
  open()
  await screen.findByText('ana@example.com')
  await u.click(screen.getByRole('button', { name: /Approve all pending/ }))
  const dialog = await screen.findByRole('dialog')
  await u.click(within(dialog).getByRole('button', { name: 'Approve all pending' }))
  await waitFor(() => expect(calls).toHaveLength(2))
  expect(calls.map(c => c.body)).toEqual([{ all_pending: true }, { all_pending: true }])
})

it('explains how to turn the waitlist on when empty', async () => {
  items = []
  open()
  expect(await screen.findByText('The waitlist is empty')).toBeTruthy()
  const link = within(screen.getByRole('main')).getByRole('link', { name: 'Sign-in methods' })
  expect(link.getAttribute('href')).toBe('/projects/project1/environments/env1/sign-in-policy')
})

it('hides every action from viewers', async () => {
  role = 'viewer'
  open()
  await screen.findByText('ana@example.com')
  expect(screen.queryByRole('button', { name: /Actions for/ })).toBeNull()
  expect(screen.queryByRole('button', { name: /Approve all pending/ })).toBeNull()
  expect(screen.queryByRole('checkbox')).toBeNull()
})
