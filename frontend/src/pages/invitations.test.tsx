// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let role = 'owner'
const base = { organization_id: 'org1', role_ids: ['r1'], group_ids: [], inviter: 'operator1', expires_at: '2026-10-03T00:00:00Z', accepted_at: null, revoked_at: null, created_at: '2026-09-26T00:00:00Z' }
const pending = { ...base, id: 'i1', email: 'bob@example.com', status: 'pending' }
const accepted = { ...base, id: 'i2', email: 'carol@example.com', status: 'accepted', accepted_at: '2026-09-27T00:00:00Z', accepted_user_id: 'u2' }
const org = '/environments/env1/organizations/org1'

beforeEach(() => {
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method === 'POST' && path === `${org}/invitations`) return Response.json({ ...pending, id: 'i3', email: 'dave@example.com', token: 'ik_inv_secret', delivery: 'skipped' }, { status: 201 })
    if (init.method === 'POST' && path.endsWith('/resend')) return Response.json({ ...pending, token: 'ik_inv_rotated', link: 'https://app.example/join?token=ik_inv_rotated', delivery: 'sent' })
    if (init.method === 'DELETE') return new Response(null, { status: 204 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === org ? { id: 'org1', name: 'Acme' } :
            path === `${org}/invitations` ? page([pending, accepted]) : page([])
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/organizations/org1/invitations']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('lists invitations with their status', async () => {
  open()
  await screen.findByText('bob@example.com')
  expect(screen.getByText('Invitations to Acme')).toBeTruthy()
  const table = within(screen.getByRole('table'))
  expect(table.getByText('Pending')).toBeTruthy()
  expect(table.getByText('Accepted')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Actions for bob@example.com' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Actions for carol@example.com' })).toBeNull()
})

it('invites and shows the token once', async () => {
  open()
  await screen.findByText('bob@example.com')
  await userEvent.click(screen.getByRole('button', { name: /Invite member/ }))
  await userEvent.type(screen.getByLabelText('Email'), 'dave@example.com')
  await userEvent.click(screen.getByRole('button', { name: 'Send invitation' }))
  await screen.findByText('Invitation for dave@example.com')
  expect(screen.getByText('ik_inv_secret')).toBeTruthy()
  expect(screen.getByText(/Email delivery is not configured/)).toBeTruthy()
  expect(calls('POST')[0].body).toEqual({ email: 'dave@example.com', role_ids: [], group_ids: [] })
})

it('offers only operator-managed groups to invite into', async () => {
  open()
  await screen.findByText('bob@example.com')
  await userEvent.click(screen.getByRole('button', { name: /Invite member/ }))
  const urls = () => fetchMock.mock.calls.map(([url]) => String(url)).filter(url => url.includes(`${org}/groups?`))
  await waitFor(() => expect(urls().length).toBeGreaterThan(0))
  expect(urls().every(url => url.includes('source=manual'))).toBe(true)
})

it('resends with a new link and filters by status', async () => {
  open()
  await screen.findByText('bob@example.com')
  await userEvent.click(screen.getByRole('button', { name: 'Actions for bob@example.com' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Resend invitation' }))
  await screen.findByText('https://app.example/join?token=ik_inv_rotated')
  await userEvent.selectOptions(screen.getByLabelText('Filter by status'), 'expired')
  await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/invitations?') && String(url).includes('status=expired'))).toBe(true))
})

it('hides mutations from viewers', async () => {
  role = 'viewer'
  open()
  await screen.findByText('bob@example.com')
  expect(screen.queryByRole('button', { name: /Invite member/ })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Actions for bob@example.com' })).toBeNull()
})
