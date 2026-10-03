// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
let user: Record<string, unknown>
let calls: { method: string; path: string }[]
let listed: string[]

beforeEach(() => {
  user = { id: 'u1', name: 'Alice', email: 'alice@example.com', active: true, state: 'initial', last_signed_in_at: null }
  calls = []
  listed = []
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [raw, search = ''] = url.replace('/management/v1', '').split('?')
    const path = raw
    const method = init.method ?? 'GET'
    if (method !== 'GET') calls.push({ method, path })
    if (path === `${env}/users/u1/deactivate`) { user = { ...user, active: false, state: 'suspended' }; return new Response(null, { status: 204 }) }
    if (path === `${env}/users/u1/reactivate`) { user = { ...user, active: true, state: 'active' }; return new Response(null, { status: 204 }) }
    if (method !== 'GET') return new Response(null, { status: 204 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    if (path === `${env}/users`) {
      const state = new URLSearchParams(search).get('state') ?? ''
      listed.push(state)
      return Response.json(page([user].filter(u => !state || u.state === state)))
    }
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role: 'owner' } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/users/u1` ? user :
            path === `${env}/users/u1/factors` ? { factors: [], recovery_codes_remaining: 0 } :
              path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('shows user states and filters the list by state', async () => {
  const u = userEvent.setup()
  open('users')
  expect(await screen.findByText('Never signed in')).toBeTruthy()
  await u.selectOptions(screen.getByLabelText('Filter by state'), 'locked')
  await waitFor(() => expect(listed.at(-1)).toBe('locked'))
  expect(await screen.findByText('No users yet')).toBeTruthy()
})

it('suspends and reactivates a user', async () => {
  const u = userEvent.setup()
  open('users/u1')
  expect(await screen.findByText('Never signed in')).toBeTruthy()
  expect(screen.getByText('Never')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: /Suspend/ }))
  await u.click(await screen.findByRole('button', { name: 'Suspend' }))
  await waitFor(() => expect(calls).toContainEqual({ method: 'POST', path: `${env}/users/u1/deactivate` }))
  expect(await screen.findByText('Suspended')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: /Reactivate/ }))
  await u.click(await screen.findByRole('button', { name: 'Reactivate' }))
  await waitFor(() => expect(calls).toContainEqual({ method: 'POST', path: `${env}/users/u1/reactivate` }))
  expect(await screen.findByText('Active')).toBeTruthy()
})

it('shows when a signed-up user accepted the terms, and nothing otherwise', async () => {
  open('users/u1')
  expect(await screen.findByText('Never signed in')).toBeTruthy()
  expect(screen.queryByText('Terms accepted')).toBeNull()
  cleanup()
  user = { ...user, terms_accepted_at: '2026-10-03T01:27:16Z' }
  open('users/u1')
  expect(await screen.findByText('Terms accepted')).toBeTruthy()
})
