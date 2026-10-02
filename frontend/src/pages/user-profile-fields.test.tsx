// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { initials } from '../components/library/avatar'

const fetchMock = vi.fn()
const env = '/environments/env1'
let user: Record<string, unknown>
let patches: Record<string, unknown>[]

beforeEach(() => {
  user = { id: 'u1', name: 'Alice Doe', email: 'alice@example.com', active: true, state: 'active', avatar_url: 'https://cdn.example/alice.png' }
  patches = []
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    const method = init.method ?? 'GET'
    if (method === 'PATCH' && path === `${env}/users/u1`) {
      const body = JSON.parse(String(init.body))
      patches.push(body)
      user = { ...user, ...body }
      return new Response(null, { status: 204 })
    }
    if (method !== 'GET') return new Response(null, { status: 204 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role: 'owner' } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/users` ? page([user, { id: 'u2', name: 'Bob', email: 'bob@example.com', active: true, state: 'active', avatar_url: '' }]) :
            path === `${env}/users/u1` ? user :
              path === `${env}/users/u1/factors` ? { factors: [], recovery_codes_remaining: 0 } :
                path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  return render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('derives initials', () => {
  expect(initials('Alice Doe')).toBe('AD')
  expect(initials('bob@example.com')).toBe('BO')
  expect(initials('')).toBe('?')
})

it('shows avatars in the user list, with initials when there is none', async () => {
  const { container } = open('users')
  expect(await screen.findByText('Bob')).toBeTruthy()
  expect(container.querySelector('img[src="https://cdn.example/alice.png"]')?.getAttribute('referrerpolicy')).toBe('no-referrer')
  expect(screen.getByText('BO')).toBeTruthy()
})

it('edits and clears the avatar URL on the user page', async () => {
  const u = userEvent.setup()
  const { container } = open('users/u1')
  expect(await screen.findByRole('heading', { name: 'Alice Doe' })).toBeTruthy()
  expect(container.querySelector('img[src="https://cdn.example/alice.png"]')).toBeTruthy()
  await u.click(screen.getAllByRole('button', { name: /^Edit$/ })[0])
  const field = await screen.findByLabelText(/Avatar URL/)
  await u.clear(field)
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patches.at(-1)?.avatar_url).toBe(''))
  await waitFor(() => expect(container.querySelector('img[src="https://cdn.example/alice.png"]')).toBeNull())
  expect(screen.getAllByText('AD').length).toBeGreaterThan(0)
})

it('shows and edits the username', async () => {
  user = { ...user, username: 'alice' }
  const u = userEvent.setup()
  open('users/u1')
  expect(await screen.findByRole('heading', { name: 'Alice Doe' })).toBeTruthy()
  expect(screen.getByText('alice')).toBeTruthy()
  await u.click(screen.getAllByRole('button', { name: /^Edit$/ })[0])
  const field = await screen.findByLabelText(/Username/)
  await u.clear(field)
  await u.type(field, 'alice.doe')
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patches.at(-1)?.username).toBe('alice.doe'))
})

it('lists usernames next to the email', async () => {
  user = { ...user, username: 'alice' }
  open('users')
  expect(await screen.findByText('alice@example.com · @alice')).toBeTruthy()
})
