// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { properties } from './user-schema'
import { parseValue } from '../components/library/metadata-editor'

const fetchMock = vi.fn()
const env = '/environments/env1'
let schema: Record<string, unknown> | null
let user: Record<string, unknown>
let calls: { method: string; path: string; body?: unknown }[]

beforeEach(() => {
  schema = null
  user = { id: 'u1', name: 'Alice', email: 'alice@example.com', active: true, state: 'active', metadata: { tier: 'gold' }, profile: { department: 'eng', legacy: 1 } }
  calls = []
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    const method = init.method ?? 'GET'
    if (method !== 'GET') calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined })
    if (path === `${env}/user-schema`) {
      if (method === 'PUT') { schema = { schema: JSON.parse(String(init.body)).schema, version: 1, non_conforming: 2 }; return Response.json(schema) }
      if (method === 'DELETE') { schema = null; return new Response(null, { status: 204 }) }
      return schema ? Response.json(schema) : Response.json({ error: { code: 'NOT_FOUND', message: 'no user schema is saved' } }, { status: 404 })
    }
    if (method !== 'GET') return new Response(null, { status: 204 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
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

it('reads schema properties and metadata values', () => {
  expect(properties({ type: 'object', required: ['a'], properties: { b: { type: ['string', 'null'], 'x-iamkit-self': 'write' }, a: { type: 'string', 'x-iamkit-claim': 'dept' } } })).toEqual([
    { name: 'a', type: 'string', self: '', claim: 'dept', required: true },
    { name: 'b', type: 'string | null', self: 'write', claim: '', required: false },
  ])
  expect(parseValue('{"x":1}')).toEqual({ x: 1 })
  expect(parseValue('12')).toBe(12)
  expect(parseValue('eu')).toBe('eu')
})

it('creates a user schema and reports non-conforming profiles', async () => {
  const u = userEvent.setup()
  open('user-schema')
  expect(await screen.findByText('No user schema')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'Create schema' }))
  const text = await screen.findByLabelText('Schema')
  fireEvent.change(text, { target: { value: '[1]' } })
  await u.click(screen.getByRole('button', { name: 'Save' }))
  expect(await screen.findByText('Schema must be a JSON object')).toBeTruthy()
  fireEvent.change(text, { target: { value: '{"type":"object","properties":{"department":{"type":"string","x-iamkit-claim":"department","x-iamkit-self":"read"}}}' } })
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls).toEqual([{ method: 'PUT', path: `${env}/user-schema`, body: { schema: { type: 'object', properties: { department: { type: 'string', 'x-iamkit-claim': 'department', 'x-iamkit-self': 'read' } } } } }]))
  const row = (await screen.findAllByText('department', { selector: 'td' }))[0].closest('tr')!
  expect(within(row).getByText('Read')).toBeTruthy()
})

it('edits user metadata per key and patches the profile with removals', async () => {
  const u = userEvent.setup()
  open('users/u1')
  expect(await screen.findByText('gold')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'Add key' }))
  await u.type(await screen.findByLabelText('Key'), 'plan.seats')
  await u.type(screen.getByLabelText('Value'), '12')
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await u.click(await screen.findByRole('button', { name: 'Delete tier' }))
  await u.click(await screen.findByRole('button', { name: 'Delete' }))
  await waitFor(() => expect(calls).toEqual([
    { method: 'PUT', path: `${env}/users/u1/metadata/plan.seats`, body: 12 },
    { method: 'DELETE', path: `${env}/users/u1/metadata/tier`, body: undefined },
  ]))

  calls = []
  const section = screen.getByText('Profile attributes').closest('section') ?? document.body
  await u.click(within(section as HTMLElement).getByRole('button', { name: 'Edit' }))
  fireEvent.change(await screen.findByLabelText('Profile'), { target: { value: '{"department":"sales"}' } })
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls).toEqual([{ method: 'PATCH', path: `${env}/users/u1/profile`, body: { department: 'sales', legacy: null } }]))
})

it('marks a phone number verified only when the switch changes', async () => {
  user = { ...user, phone: '+15557654321', phone_verified: false }
  const u = userEvent.setup()
  open('users/u1')
  expect(await screen.findByText('+15557654321')).toBeTruthy()
  const section = screen.getByText('Profile', { selector: 'h2, h3' }).closest('section') ?? document.body
  await u.click(within(section as HTMLElement).getByRole('button', { name: 'Edit' }))
  await u.click(await screen.findByRole('switch', { name: /Phone number verified/ }))
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls[0]?.body).toMatchObject({ phone: '+15557654321', phone_verified: true }))

  calls = []
  await u.click(within(section as HTMLElement).getByRole('button', { name: 'Edit' }))
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls).toHaveLength(1))
  expect(calls[0]?.body).not.toHaveProperty('phone_verified')
})
