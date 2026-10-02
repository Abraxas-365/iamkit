// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { answers, conditionLabel, type ActionCall, type ActionCondition, type ActionExecution, type ActionTarget } from './actions'

const fetchMock = vi.fn()
const env = '/environments/env1'
let targets: ActionTarget[]
let executions: ActionExecution[]
let callLog: ActionCall[]
let calls: { method: string; path: string; body?: Record<string, unknown> }[]
let role = 'owner'
const conditions: ActionCondition[] = [
  { name: 'function:pre_sign_in', description: 'Before a user session is created', deny: true, claims: false },
  { name: 'function:pre_access_token', description: 'Before an OAuth access token is issued', deny: true, claims: true },
  { name: 'request:user.create', description: 'Before the management API creates a user', deny: true, claims: false, patch: ['name', 'username'] },
]

const target = (id: string, extra: Partial<ActionTarget> = {}): ActionTarget => ({
  id, name: `Target ${id}`, url: `https://hooks.example/${id}`, kind: 'call', timeout_ms: 5000, interrupt_on_error: false,
  created_at: new Date().toISOString(), updated_at: new Date().toISOString(), ...extra,
})

beforeEach(() => {
  targets = [target('t1'), target('t2', { kind: 'async' })]
  executions = [{ condition: 'function:pre_sign_in', targets: ['t1'], updated_at: new Date().toISOString() }]
  callLog = [
    { id: 1, target_id: 't1', condition: 'function:pre_sign_in', outcome: 'denied', status: 200, duration_ms: 12, created_at: new Date().toISOString() },
    { id: 2, target_id: 't1', condition: 'function:pre_sign_in', outcome: 'failed', status: 500, duration_ms: 30, error: 'endpoint answered 500', created_at: new Date().toISOString() },
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
    if (path === `${env}/action-targets` && method === 'POST') return Response.json({ id: 't3', secret: 'whsec_c2VjcmV0' }, { status: 201 })
    if (path === `${env}/action-targets`) return Response.json({ items: targets })
    if (path === `${env}/action-conditions`) return Response.json({ items: conditions })
    if (path === `${env}/action-executions`) return Response.json({ items: executions })
    if (path.startsWith(`${env}/action-executions/`)) return method === 'DELETE' ? new Response(null, { status: 204 }) : Response.json({ condition: decodeURIComponent(path.split('/').pop()!), targets: body?.targets })
    if (path === `${env}/action-calls`) {
      const outcome = new URLSearchParams(query).get('outcome')
      return Response.json({ items: callLog.filter(c => !outcome || c.outcome === outcome) })
    }
    if (path === `${env}/action-targets/t1/test`) return Response.json({ outcome: 'denied', status: 200, duration_ms: 8, response: { deny: true, message: 'Blocked' } })
    if (path === `${env}/action-targets/t1/rotate-secret`) return Response.json({ id: 't1', secret: 'whsec_bmV3' })
    if (path === `${env}/action-targets/t1` && method === 'PATCH') { targets[0] = { ...targets[0], ...body }; return Response.json(targets[0]) }
    if (path === `${env}/action-targets/t1`) return Response.json(targets[0])
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path.startsWith(env) ? { items: [] } : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('labels conditions and what they accept', () => {
  expect(conditionLabel('function:pre_sign_in')).toBe('Pre sign in')
  expect(conditionLabel('request:user.create')).toBe('Request: User create')
  expect(answers(conditions[1])).toBe('deny · add claims')
  expect(answers(conditions[2])).toBe('deny · patch name, username')
  expect(answers({ name: 'x', description: '', deny: false, claims: false })).toBe('observe only')
})

it('lists targets, creates one and binds conditions in order', async () => {
  const u = userEvent.setup()
  open('actions')
  expect(await screen.findByRole('link', { name: 'Target t1' })).toBeTruthy()
  const signIn = (await screen.findByText('Pre sign in')).closest('tr')!
  expect(within(signIn).getByText('Target t1')).toBeTruthy()
  expect(await screen.findByText(/endpoint answered 500/)).toBeTruthy()

  await u.click(screen.getByRole('button', { name: 'Add target' }))
  await u.type(screen.getByLabelText('Name'), 'Risk')
  await u.type(screen.getByLabelText('Endpoint URL'), 'https://risk.example/hook')
  await u.click(screen.getByRole('button', { name: 'Add' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'POST', path: `${env}/action-targets`, body: { name: 'Risk', url: 'https://risk.example/hook', kind: 'call', timeout_ms: 0, interrupt_on_error: false } }))
  expect(await screen.findByText('Signing secret')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'I have saved the secret' }))

  await u.click(screen.getByRole('button', { name: 'Edit function:pre_access_token' }))
  const dialog = await screen.findByRole('dialog')
  await u.click(within(dialog).getByLabelText(/Target t1/))
  await u.click(within(dialog).getByLabelText(/Target t2/))
  await u.click(within(dialog).getByRole('button', { name: 'Move Target t2 up' }))
  await u.click(within(dialog).getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'PUT', path: `${env}/action-executions/function%3Apre_access_token`, body: { targets: ['t2', 't1'] } }))

  // Clearing every target removes the execution.
  await u.click(screen.getByRole('button', { name: 'Edit function:pre_sign_in' }))
  await u.click(within(await screen.findByRole('dialog')).getByLabelText(/Target t1/))
  await u.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'DELETE', path: `${env}/action-executions/function%3Apre_sign_in`, body: undefined }))
})

it('tests, edits and rotates a target', async () => {
  const u = userEvent.setup()
  open('actions/t1')
  expect(await screen.findByText('https://hooks.example/t1')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: /Test/ }))
  await u.click(await screen.findByRole('button', { name: 'Send' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'POST', path: `${env}/action-targets/t1/test`, body: { condition: 'function:pre_sign_in' } }))
  expect(await screen.findByText(/"message": "Blocked"/)).toBeTruthy()

  await u.click(screen.getByRole('button', { name: /Edit/ }))
  await u.click(await screen.findByRole('switch', { name: 'Interrupt on error' }))
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls.at(-1)?.body).toMatchObject({ interrupt_on_error: true, timeout_ms: 5000 }))
  expect(await screen.findByText('Interrupt the flow')).toBeTruthy()

  await u.click(screen.getByRole('button', { name: /Rotate secret/ }))
  await u.click(await screen.findByRole('button', { name: 'Rotate' }))
  expect(await screen.findByText('Signing secret')).toBeTruthy()
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  open('actions')
  expect(await screen.findByRole('link', { name: 'Target t1' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Add target' })).toBeNull()
  expect(screen.queryByRole('button', { name: /Edit function/ })).toBeNull()
})
