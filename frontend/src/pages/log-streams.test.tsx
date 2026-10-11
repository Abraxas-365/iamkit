// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { streamState, type LogStream } from '@/components/library/log-streams-view'

const fetchMock = vi.fn()
const env = '/environments/env1'
const now = new Date().toISOString()
let streams: LogStream[]
let calls: { method: string; path: string; body?: Record<string, unknown> }[]
let role = 'owner'

const stream = (id: string, extra: Partial<LogStream> = {}): LogStream => ({
  id, name: `Stream ${id}`, destination: 'datadog', config: { site: 'datadoghq.eu' }, sources: ['events', 'audit_logs'], secret_set: true,
  active: true, pending: 0, created_at: now, updated_at: now, ...extra,
})

beforeEach(() => {
  streams = [stream('s1'), stream('s2', { destination: 'https', config: { url: 'https://logs.example/in' }, failing_since: now, pending: 4 }), stream('s3', { active: false, disabled_reason: 'failing' })]
  calls = []
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    const method = init.method ?? 'GET'
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    if (method !== 'GET') calls.push({ method, path, body })
    if (path === `${env}/log-streams` && method === 'POST') return Response.json(body.destination === 'https' ? { id: 's9', secret: 'whsec_c2VjcmV0' } : { id: 's9' }, { status: 201 })
    if (path === `${env}/log-streams`) return Response.json({ items: streams })
    if (path === `${env}/log-streams/s1/test`) return Response.json({ delivered: false, status: 503, error: 'endpoint answered 503' })
    if (path === `${env}/log-streams/s1/deliveries`) return Response.json({ items: [{ id: 7, source: 'audit_logs', seq: 3, status: 'failed', attempts: 5, last_error: 'boom', queued_at: now }], page: { total: 1, limit: 20, offset: 0 } })
    if (path.endsWith('/retry')) return new Response(null, { status: 202 })
    if (path === `${env}/log-streams/s3/enable`) return new Response(null, { status: 204 })
    if (method === 'PATCH' || method === 'DELETE') return new Response(null, { status: 204 })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path.startsWith(env) ? { items: [], page: { total: 0, limit: 50, offset: 0 } } : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
const open = () => render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/log-streams']}><AuthProvider><App /></AuthProvider></MemoryRouter>)

it('names stream states', () => {
  expect(streamState(stream('a'))[0]).toBe('Active')
  expect(streamState(stream('a', { failing_since: now }))[0]).toBe('Failing')
  expect(streamState(stream('a', { active: false, disabled_reason: 'failing' }))[0]).toBe('Disabled (failing)')
})

it('lists streams with their status', async () => {
  open()
  expect(await screen.findByText('Stream s1')).toBeTruthy()
  expect(within(screen.getByText('Stream s2').closest('tr')!).getByText('Failing')).toBeTruthy()
  expect(within(screen.getByText('Stream s3').closest('tr')!).getByText('Disabled (failing)')).toBeTruthy()
  expect(screen.getAllByText('datadoghq.eu').length).toBe(2)
})

it('creates a Datadog stream with a site from the allowed list and a write-only key', async () => {
  const u = userEvent.setup()
  open()
  await u.click(await screen.findByRole('button', { name: 'Add log stream' }))
  await u.type(screen.getByLabelText('Name'), 'SIEM')
  const site = screen.getByLabelText('Datadog site') as HTMLSelectElement
  expect([...site.options].map(o => o.value)).toContain('us5.datadoghq.com')
  await u.selectOptions(site, 'datadoghq.eu')
  const key = screen.getByLabelText('API key') as HTMLInputElement
  expect(key.type).toBe('password')
  await u.type(key, 'dd-secret')
  await u.click(screen.getByLabelText('App audit logs'))
  await u.click(screen.getByRole('button', { name: 'Create log stream' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'POST', path: `${env}/log-streams`, body: { name: 'SIEM', destination: 'datadog', config: { site: 'datadoghq.eu' }, sources: ['events'], secret: 'dd-secret' } }))
})

it('creates Splunk and S3 streams with their own fields', async () => {
  const u = userEvent.setup()
  open()
  await u.click(await screen.findByRole('button', { name: 'Add log stream' }))
  await u.type(screen.getByLabelText('Name'), 'Splunk')
  await u.selectOptions(screen.getByLabelText('Destination'), 'splunk')
  await u.type(screen.getByLabelText('HEC endpoint URL'), 'https://splunk.example:8088')
  await u.type(screen.getByLabelText('HEC token'), 'hec-token')
  await u.click(screen.getByRole('button', { name: 'Create log stream' }))
  await waitFor(() => expect(calls.at(-1)?.body).toEqual({ name: 'Splunk', destination: 'splunk', config: { url: 'https://splunk.example:8088' }, sources: ['events', 'audit_logs'], secret: 'hec-token' }))
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Create log stream' })).toBeNull())
  await u.click(screen.getByRole('button', { name: 'Add log stream' }))
  await u.type(screen.getByLabelText('Name'), 'Archive')
  await u.selectOptions(screen.getByLabelText('Destination'), 's3')
  await u.type(screen.getByLabelText('Bucket'), 'logs')
  await u.type(screen.getByLabelText('Region'), 'eu-west-1')
  await u.type(screen.getByLabelText('Access key ID'), 'AKIA1')
  await u.type(screen.getByLabelText('Secret access key'), 's3-secret')
  await u.click(screen.getByRole('button', { name: 'Create log stream' }))
  await waitFor(() => expect(calls.at(-1)?.body).toEqual({ name: 'Archive', destination: 's3', config: { bucket: 'logs', region: 'eu-west-1', access_key_id: 'AKIA1' }, sources: ['events', 'audit_logs'], secret: 's3-secret' }))
})

it('creates an https stream and shows the signing secret once', async () => {
  const u = userEvent.setup()
  open()
  await u.click(await screen.findByRole('button', { name: 'Add log stream' }))
  await u.type(screen.getByLabelText('Name'), 'Hook')
  await u.selectOptions(screen.getByLabelText('Destination'), 'https')
  expect(screen.queryByLabelText('API key')).toBeNull()
  await u.type(screen.getByLabelText('Endpoint URL'), 'https://logs.example/iamkit')
  await u.click(screen.getByRole('button', { name: 'Create log stream' }))
  await waitFor(() => expect(calls.at(-1)?.body).toEqual({ name: 'Hook', destination: 'https', config: { url: 'https://logs.example/iamkit' }, sources: ['events', 'audit_logs'] }))
  expect(await screen.findByText('whsec_c2VjcmV0')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'I have copied the secret' }))
  expect(screen.queryByText('whsec_c2VjcmV0')).toBeNull()
})

it('keeps the stored secret when editing leaves the field empty', async () => {
  const u = userEvent.setup()
  open()
  await screen.findByText('Stream s1')
  await u.click(screen.getByRole('button', { name: 'Actions for Stream s1' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Edit' }))
  const key = screen.getByLabelText('API key') as HTMLInputElement
  expect(key.value).toBe('')
  expect(key.required).toBe(false)
  await u.clear(screen.getByLabelText('Name'))
  await u.type(screen.getByLabelText('Name'), 'Renamed')
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'PATCH', path: `${env}/log-streams/s1`, body: { name: 'Renamed', config: { site: 'datadoghq.eu' }, sources: ['events', 'audit_logs'] } }))
  expect(calls.at(-1)?.body).not.toHaveProperty('secret')
})

it('tests a stream, lists and retries its deliveries and enables a disabled one', async () => {
  const u = userEvent.setup()
  open()
  await screen.findByText('Stream s1')
  await u.click(screen.getByRole('button', { name: 'Actions for Stream s1' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Send test record' }))
  await waitFor(() => expect(calls.at(-1)?.path).toBe(`${env}/log-streams/s1/test`))
  await u.click(screen.getByRole('button', { name: 'Actions for Stream s1' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Deliveries' }))
  await u.click(await screen.findByRole('button', { name: 'Retry delivery 7' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'POST', path: `${env}/log-streams/s1/deliveries/7/retry`, body: {} }))
  await u.keyboard('{Escape}')
  await u.click(screen.getByRole('button', { name: 'Actions for Stream s3' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Enable' }))
  await waitFor(() => expect(calls.at(-1)?.path).toBe(`${env}/log-streams/s3/enable`))
})

it('hides writes from viewers', async () => {
  role = 'viewer'
  open()
  expect(await screen.findByText('Stream s1')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Add log stream' })).toBeNull()
})
