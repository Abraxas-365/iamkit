// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
let role = 'owner'
let linked = [{ id: 'app1', name: 'Notes', redirect_uris: [], active: true }]
let servers: unknown[] = []
const resource = { id: 'res1', name: 'Notes API', prefix: 'notes', audience: 'https://mcp.example/mcp', permissions: ['notes:read', 'notes:write'], owner_organization_id: null, require_grant: false }

beforeEach(() => {
  role = 'owner'
  linked = [{ id: 'app1', name: 'Notes', redirect_uris: [], active: true }]
  servers = []
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [raw, search] = url.replace('/management/v1', '').split('?')
    const params = new URLSearchParams(search)
    const method = init.method ?? 'GET'
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    if (method === 'POST' && raw === `${env}/protected-resources`) {
      servers = [{ id: 'pr1', resource_id: 'res1', uri: resource.audience, name: 'Notes MCP', default_scopes: ['notes:read'], idle_ttl_seconds: 604800, max_ttl_seconds: 2592000, active: true, created_at: '2026-01-01T00:00:00Z', allow_client_metadata: false }]
      return Response.json({ id: 'pr1' }, { status: 201 })
    }
    if (method !== 'GET') return new Response(null, { status: 204 })
    const data = raw === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      raw === '/projects' ? [{ id: 'project1', name: 'Notes' }] :
        raw === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          raw === `${env}/resources/res1` ? resource :
            raw === `${env}/applications` ? page(params.get('resource_id') === 'res1' ? linked : []) :
              raw === `${env}/protected-resource-policy` ? { max_idle_ttl_seconds: 30 * 86400, max_lifetime_ttl_seconds: 90 * 86400 } :
                raw === `${env}/protected-resources` ? page(servers) :
                  raw === `${env}/protected-resources/pr1/clients` ? page([]) :
                    raw === `${env}/oauth-client-presets` ? [] :
                      raw === `${env}/resource-grants` ? page([]) :
                        raw === `${env}/roles` ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })

function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/resources/res1']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function posts() {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST').map(([url, init]) => ({ url: String(url), body: JSON.parse(init.body) }))
}

it('protects a resource as an MCP server with its audience as URL', async () => {
  open()
  await userEvent.click(await screen.findByRole('button', { name: 'Protect as MCP server' }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByText('https://mcp.example/mcp')).toBeTruthy()
  // Only applications linked to the resource are offered.
  await waitFor(() => expect((within(dialog).getByLabelText('Application') as HTMLSelectElement).value).toBe('app1'))
  expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/applications?') && String(url).includes('resource_id=res1'))).toBe(true)
  const name = within(dialog).getByLabelText('Name')
  await userEvent.clear(name)
  await userEvent.type(name, 'Notes MCP')
  await userEvent.click(within(dialog).getByLabelText('notes:read'))
  await waitFor(() => expect(within(dialog).getByLabelText('Maximum lifetime (days)').getAttribute('max')).toBe('90'))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Protect' }))
  await waitFor(() => expect(posts()).toHaveLength(1))
  expect(posts()[0]).toMatchObject({ url: expect.stringContaining(`${env}/protected-resources`), body: { application_id: 'app1', resource_id: 'res1', name: 'Notes MCP', default_scopes: ['notes:read'], idle_ttl_seconds: 604800, max_ttl_seconds: 2592000 } })
  // The section then shows the new server.
  expect(await screen.findByText('Client settings')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Protect as MCP server' })).toBeNull()
})

it('asks to link an application first when none uses the resource', async () => {
  linked = []
  open()
  await userEvent.click(await screen.findByRole('button', { name: 'Protect as MCP server' }))
  const dialog = await screen.findByRole('dialog')
  expect(await within(dialog).findByText(/No application uses this resource yet/)).toBeTruthy()
  expect((within(dialog).getByRole('button', { name: 'Protect' }) as HTMLButtonElement).disabled).toBe(true)
})

it('hides the offer from read-only operators', async () => {
  role = 'viewer'
  open()
  await screen.findByText('https://mcp.example/mcp')
  await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/protected-resources?'))).toBe(true))
  expect(screen.queryByRole('button', { name: 'Protect as MCP server' })).toBeNull()
})
