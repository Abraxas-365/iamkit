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
const resource = { id: 'res1', name: 'Invoices', prefix: 'invoices', audience: 'https://invoices.example', permissions: ['invoices:read'], owner_organization_id: 'o1', require_grant: true }
const grants = [
  { id: 'g1', resource_id: 'res1', resource_name: 'Invoices', organization_id: 'o2', organization_name: 'Beta', role_ids: null, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' },
  { id: 'g2', resource_id: 'res1', resource_name: 'Invoices', organization_id: 'o3', organization_name: 'Gamma', role_ids: ['r2'], created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z' },
]

beforeEach(() => {
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    const method = init.method ?? 'GET'
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    if (method === 'PUT' && path === `${env}/resource-grants`) return Response.json(grants[0])
    if (method !== 'GET') return new Response(null, { status: 204 })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/resources/res1` ? resource :
            path === `${env}/organizations/o1` ? { id: 'o1', name: 'Acme', active: true } :
              path === `${env}/organizations/o2` ? { id: 'o2', name: 'Beta', active: true } :
                path === `${env}/organizations` ? page([{ id: 'o1', name: 'Acme' }, { id: 'o4', name: 'Delta' }]) :
                  path === `${env}/roles` ? page([
                    { id: 'r2', name: 'Reader', resource_id: 'res1' },
                    { id: 'r3', name: 'Writer', resource_id: 'res1' },
                    { id: 'r9', name: 'Other', resource_id: 'res9' },
                  ]) :
                    path === `${env}/resource-grants` ? page(url.includes('organization_id=o2') ? [grants[0]] : grants) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })

function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('shows ownership and the organizations a resource is granted to', async () => {
  open('/resources/res1')
  await screen.findByText('Gamma')
  expect(screen.getByRole('link', { name: 'Acme' })).toBeTruthy()
  expect(screen.getByText(/only the owner and granted organizations/)).toBeTruthy()
  expect(screen.getByText('All roles')).toBeTruthy()
  expect(screen.getByText('Reader')).toBeTruthy()
  expect(fetchMock.mock.calls.some(([url]) => String(url).includes('resource-grants?') && String(url).includes('resource_id=res1'))).toBe(true)
})

it('grants the resource with a chosen subset of its roles', async () => {
  open('/resources/res1')
  await screen.findByText('Gamma')
  await userEvent.click(screen.getByRole('button', { name: /Grant to organization/ }))
  const dialog = await screen.findByRole('dialog')
  await userEvent.click(within(dialog).getByPlaceholderText('Search organization…'))
  await userEvent.click(await screen.findByText('Delta'))
  await userEvent.click(within(dialog).getByRole('switch'))
  // Only roles of this resource are offered.
  expect(within(dialog).queryByText('Other')).toBeNull()
  await userEvent.click(within(dialog).getByLabelText('Writer'))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Grant' }))
  await waitFor(() => expect(calls('PUT')).toHaveLength(1))
  expect(calls('PUT')[0].body).toEqual({ resource_id: 'res1', organization_id: 'o4', role_ids: ['r3'] })
})

it('sets the owner organization and grant requirement', async () => {
  open('/resources/res1')
  await screen.findByText('Gamma')
  await userEvent.click(screen.getByRole('button', { name: /Edit access/ }))
  const dialog = await screen.findByRole('dialog')
  await userEvent.click(within(dialog).getByRole('button', { name: 'Clear owner' }))
  await userEvent.click(within(dialog).getByRole('switch'))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toHaveLength(1))
  expect(calls('PUT')[0]).toMatchObject({ url: expect.stringContaining(`${env}/resources/res1/access`), body: { owner_organization_id: null, require_grant: false } })
})

it('revokes a grant', async () => {
  open('/resources/res1')
  await screen.findByText('Gamma')
  await userEvent.click(screen.getByRole('button', { name: 'Actions for Gamma' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: /Revoke grant/ }))
  await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Revoke grant' }))
  await waitFor(() => expect(calls('DELETE')).toHaveLength(1))
  expect(calls('DELETE')[0].url).toContain(`${env}/resource-grants/g2`)
})

it('hides write actions from viewers', async () => {
  role = 'viewer'
  open('/resources/res1')
  await screen.findByText('Gamma')
  expect(screen.queryByRole('button', { name: /Edit access/ })).toBeNull()
  expect(screen.queryByRole('button', { name: /Grant to organization/ })).toBeNull()
})

it('lists the resources granted to an organization', async () => {
  open('/organizations/o2/resources')
  await screen.findByText('Resources granted to Beta')
  expect(await screen.findByRole('link', { name: 'Invoices' })).toBeTruthy()
  expect(screen.getByText('All roles')).toBeTruthy()
  expect(screen.queryByText('Gamma')).toBeNull()
})
