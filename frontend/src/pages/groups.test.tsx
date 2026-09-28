// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let role = 'owner'
const manual = { id: 'g1', name: 'Finance', description: 'Money people', connection_id: null, member_count: 1, created_at: '', updated_at: '' }
const directory = { id: 'g2', name: 'Engineering', description: '', connection_id: 'conn1', external_id: 'grp-eng', member_count: 2, created_at: '', updated_at: '' }
const org = '/environments/env1/organizations/org1'

beforeEach(() => {
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    if (init.method && init.method !== 'GET') return new Response(null, { status: 204 })
    const path = url.replace('/management/v1', '').split('?')[0]
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === org ? { id: 'org1', name: 'Acme' } :
            path === `${org}/groups` ? page([manual, directory]) :
              path === `${org}/groups/g1` ? manual :
                path === `${org}/groups/g2` ? directory :
                  path.startsWith(`${org}/groups/`) && path.endsWith('/members') ? page([{ user_id: 'u1', user_name: 'Jane', user_email: 'jane@example.com', active: true, added_at: '' }]) :
                    path === '/environments/env1/group-role-assignments' ? page([{ group_id: 'g1', group_name: 'Finance', organization_id: 'org1', resource_id: 'r1', resource_name: 'Billing API', role_id: 'role1', role_name: 'reader' }]) :
                      path === `${org}/members` ? page([{ user_id: 'u1', user_name: 'Jane', user_email: 'jane@example.com', active: true, manager_id: null, manager_name: null }]) :
                        path === '/environments/env1/effective-roles' ? { items: [
                          { role_id: 'role1', role_name: 'reader', resource_id: 'r1', resource_name: 'Billing API', source: 'group', group_id: 'g1', group_name: 'Finance' },
                          { role_id: 'role2', role_name: 'admin', resource_id: 'r1', resource_name: 'Billing API', source: 'direct' },
                        ] } :
                          path === `${org}/members/u1/groups` ? page([manual]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[path]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
const envBase = '/projects/project1/environments/env1'
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('lists groups and makes directory groups read-only', async () => {
  open(`${envBase}/organizations/org1/groups`)
  await screen.findByText('Finance')
  expect(screen.getByText('Groups of Acme')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Actions for Finance' }))
  expect(await screen.findByRole('menuitem', { name: 'Edit' })).toBeTruthy()
  expect(screen.getByRole('menuitem', { name: 'Delete group' })).toBeTruthy()
  await userEvent.keyboard('{Escape}')
  expect(screen.getByText('Directory')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Actions for Engineering' })).toBeNull()
})

it('creates a group', async () => {
  const user = userEvent.setup()
  open(`${envBase}/organizations/org1/groups`)
  await user.click(await screen.findByRole('button', { name: 'Create group' }))
  await user.type(screen.getByLabelText('Name'), 'Ops')
  await user.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('POST')).toEqual([{ url: `/management/v1${org}/groups`, body: { name: 'Ops', description: '' } }]))
})

it('shows group roles and members, and removes a member', async () => {
  const user = userEvent.setup()
  open(`${envBase}/organizations/org1/groups/g1`)
  await screen.findByText('reader')
  expect(screen.getByText('Billing API')).toBeTruthy()
  await user.click(await screen.findByRole('button', { name: 'Actions for Jane' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Remove from group' }))
  await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Remove' }))
  await waitFor(() => expect(calls('POST')).toEqual([{ url: `/management/v1${org}/groups/g1/members`, body: { remove: ['u1'] } }]))
})

it('lets operators bind roles to directory groups but not change members', async () => {
  open(`${envBase}/organizations/org1/groups/g2`)
  await screen.findByText(/managed by a provisioning directory/)
  expect(screen.getByRole('button', { name: /Assign role/ })).toBeTruthy()
  expect(screen.queryByRole('button', { name: /Add member/ })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Actions for Jane' })).toBeNull()
})

it('hides group write controls for a viewer', async () => {
  role = 'viewer'
  open(`${envBase}/organizations/org1/groups/g1`)
  await screen.findByText('reader')
  expect(screen.queryByRole('button', { name: /Assign role/ })).toBeNull()
  expect(screen.queryByRole('button', { name: /Add member/ })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Unassign reader' })).toBeNull()
})

it('shows a member effective roles with their source', async () => {
  const user = userEvent.setup()
  role = 'viewer'
  open(`${envBase}/organizations/org1/members`)
  await user.click(await screen.findByRole('button', { name: 'Actions for Jane' }))
  await user.click(await screen.findByRole('menuitem', { name: 'View access' }))
  const dialog = await screen.findByRole('dialog')
  await within(dialog).findByText('reader')
  expect(within(dialog).getByText('via Finance')).toBeTruthy()
  expect(within(dialog).getByText('Direct')).toBeTruthy()
  expect(within(dialog).getAllByText('Finance').length).toBeGreaterThan(0)
  const effective = fetchMock.mock.calls.map(([url]) => String(url)).find(url => url.includes('/effective-roles'))!
  expect(effective).toContain('organization_id=org1')
  expect(effective).toContain('user_id=u1')
})
