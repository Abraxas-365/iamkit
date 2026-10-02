// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let effectiveFails = false
const env = '/environments/env1'
const envBase = '/projects/project1/environments/env1'

beforeEach(() => {
  effectiveFails = false
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    if (init.method && init.method !== 'GET') return new Response(null, { status: 204 })
    const path = url.replace('/management/v1', '').split('?')[0]
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role: 'owner' } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/roles` ? page([{ id: 'role1', name: 'reader', resource_name: 'Billing API' }, { id: 'role3', name: 'writer', resource_name: 'Billing API' }]) :
            path === `${env}/organizations` ? page([{ id: 'org1', name: 'Acme', active: true }]) :
              path === `${env}/organizations/org1/groups` ? page([{ id: 'g1', name: 'Finance' }]) :
                path === `${env}/organizations/org1/members` ? page([{ user_id: 'u1', user_name: 'Jane', user_email: 'jane@example.com', active: true }]) :
                  path === `${env}/role-assignments` ? page([{ organization_id: 'org1', organization_name: 'Acme', user_id: 'u1', user_name: 'Jane', user_email: 'jane@example.com', resource_id: 'r1', resource_name: 'Billing API', role_id: 'role2', role_name: 'admin' }]) :
                    path === `${env}/group-role-assignments` ? page([{ organization_id: 'org1', organization_name: 'Acme', group_id: 'g1', group_name: 'Finance', resource_id: 'r1', resource_name: 'Billing API', role_id: 'role1', role_name: 'reader' }]) :
                      path === `${env}/users/u1` ? { id: 'u1', name: 'Jane', email: 'jane@example.com', active: true } :
                        path === `${env}/users/u1/factors` ? { factors: [], recovery_codes_remaining: 0 } :
                          path === `${env}/effective-roles` ? (effectiveFails ? new Response(JSON.stringify({ error: { message: 'database unavailable' } }), { status: 500 }) : { items: [
                            { organization_id: 'org1', role_id: 'role2', role_name: 'admin', resource_id: 'r1', resource_name: 'Billing API', source: 'direct', granted: true },
                            { organization_id: 'org1', role_id: 'role1', role_name: 'reader', resource_id: 'r1', resource_name: 'Billing API', source: 'group', granted: true, group_id: 'g1', group_name: 'Finance' },
                          ] }) :
                            path === `${env}/users` ? page([{ id: 'u1', name: 'Jane', email: 'jane@example.com', active: true }]) : page([])
    return data instanceof Response ? data : Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })

function open(path: string) {
  render(<MemoryRouter initialEntries={[path]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}
/** option finds an entry of the open search-select dropdown (portalled list). */
async function option(label: string) {
  return (await screen.findAllByText(label)).find(el => el.closest('li'))!
}

it('lists group role assignments on the Groups tab and unassigns one', async () => {
  const user = userEvent.setup()
  open(`${envBase}/role-assignments`)
  await screen.findByText('jane@example.com')
  await user.click(screen.getByRole('tab', { name: 'Groups' }))
  const link = await screen.findByRole('link', { name: 'Finance' })
  expect(link.getAttribute('href')).toBe(`${envBase}/organizations/org1/groups/g1`)
  expect(screen.getByRole('tab', { name: 'Groups' }).getAttribute('aria-selected')).toBe('true')
  expect(screen.queryByLabelText('Filter by User')).toBeNull()
  await user.click(screen.getByRole('button', { name: 'Actions for Finance as reader' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Unassign role' }))
  await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Unassign' }))
  await waitFor(() => expect(calls('DELETE').map(c => c.url)).toEqual([`/management/v1${env}/group-role-assignments/role1/org1/g1`]))
})

it('assigns a role to a group, picking the organization first', async () => {
  const user = userEvent.setup()
  open(`${envBase}/role-assignments`)
  await user.click(await screen.findByRole('button', { name: 'Assign role' }))
  const dialog = await screen.findByRole('dialog')
  await user.click(within(dialog).getByLabelText(/A group/))
  expect(within(dialog).getByText('Pick an organization first.')).toBeTruthy()
  await user.click(within(dialog).getByLabelText('Organization'))
  await user.click(await option('Acme'))
  await user.click(within(dialog).getByLabelText('Group'))
  await user.click(await option('Finance'))
  await user.click(within(dialog).getByLabelText('Role'))
  await user.click(await screen.findByText('writer · Billing API'))
  await user.click(within(dialog).getByRole('button', { name: 'Assign role' }))
  await waitFor(() => expect(calls('POST')).toEqual([{ url: `/management/v1${env}/group-role-assignments`, body: { organization_id: 'org1', group_id: 'g1', role_id: 'role3' } }]))
  await waitFor(() => expect(screen.getByRole('tab', { name: 'Groups' }).getAttribute('aria-selected')).toBe('true'))
})

it('assigns a role to an organization member', async () => {
  const user = userEvent.setup()
  open(`${envBase}/role-assignments`)
  await user.click(await screen.findByRole('button', { name: 'Assign role' }))
  const dialog = await screen.findByRole('dialog')
  await user.click(within(dialog).getByLabelText('Organization'))
  await user.click(await option('Acme'))
  await user.click(within(dialog).getByLabelText('User'))
  await user.click(await screen.findByText('Jane (jane@example.com)'))
  await user.click(within(dialog).getByLabelText('Role'))
  await user.click(await screen.findByText('reader · Billing API'))
  await user.click(within(dialog).getByRole('button', { name: 'Assign role' }))
  await waitFor(() => expect(calls('POST')).toEqual([{ url: `/management/v1${env}/role-assignments`, body: { organization_id: 'org1', user_id: 'u1', role_id: 'role1' } }]))
})

it('shows roles a user inherits from groups on their page', async () => {
  open(`${envBase}/users/u1`)
  const inherited = await screen.findByText('via Finance')
  expect(inherited.closest('a')?.getAttribute('href')).toBe(`${envBase}/organizations/org1/groups/g1`)
  expect(screen.getByRole('button', { name: 'Remove role admin in Acme' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Remove role reader in Acme' })).toBeNull()
  // One request covers every organization.
  const effective = fetchMock.mock.calls.map(([url]) => String(url)).filter(url => url.includes('/effective-roles'))
  expect(effective).toEqual([`/management/v1${env}/effective-roles?user_id=u1`])
})

it('surfaces a failure to load a user\'s roles', async () => {
  effectiveFails = true
  open(`${envBase}/users/u1`)
  expect(await screen.findByText('Roles could not be loaded: database unavailable')).toBeTruthy()
  expect(screen.getByText('Unavailable')).toBeTruthy()
  expect(screen.queryByText('No roles')).toBeNull()
})

it('marks roles the subject already holds and blocks assigning them again', async () => {
  const user = userEvent.setup()
  open(`${envBase}/users/u1`)
  await screen.findByText('via Finance')
  await user.click(screen.getByRole('button', { name: 'Actions for Acme' }))
  await user.click(await screen.findByRole('menuitem', { name: 'Assign role' }))
  const dialog = await screen.findByRole('dialog')
  await user.click(within(dialog).getByLabelText('Role'))
  // reader comes from the Finance group: a direct assignment is still allowed.
  expect(await screen.findByText('Via Finance')).toBeTruthy()
  await user.click(await screen.findByText('reader · Billing API'))
  expect(within(dialog).getByRole('status').textContent).toBe('The user already holds this role via Finance; a direct assignment keeps it if they leave the group.')
  expect(within(dialog).getByRole('button', { name: 'Assign role' })).toHaveProperty('disabled', false)
})

it('filters by a user found by search, and clears it', async () => {
  const user = userEvent.setup()
  open(`${envBase}/role-assignments`)
  await screen.findByText('jane@example.com')
  await user.click(screen.getByLabelText('Filter by user'))
  await user.click(await option('Jane'))
  await waitFor(() => expect(fetchMock.mock.calls.map(([url]) => String(url)).some(url => url.includes('/role-assignments?') && url.includes('user_id=u1'))).toBe(true))
  const users = fetchMock.mock.calls.map(([url]) => String(url)).filter(url => url.includes(`${env}/users?`))
  expect(users.every(url => url.includes('limit=25'))).toBe(true)
  await user.click(screen.getByRole('button', { name: 'Clear user filter' }))
  expect(screen.queryByRole('button', { name: 'Clear user filter' })).toBeNull()
})

it('keeps the search after assigning a role', async () => {
  const user = userEvent.setup()
  open(`${envBase}/role-assignments`)
  await screen.findByText('jane@example.com')
  await user.type(screen.getByLabelText('Search assignments'), 'adm')
  await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/role-assignments?') && String(url).includes('search=adm'))).toBe(true))
  await user.click(screen.getByRole('button', { name: 'Assign role' }))
  const dialog = await screen.findByRole('dialog')
  await user.click(within(dialog).getByLabelText('Organization'))
  await user.click(await option('Acme'))
  await user.click(within(dialog).getByLabelText('User'))
  await user.click(await screen.findByText('Jane (jane@example.com)'))
  await user.click(within(dialog).getByLabelText('Role'))
  await user.click(await screen.findByText('reader · Billing API'))
  const before = fetchMock.mock.calls.length
  await user.click(within(dialog).getByRole('button', { name: 'Assign role' }))
  await waitFor(() => expect(fetchMock.mock.calls.slice(before).some(([url, init]) => !init?.method && String(url).includes('/role-assignments?') && String(url).includes('search=adm'))).toBe(true))
  expect((screen.getByLabelText('Search assignments') as HTMLInputElement).value).toBe('adm')
})

it('switches tabs with the arrow keys', async () => {
  const user = userEvent.setup()
  open(`${envBase}/role-assignments`)
  await screen.findByText('jane@example.com')
  const users = screen.getByRole('tab', { name: 'Users' })
  expect(users.tabIndex).toBe(0)
  expect(screen.getByRole('tab', { name: 'Groups' }).tabIndex).toBe(-1)
  users.focus()
  await user.keyboard('{ArrowRight}')
  const groups = screen.getByRole('tab', { name: 'Groups' })
  expect(groups.getAttribute('aria-selected')).toBe('true')
  expect(document.activeElement).toBe(groups)
  expect(screen.getByRole('tabpanel').getAttribute('aria-labelledby')).toBe('assignments-tab-group')
  await user.keyboard('{ArrowRight}')
  expect(screen.getByRole('tab', { name: 'Users' }).getAttribute('aria-selected')).toBe('true')
})
