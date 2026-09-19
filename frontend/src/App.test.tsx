// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from './lib/auth'
import App from './App'

const fetchMock = vi.fn()
let role = 'owner'
let grants = false
beforeEach(() => {
  role = 'owner'; grants = false
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit) => {
    if (init.method === 'PUT') return Response.json({ id: 'grant1' })
    const fullPath = url.replace('/management/v1', '')
    const path = fullPath.split('?')[0]
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === '/environments/env1/users' ? [{ id: 'user1', name: 'Jane', email: 'jane@example.com', active: true }] :
            path === '/environments/env1/grants' && grants ? [{ id: 'grant1', organization_id: 'org1', user_id: 'user1', resource_id: 'resource1', permissions: ['read'] }] :
              path === '/environments/env1/resources/resource1' ? { id: 'resource1', name: 'API', audience: 'https://api.test', permissions: ['read', 'write'] } : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[path]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
it('loads deep-linked environment context in the parent shell', async () => {
  open('/projects/project1/environments/env1/users')
  await screen.findByText('Jane')
  expect((screen.getByLabelText('Project') as HTMLSelectElement).value).toBe('project1')
  expect((screen.getByLabelText('Environment') as HTMLSelectElement).value).toBe('env1')
  expect(screen.getByRole('link', { name: 'Roles' }).getAttribute('href')).toBe('/projects/project1/environments/env1/roles')
})
it('toggles the inset sidebar without losing environment context', async () => {
  const user = userEvent.setup()
  open('/projects/project1/environments/env1/users')
  await screen.findByText('Jane')
  const sidebar = document.querySelector('[data-slot="sidebar"]')!
  expect(sidebar.getAttribute('data-state')).toBe('expanded')
  await user.click(screen.getByRole('button', { name: 'Toggle Sidebar' }))
  expect(sidebar.getAttribute('data-state')).toBe('collapsed')
  expect((screen.getByLabelText('Environment') as HTMLSelectElement).value).toBe('env1')
  await user.click(screen.getByRole('button', { name: 'Toggle Sidebar' }))
  expect(sidebar.getAttribute('data-state')).toBe('expanded')
})
it('blocks a project/environment mismatch before fetching or mutating data', async () => {
  open('/projects/project1/environments/other-env/users')
  await screen.findByText('This project or environment was not found. Select a valid context above.')
  expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/other-env/'))).toBe(false)
  expect(screen.queryByRole('button', { name: 'Create' })).toBeNull()
})
it('hides environment write controls for a viewer', async () => {
  role = 'viewer'
  open('/projects/project1/environments/env1/users')
  await screen.findByText('Jane')
  expect(screen.queryByRole('button', { name: 'Create' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Edit Jane' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Suspend Jane' })).toBeNull()
})
it('edits grant permissions without changing the recipient tuple', async () => {
  grants = true
  const user = userEvent.setup()
  open('/projects/project1/environments/env1/grants')
  await user.click(await screen.findByRole('button', { name: 'Edit grant1' }))
  // Verify org/user/resource are displayed as read-only (hidden inputs, not editable selects)
  expect(screen.queryByRole('combobox', { name: 'Organization' })).toBeNull()
  expect(screen.queryByRole('combobox', { name: 'User' })).toBeNull()
  // The PermissionPicker fetches the resource's catalog; our mock returns ['read', 'write']
  // Wait for the catalog checkboxes to load
  const readCheckbox = await screen.findByRole('checkbox', { name: 'read' }) as HTMLInputElement
  expect(readCheckbox.checked).toBe(true)
  const writeCheckbox = screen.getByRole('checkbox', { name: 'write' }) as HTMLInputElement
  expect(writeCheckbox.checked).toBe(false)
  await user.click(writeCheckbox)
  await user.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(fetchMock.mock.calls.some(([, init]) => init.method === 'PUT')).toBe(true))
  const [, init] = fetchMock.mock.calls.find(([, init]) => init.method === 'PUT')!
  expect(JSON.parse(init.body)).toEqual({ permissions: ['read', 'write'], organization_id: 'org1', user_id: 'user1', resource_id: 'resource1' })
})
