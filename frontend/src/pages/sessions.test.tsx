// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
const session = (id: string, organization: string, application: string) => ({
  id, user_id: `u-${id}`, user_name: '', user_email: `${id}@example.com`, organization_id: organization, organization_name: organization === 'o1' ? 'Acme' : 'Globex',
  application_id: application, application_name: application === 'a1' ? 'Web' : 'Mobile', resource_id: 'r1', resource_name: 'Billing',
  authenticated_at: new Date().toISOString(), expires_at: new Date(Date.now() + 3600e3).toISOString(), revoked_at: null,
})
const sessions = [session('s1', 'o1', 'a1'), session('s2', 'o2', 'a1'), session('s3', 'o1', 'a2')]
let queries: URLSearchParams[]

beforeEach(() => {
  queries = []
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string) => {
    const [path, raw = ''] = url.replace('/management/v1', '').split('?')
    const query = new URLSearchParams(raw)
    if (path === `${env}/sessions`) {
      queries.push(query)
      const items = sessions.filter(s => (!query.get('organization_id') || s.organization_id === query.get('organization_id')) && (!query.get('application_id') || s.application_id === query.get('application_id')))
      return Response.json({ items, page: { total: items.length, limit: 50, offset: 0 } })
    }
    if (path === `${env}/organizations`) return Response.json({ items: [{ id: 'o1', name: 'Acme' }, { id: 'o2', name: 'Globex' }] })
    if (path === `${env}/applications`) return Response.json({ items: [{ id: 'a1', name: 'Web' }, { id: 'a2', name: 'Mobile' }] })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role: 'owner' } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path.startsWith(env) ? { items: [] } : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
const open = (search = '') => render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/sessions${search}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)

it('narrows sessions to an organization and an application', async () => {
  const u = userEvent.setup()
  open()
  expect(await screen.findByText('s2@example.com')).toBeTruthy()
  const organization = screen.getByLabelText('Filter by organization')
  await screen.findByRole('option', { name: 'Acme' })
  await u.selectOptions(organization, 'o1')
  await waitFor(() => expect(screen.queryByText('s2@example.com')).toBeNull())
  expect(screen.getByText('s1@example.com')).toBeTruthy()
  expect(queries.at(-1)!.get('organization_id')).toBe('o1')

  await screen.findByRole('option', { name: 'Mobile' })
  await u.selectOptions(screen.getByLabelText('Filter by application'), 'a2')
  await waitFor(() => expect(screen.queryByText('s1@example.com')).toBeNull())
  expect(screen.getByText('s3@example.com')).toBeTruthy()
  expect(Object.fromEntries(queries.at(-1)!)).toMatchObject({ organization_id: 'o1', application_id: 'a2' })

  await u.selectOptions(organization, '')
  await waitFor(() => expect(queries.at(-1)!.get('organization_id')).toBeNull())
})

it('opens with the filters of the link', async () => {
  open('?application_id=a2')
  expect(await screen.findByText('s3@example.com')).toBeTruthy()
  expect(screen.queryByText('s1@example.com')).toBeNull()
  expect(queries[0].get('application_id')).toBe('a2')
})
