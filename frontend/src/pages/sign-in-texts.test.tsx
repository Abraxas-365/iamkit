// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { scopePath, textProblem } from './sign-in-texts'

const fetchMock = vi.fn()
let role = 'owner'
let saved: Record<string, string> = {}
const env = '/environments/env1/login-settings'
const catalog = [
  { key: 'hosted.form.continue', default: 'Continue', placeholders: [], max_length: 80 },
  { key: 'hosted.notice.code_sent', default: 'We sent a code to %s.', placeholders: ['%s'], max_length: 80 },
  { key: 'hosted.title.sign_in', default: 'Sign in', placeholders: [], max_length: 80 },
]

beforeEach(() => {
  role = 'owner'
  saved = {}
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method === 'PUT') return Response.json({ locale: 'en', texts: JSON.parse(String(init.body)).texts })
    if (init.method === 'DELETE') return new Response(null, { status: 204 })
    if (init.method === 'POST') return Response.json({ html: '<p>preview</p>' })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/locales` ? { items: [{ code: 'en', name: 'English' }, { code: 'es', name: 'Español' }] } :
            path === `${env}/texts/catalog` ? { locale: 'en', items: catalog } :
              path === `${env}/texts` ? { items: [], page: { total: 0, limit: 100, offset: 0 } } :
                path.startsWith(`${env}`) && path.includes('/texts/') ? { locale: path.split('/').at(-1), texts: saved } :
                  path === '/environments/env1/oauth-clients' ? { items: [{ id: 'c1', application_name: 'Web', resource_name: 'Billing', hosted_login: true }] } :
                    path === '/environments/env1/organizations' ? { items: [{ id: 'o1', name: 'Acme' }] } : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/hosted-login/texts']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('checks texts like the server and builds scope paths', () => {
  expect(textProblem('', catalog[1])).toBe('')
  expect(textProblem('Code sent to %s', catalog[1])).toBe('')
  expect(textProblem('Code sent', catalog[1])).toBe('Keep %s.')
  expect(textProblem('a'.repeat(81), catalog[0])).toBe('At most 80 characters.')
  expect(scopePath('/environments/e', '', 'es')).toBe('/environments/e/login-settings/texts/es')
  expect(scopePath('/environments/e', 'client:c1', 'en')).toBe('/environments/e/login-settings/clients/c1/texts/en')
  expect(scopePath('/environments/e', 'organization:o1', 'en')).toBe('/environments/e/login-settings/organizations/o1/texts/en')
})

it('saves only customized texts and previews the draft', async () => {
  open()
  const field = await screen.findByLabelText('hosted.form.continue')
  expect(field.getAttribute('placeholder')).toBe('Continue')
  await userEvent.type(field, 'Next')
  await waitFor(() => expect(calls('POST').at(-1)?.body.texts).toEqual({ 'hosted.form.continue': 'Next' }))
  await userEvent.type(screen.getByLabelText('hosted.notice.code_sent'), 'Sent')
  expect(screen.getByText('Keep %s.')).toBeTruthy()
  expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true)
  await userEvent.type(screen.getByLabelText('hosted.notice.code_sent'), ' to %s')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toHaveLength(1))
  expect(calls('PUT')[0].url).toContain(`${env}/texts/en`)
  expect(calls('PUT')[0].body).toEqual({ texts: { 'hosted.form.continue': 'Next', 'hosted.notice.code_sent': 'Sent to %s' } })
})

it('edits an organization in another language and removes its texts', async () => {
  saved = { 'hosted.title.sign_in': 'Hola' }
  open()
  const scope = await screen.findByLabelText('Texts for')
  await waitFor(() => expect(scope.querySelector('option[value="organization:o1"]')).toBeTruthy())
  await userEvent.selectOptions(scope, 'organization:o1')
  await userEvent.selectOptions(screen.getByLabelText('Language'), 'es')
  await waitFor(() => expect((screen.getByLabelText('hosted.title.sign_in') as HTMLInputElement).value).toBe('Hola'))
  await waitFor(() => expect(calls('POST').at(-1)?.body).toMatchObject({ organization_id: 'o1', locale: 'es' }))
  await userEvent.click(screen.getByRole('button', { name: /Remove these texts/ }))
  await userEvent.click(screen.getByRole('button', { name: 'Remove' }))
  await waitFor(() => expect(calls('DELETE')).toHaveLength(1))
  expect(calls('DELETE')[0].url).toContain(`${env}/organizations/o1/texts/es`)
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  open()
  expect((await screen.findByLabelText('hosted.form.continue') as HTMLInputElement).disabled).toBe(true)
  expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
})
