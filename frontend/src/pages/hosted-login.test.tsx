// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, MemoryRouter, RouterProvider } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let role = 'owner'
let savedLocale = ''
let localesFail = false
const client = { id: 'c1', application_id: 'a1', application_name: 'Web', resource_id: 'r1', resource_name: 'Billing', redirect_uris: ['https://app.example/callback'], public: true, hosted_login: false, active: true }
const env = '/environments/env1'

beforeEach(() => {
  role = 'owner'
  savedLocale = ''
  localesFail = false
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method === 'PATCH') return new Response(null, { status: 204 })
    if (init.method === 'PUT') {
      const body = JSON.parse(String(init.body))
      return Response.json({ environment_id: 'env1', ...body, updated_at: '2026-09-27T00:00:00Z' })
    }
    if (init.method === 'DELETE') return new Response(null, { status: 204 })
    if (path.endsWith('/login-settings/preview')) return Response.json({ html: '<!doctype html><title>preview</title>' })
    if (localesFail && path === `${env}/login-settings/locales`) return Response.json({ error: { message: 'boom' } }, { status: 500 })
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/login-settings` ? { environment_id: 'env1', display_name: 'Acme', logo_url: '', accent_color: '', locale: savedLocale } :
            path === `${env}/login-settings/locales` ? { items: [{ code: 'en', name: 'English' }, { code: 'es', name: 'Español' }] } :
            path === `${env}/login-settings/clients` ? page([{ environment_id: 'env1', client_id: 'c2', display_name: 'Admin', logo_url: '', accent_color: '#ff6600', theme: { mode: 'dark' } }]) :
              path === `${env}/login-settings/clients/c1` ? null :
                path === `${env}/oauth-clients` ? page([client, { ...client, id: 'c2', application_name: 'Admin', hosted_login: true }, { ...client, id: 'c3', application_name: 'Portal', hosted_login: true }]) : page([])
    if (data === null) return Response.json({ error: { message: 'client uses the environment branding' } }, { status: 404 })
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(page: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${page}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('lists the default style and client styles', async () => {
  open('hosted-login')
  expect(await screen.findByRole('heading', { name: 'Default style' })).toBeTruthy()
  expect(screen.getByText('Acme')).toBeTruthy()
  // The hosted client is listed with the default style and can be customized.
  expect(await screen.findByText('Portal · Billing')).toBeTruthy()
  expect(screen.queryByText('Web · Billing')).toBeNull()
  expect(screen.getByRole('link', { name: 'Portal · Billing' }).getAttribute('href')).toBe('/projects/project1/environments/env1/hosted-login/clients/c3')
  await userEvent.click(screen.getByRole('button', { name: 'Actions for Portal · Billing' }))
  expect(await screen.findByRole('menuitem', { name: 'Customize style' })).toBeTruthy()
  await userEvent.keyboard('{Escape}')
  // The styled client can be reset to the default style.
  expect(screen.getByText('Custom')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Actions for Admin · Billing' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Reset to default style' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Reset' }))
  await waitFor(() => expect(calls('DELETE')).toHaveLength(1))
  expect(calls('DELETE')[0].url).toContain(`${env}/login-settings/clients/c2`)
})

it('edits the default style with a live preview', async () => {
  open('hosted-login/default')
  const name = await screen.findByLabelText('Display name')
  expect((name as HTMLInputElement).value).toBe('Acme')
  await waitFor(() => expect(calls('POST').some(c => c.url.endsWith('/login-settings/preview'))).toBe(true))
  expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
  await userEvent.clear(name)
  await userEvent.type(name, 'Acme Billing')
  await userEvent.selectOptions(screen.getByLabelText('Mode'), 'adaptive')
  const primary = screen.getByLabelText('Dark primary')
  await userEvent.type(primary, '#FFAA00')
  await userEvent.click(screen.getByRole('button', { name: 'Add link' }))
  await userEvent.type(screen.getByLabelText('Link 1 label'), 'Privacy')
  await userEvent.type(screen.getByLabelText('Link 1 URL'), 'https://acme.example/privacy')
  await waitFor(() => {
    const last = calls('POST').filter(c => c.url.endsWith('/login-settings/preview')).at(-1)
    expect(last?.body.settings.display_name).toBe('Acme Billing')
    expect(last?.body.settings.theme.footer.links).toHaveLength(1)
  }, { timeout: 2000 })
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toHaveLength(1))
  const put = calls('PUT')[0]
  expect(put.url).toMatch(/\/environments\/env1\/login-settings$/)
  expect(put.body.display_name).toBe('Acme Billing')
  expect(put.body.theme.mode).toBe('adaptive')
  expect(put.body.theme.dark.primary).toBe('#FFAA00')
  expect(put.body.theme.footer.links).toEqual([{ label: 'Privacy', url: 'https://acme.example/privacy' }])
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Save' })).toBeNull())
})

it('starts a client style from the default and warns on low contrast', async () => {
  open('hosted-login/clients/c1')
  expect(await screen.findByText(/This client uses the default style/)).toBeTruthy()
  expect((screen.getByLabelText('Display name') as HTMLInputElement).value).toBe('Acme')
  // Unsaved new style: the save bar is shown right away.
  expect(screen.getByRole('button', { name: 'Save' })).toBeTruthy()
  await userEvent.type(screen.getByLabelText('Light text'), '#eeeeee')
  expect(await screen.findByLabelText('Contrast warnings')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toHaveLength(1))
  expect(calls('PUT')[0].url).toContain(`${env}/login-settings/clients/c1`)
  expect(calls('PUT')[0].body).not.toHaveProperty('locale')
  expect(screen.queryByLabelText('Language')).toBeNull()
})

it('previews only the chosen sign-in methods', async () => {
  open('hosted-login/default')
  const picker = await screen.findByRole('group', { name: 'Sign-in methods in the preview' })
  // No social login in the environment: sample buttons, every method on.
  expect(within(picker).getByRole('button', { name: 'Google' }).getAttribute('aria-pressed')).toBe('true')
  await userEvent.click(within(picker).getByRole('button', { name: 'Social only' }))
  await waitFor(() => {
    const last = calls('POST').filter(c => c.url.endsWith('/login-settings/preview')).at(-1)
    expect(last?.body.sign_in).toMatchObject({ password: false, email_code: false, organization_sso: false })
    expect(last?.body.sign_in.connections.map((c: { name: string }) => c.name)).toEqual(['Google', 'Microsoft', 'GitHub', 'Apple'])
  }, { timeout: 2000 })
  expect(within(picker).getByText(/No email field/)).toBeTruthy()
  // The preview never changes the saved style.
  expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
  // Pages without sign-in methods hide the picker and send none.
  await userEvent.selectOptions(screen.getByLabelText('Preview page'), 'mfa')
  expect(screen.queryByRole('group', { name: 'Sign-in methods in the preview' })).toBeNull()
})

it('previews dark, another language and a background image of a light style', async () => {
  open('hosted-login/default')
  await screen.findByLabelText('Display name')
  const lastPreview = () => calls('POST').filter(c => c.url.endsWith('/login-settings/preview')).at(-1)
  // The mode is light, yet dark can be previewed, with a way to show it.
  const dark = screen.getByRole('button', { name: 'Dark' })
  expect(dark.matches(':disabled')).toBe(false)
  await userEvent.click(dark)
  await waitFor(() => expect(lastPreview()?.body.scheme).toBe('dark'), { timeout: 2000 })
  expect(screen.getByText(/Visitors never see this dark version/)).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Use adaptive' }))
  expect((screen.getByLabelText('Mode') as HTMLSelectElement).value).toBe('adaptive')
  expect(screen.queryByText(/Visitors never see/)).toBeNull()
  // The language of the preview only changes the preview.
  const language = await screen.findByLabelText('Preview language')
  await userEvent.selectOptions(language, 'es')
  await waitFor(() => expect(lastPreview()?.body.locale).toBe('es'), { timeout: 2000 })
  // A background image, with its tint.
  expect(screen.queryByLabelText(/Background tint/)).toBeNull()
  await userEvent.type(screen.getByLabelText('Background image URL'), 'https://cdn.example/bg.jpg')
  expect(screen.getByLabelText('Background tint: 0%')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toHaveLength(1))
  expect(calls('PUT')[0].body.theme).toMatchObject({ mode: 'adaptive', background_image_url: 'https://cdn.example/bg.jpg', background_overlay: 0 })
})

it('sets the language of the default style', async () => {
  open('hosted-login/default')
  const select = await screen.findByLabelText('Language')
  await waitFor(() => expect(within(select).getByRole('option', { name: 'Español' })).toBeTruthy())
  await userEvent.selectOptions(select, 'es')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toHaveLength(1))
  expect(calls('PUT')[0].body).toMatchObject({ display_name: 'Acme', locale: 'es' })
})

it('keeps a language the server no longer lists', async () => {
  savedLocale = 'pt'
  open('hosted-login/default')
  const select = await screen.findByLabelText('Language') as HTMLSelectElement
  await waitFor(() => expect(within(select).getByRole('option', { name: 'pt (not available)' })).toBeTruthy())
  expect(select.value).toBe('pt')
  expect(screen.getByText(/“pt” is no longer available/)).toBeTruthy()
})

it('keeps the saved language when the list fails to load', async () => {
  savedLocale = 'es'
  localesFail = true
  open('hosted-login/default')
  const select = await screen.findByLabelText('Language') as HTMLSelectElement
  await waitFor(() => expect(screen.getByText(/could not be loaded/)).toBeTruthy())
  expect(select.value).toBe('es')
  expect(select.getAttribute('aria-describedby')).toBe('locale-hint')
})

it('is read-only for viewers and previews the saved style', async () => {
  role = 'viewer'
  open('hosted-login/default')
  const name = await screen.findByLabelText('Display name')
  expect(name.matches(':disabled')).toBe(true)
  expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
  await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url).includes('/login-settings/preview?') && !init?.method)).toBe(true))
  expect(calls('POST')).toHaveLength(0)
})

it('toggles hosted login on an OAuth client', async () => {
  open('oauth-clients')
  await screen.findByText('Your UI')
  await userEvent.click(screen.getByRole('button', { name: 'Actions for Web' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Switch to hosted page' }))
  await waitFor(() => expect(calls('PATCH')).toHaveLength(1))
  expect(calls('PATCH')[0].url).toContain(`${env}/oauth-clients/c1`)
  expect(calls('PATCH')[0].body).toEqual({ hosted_login: true })
})

it('asks before leaving the editor with unsaved changes', async () => {
  // A data router, as in main.tsx, so in-app navigation can be blocked.
  const router = createMemoryRouter([{ path: '*', element: <AuthProvider><App /></AuthProvider> }], { initialEntries: ['/projects/project1/environments/env1/hosted-login/default'] })
  render(<RouterProvider router={router} />)
  const name = await screen.findByLabelText('Display name')
  await userEvent.type(name, ' Inc')
  // Keep editing: the draft stays.
  await userEvent.click(screen.getAllByRole('link', { name: /Hosted login/ })[0])
  const dialog = await screen.findByRole('dialog', { name: 'Leave without saving?' })
  await userEvent.click(within(dialog).getByRole('button', { name: 'Keep editing' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  expect((screen.getByLabelText('Display name') as HTMLInputElement).value).toBe('Acme Inc')
  expect(router.state.location.pathname).toBe('/projects/project1/environments/env1/hosted-login/default')
  // Discard changes: the navigation goes through.
  await userEvent.click(screen.getAllByRole('link', { name: /Hosted login/ })[0])
  await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Discard changes' }))
  await waitFor(() => expect(router.state.location.pathname).toBe('/projects/project1/environments/env1/hosted-login'))
  expect(calls('PUT')).toHaveLength(0)
})

it('does not ask after saving', async () => {
  const router = createMemoryRouter([{ path: '*', element: <AuthProvider><App /></AuthProvider> }], { initialEntries: ['/projects/project1/environments/env1/hosted-login/default'] })
  render(<RouterProvider router={router} />)
  await userEvent.type(await screen.findByLabelText('Display name'), ' Inc')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Save' })).toBeNull())
  await userEvent.click(screen.getAllByRole('link', { name: /Hosted login/ })[0])
  await waitFor(() => expect(router.state.location.pathname).toBe('/projects/project1/environments/env1/hosted-login'))
  expect(screen.queryByRole('dialog')).toBeNull()
})
