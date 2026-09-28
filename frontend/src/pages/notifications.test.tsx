// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let role = 'owner'
let config: Record<string, unknown> | null = null
let status: Record<string, unknown>
let putDelivery: () => Response
const delivery = '/environments/env1/delivery'
const hosted = 'https://iam.example/hosted/invite'
const smtpConfig = {
  environment_id: 'env1', provider: 'smtp', webhook_url: '', has_token: false, invitation_url: '', from_email: 'no-reply@acme.io', from_name: 'Acme', reply_to: '',
  smtp_host: 'smtp.acme.io', smtp_port: 587, smtp_username: 'mailer', smtp_tls: 'starttls', has_secret: true, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
}
const defaults = { subject: 'Your sign-in code for {{app_name}}', heading: 'Your sign-in code', body: 'Enter this code to sign in.', action: '', footer: 'If you did not ask for it, ignore this email.' }
let templates: Record<string, { subject: string; heading: string; body: string; action: string; footer: string }>
let branding: Record<string, unknown>

beforeEach(() => {
  role = 'owner'
  config = null
  templates = {}
  branding = { environment_id: 'env1', display_name: 'Acme', logo_url: '', accent_color: '#2563eb', theme: { mode: 'dark', light: { primary: '#2563eb' } }, locale: 'fr' }
  putDelivery = () => new Response(null, { status: 204 })
  status = { source: 'global', provider: 'webhook', global_configured: true, hosted_invitation_url: hosted, last_attempt: null, last_failure: null }
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    const template = path.match(/\/delivery\/templates\/(\w+)\/(\w+)$/)
    if (init.method === 'POST' && path === `${delivery}/test`) {
      return Response.json({ source: 'environment', purpose: 'test', delivered: false, status: 503, reason: 'webhook rejected the request', latency_ms: 12, at: '2026-09-27T10:00:00Z' })
    }
    if (path === '/environments/env1/login-settings') {
      if (init.method === 'PUT') branding = { ...branding, ...body }
      return Response.json(branding)
    }
    if (path === `${delivery}/preview`) {
      const subject = init.method === 'POST' ? (body.template?.subject || defaults.subject).replace('{{app_name}}', body.app_name || 'IAMKit') : `Saved ${new URLSearchParams(url.split('?')[1]).toString()}`
      return Response.json({ subject, html: '<!doctype html><p>preview</p>', text: 'Your code: 123456' })
    }
    if (template) {
      const key = `${template[1]}/${template[2]}`
      if (init.method === 'PUT') templates[key] = body
      if (init.method === 'DELETE') { delete templates[key]; return new Response(null, { status: 204 }) }
      return Response.json({ purpose: template[1], locale: template[2], customized: !!templates[key], template: templates[key] ?? { subject: '', heading: '', body: '', action: '', footer: '' }, defaults, placeholders: ['app_name', 'email', 'code', 'expires_in'] })
    }
    if (path === `${delivery}/templates`) {
      return Response.json({ items: ['login', 'password_reset', 'email_verification', 'invitation', 'test'].flatMap(p => ['en', 'es'].map(l => ({ purpose: p, locale: l, customized: !!templates[`${p}/${l}`] }))) })
    }
    if (init.method === 'PUT') return putDelivery()
    if (path === delivery) return config ? Response.json(config) : Response.json({ error: { message: 'delivery config not found' } }, { status: 404 })
    if (path === '/environments/env2/delivery') return Response.json({ ...smtpConfig, environment_id: 'env2', smtp_host: 'smtp.staging.acme.io' })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }, { id: 'env2', name: 'Staging' }] :
          path === '/environments/env1/login-settings/locales' ? { items: [{ code: 'en', name: 'English' }, { code: 'es', name: 'Español' }] } :
            path === `${delivery}/status` ? status : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/notifications']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('shows the global fallback, every message type and a correct description', async () => {
  open()
  await screen.findByText('Global fallback')
  expect(screen.getByText(/login codes, password resets, email verification and invitations/)).toBeTruthy()
  expect(screen.getByText('No deliveries yet.')).toBeTruthy()
  for (const p of ['login', 'password_reset', 'email_verification', 'invitation', 'test']) expect(screen.getAllByText(p).length).toBeGreaterThan(0)
  await userEvent.click(screen.getAllByRole('button', { name: 'Example' })[3])
  expect(screen.getByLabelText('invitation example payload').textContent).toContain('"expires_at"')
})

it('warns when nothing can deliver and hides the test button', async () => {
  status = { ...status, source: 'none', provider: '', global_configured: false }
  open()
  await screen.findByText('Not configured')
  expect(screen.queryByRole('button', { name: /Send test email/ })).toBeNull()
})

it('shows the last attempt and the sticky last failure', async () => {
  config = { environment_id: 'env1', provider: 'webhook', webhook_url: 'https://mail.example/hook', has_token: true, invitation_url: hosted, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }
  status = {
    ...status, source: 'environment',
    last_attempt: { source: 'environment', purpose: 'login', delivered: true, latency_ms: 42, at: '2026-09-27T10:00:00Z' },
    last_failure: { source: 'environment', purpose: 'invitation', delivered: false, status: 500, reason: 'webhook rejected the request', latency_ms: 0, at: '2026-09-26T10:00:00Z' },
  }
  open()
  await screen.findByText('This environment')
  expect(screen.getByText('Delivered in 42 ms')).toBeTruthy()
  expect(screen.getByText('webhook rejected the request (HTTP 500)')).toBeTruthy()
  expect(screen.getByText('Hosted page')).toBeTruthy()
})

it('sends a test email and shows the rejection', async () => {
  config = { environment_id: 'env1', provider: 'webhook', webhook_url: 'https://mail.example/hook', has_token: true, invitation_url: '', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }
  status = { ...status, source: 'environment' }
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Send test email/ }))
  await userEvent.type(screen.getByLabelText('Recipient'), 'ops@example.com')
  await userEvent.click(screen.getByRole('button', { name: /^Send$/ }))
  expect((await screen.findByRole('status')).textContent).toContain('webhook rejected the request (HTTP 503)')
  expect(calls('POST')).toEqual([{ url: `/management/v1${delivery}/test`, body: { email: 'ops@example.com' } }])
})

it('fills the hosted invitation page', async () => {
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Configure email delivery/ }))
  await userEvent.type(screen.getByLabelText('Webhook URL'), 'https://mail.example/hook')
  await userEvent.type(screen.getByLabelText('Webhook token'), 'secret')
  await userEvent.click(screen.getByRole('button', { name: 'Use hosted invite page' }))
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toEqual([{ url: `/management/v1${delivery}`, body: { provider: 'webhook', webhook_url: 'https://mail.example/hook', webhook_token: 'secret', invitation_url: hosted } }]))
})

it('lets viewers read but not change or test delivery', async () => {
  role = 'viewer'
  open()
  await screen.findByText('Global fallback')
  expect(screen.queryByRole('button', { name: /Send test email/ })).toBeNull()
  expect(screen.queryByRole('button', { name: /Configure email delivery/ })).toBeNull()
})

it('configures SMTP from a preset', async () => {
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Configure email delivery/ }))
  await userEvent.click(screen.getByRole('radio', { name: /SMTP/ }))
  expect(screen.queryByLabelText('Webhook URL')).toBeNull()
  await userEvent.selectOptions(screen.getByLabelText('Service'), 'sendgrid')
  expect((screen.getByLabelText('Host') as HTMLInputElement).value).toBe('smtp.sendgrid.net')
  expect(screen.getByText('The password is your SendGrid API key.')).toBeTruthy()
  await userEvent.type(screen.getByLabelText('From address'), 'no-reply@acme.io')
  await userEvent.type(screen.getByLabelText('From name (optional)'), 'Acme')
  await userEvent.type(screen.getByLabelText('Password'), 'SG.key')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toEqual([{ url: `/management/v1${delivery}`, body: {
    provider: 'smtp', from_email: 'no-reply@acme.io', from_name: 'Acme', reply_to: '', smtp_host: 'smtp.sendgrid.net', smtp_port: 587, smtp_tls: 'starttls', smtp_username: 'apikey', smtp_password: 'SG.key', invitation_url: '',
  } }]))
})

it('shows SMTP settings and keeps the stored password on update', async () => {
  config = smtpConfig
  status = { ...status, source: 'environment', provider: 'smtp' }
  open()
  await screen.findByText('smtp.acme.io:587')
  expect(screen.getByText('Acme <no-reply@acme.io>')).toBeTruthy()
  expect(screen.getByText('Password stored')).toBeTruthy()
  expect(screen.queryByText('Message types')).toBeNull()
  expect(screen.getByText('IAMKit’s hosted page')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: /Update/ }))
  const password = screen.getByLabelText('Password') as HTMLInputElement
  expect(password.placeholder).toBe('(unchanged)')
  expect(password.required).toBe(false)
  await userEvent.clear(screen.getByLabelText('From name (optional)'))
  await userEvent.type(screen.getByLabelText('From name (optional)'), 'Acme Mail')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toHaveLength(1))
  const body = calls('PUT')[0].body
  expect(body.from_name).toBe('Acme Mail')
  expect(body).not.toHaveProperty('smtp_password')
})

it('asks for the password again when the SMTP server or account changes', async () => {
  config = smtpConfig
  status = { ...status, source: 'environment', provider: 'smtp' }
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Update/ }))
  const password = screen.getByLabelText('Password') as HTMLInputElement
  await userEvent.clear(screen.getByLabelText('Host'))
  await userEvent.type(screen.getByLabelText('Host'), 'smtp.other.io')
  expect(password.required).toBe(true)
  expect(password.placeholder).toBe('')
  expect(screen.getByText(/only used with the same server and username/)).toBeTruthy()
  await userEvent.clear(screen.getByLabelText('Host'))
  await userEvent.type(screen.getByLabelText('Host'), 'SMTP.acme.io')
  expect(password.required).toBe(false)
  await userEvent.clear(screen.getByLabelText('Username (optional)'))
  expect(password.disabled).toBe(true)
  expect(password.required).toBe(false)
})

it('requires the other provider’s secret when switching provider', async () => {
  config = smtpConfig
  status = { ...status, source: 'environment', provider: 'smtp' }
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Update/ }))
  await userEvent.click(screen.getByRole('radio', { name: /Resend/ }))
  const key = screen.getByLabelText('API key') as HTMLInputElement
  expect(key.required).toBe(true)
  expect(key.placeholder).toBe('re_…')
})

it('saves Resend and explains a missing encryption key', async () => {
  putDelivery = () => Response.json({ error: { code: 'ENCRYPTION_KEY_REQUIRED', message: 'storing secrets requires IAMKIT_ENCRYPTION_KEY to be configured' } }, { status: 422 })
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Configure email delivery/ }))
  await userEvent.click(screen.getByRole('radio', { name: /Resend/ }))
  await userEvent.type(screen.getByLabelText('From address'), 'no-reply@acme.io')
  await userEvent.type(screen.getByLabelText('API key'), 're_123')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  expect((await screen.findByRole('note')).textContent).toContain('IAMKIT_ENCRYPTION_KEY')
  expect(calls('PUT')[0].body).toEqual({ provider: 'resend', from_email: 'no-reply@acme.io', from_name: '', reply_to: '', api_key: 're_123', invitation_url: '' })
})

it('copies settings from another environment without secrets', async () => {
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Configure email delivery/ }))
  await userEvent.selectOptions(await screen.findByLabelText('Copy from environment'), 'env2')
  await waitFor(() => expect((screen.getByLabelText('Host') as HTMLInputElement).value).toBe('smtp.staging.acme.io'))
  expect((screen.getByRole('radio', { name: /SMTP/ }) as HTMLInputElement).checked).toBe(true)
  const password = screen.getByLabelText('Password') as HTMLInputElement
  expect(password.value).toBe('')
  expect(password.required).toBe(true)
})

it('previews emails by purpose and language', async () => {
  config = smtpConfig
  status = { ...status, source: 'environment', provider: 'smtp' }
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Preview/ }))
  const dialog = await screen.findByRole('dialog')
  await waitFor(() => expect(within(dialog).getByLabelText('Preview subject').textContent).toBe('Saved purpose=login'))
  await userEvent.selectOptions(within(dialog).getByLabelText('Email'), 'invitation')
  await userEvent.selectOptions(within(dialog).getByLabelText('Language'), 'es')
  await waitFor(() => expect(within(dialog).getByLabelText('Preview subject').textContent).toBe('Saved purpose=invitation&locale=es'))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Text' }))
  expect(within(dialog).getByLabelText('Plain-text email').textContent).toBe('Your code: 123456')
})

it('edits an email template with a live preview and resets it', async () => {
  config = smtpConfig
  status = { ...status, source: 'environment', provider: 'smtp' }
  open()
  await userEvent.click(await screen.findByRole('button', { name: 'Edit Login code (Español)' }))
  const subject = await screen.findByLabelText('Subject') as HTMLInputElement
  expect(subject.placeholder).toBe(defaults.subject)
  expect(screen.queryByLabelText('Button')).toBeNull()
  await userEvent.type(subject, 'Code for ')
  await userEvent.click(screen.getByRole('button', { name: '{{app_name}}' }))
  expect(subject.value).toBe('Code for {{app_name}}')
  await waitFor(() => expect(screen.getByLabelText('Preview subject').textContent).toBe('Code for Acme'), { timeout: 2000 })
  expect(calls('POST').at(-1)).toMatchObject({ url: `/management/v1${delivery}/preview`, body: { purpose: 'login', locale: 'es', template: { subject: 'Code for {{app_name}}' } } })
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT').at(-1)).toMatchObject({ url: `/management/v1${delivery}/templates/login/es`, body: { subject: 'Code for {{app_name}}', body: '' } }))
  await userEvent.click(await screen.findByRole('button', { name: 'Reset to default' }))
  await userEvent.click(await screen.findByRole('button', { name: 'Reset' }))
  await waitFor(() => expect(calls('DELETE').map(c => c.url)).toEqual([`/management/v1${delivery}/templates/login/es`]))
})

it('shows the server error for an unknown placeholder', async () => {
  const base = fetchMock.getMockImplementation()!
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => init.method === 'PUT' && url.includes('/templates/')
    ? Response.json({ error: { message: 'subject uses unknown placeholder {{name}}; available: app_name, email, code, expires_in' } }, { status: 400 })
    : base(url, init))
  open()
  await userEvent.click(await screen.findByRole('button', { name: 'Edit Login code (English)' }))
  await userEvent.type(await screen.findByLabelText('Subject'), 'Hi {{{{name}}')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  expect((await screen.findByRole('alert')).textContent).toContain('unknown placeholder {{name}}')
})

it('counts characters like the server and blocks saving too-long wording', async () => {
  open()
  await userEvent.click(await screen.findByRole('button', { name: 'Edit Login code (English)' }))
  const subject = await screen.findByLabelText('Subject') as HTMLInputElement
  await userEvent.type(subject, '  🔐 Hi  ')
  expect(subject.getAttribute('aria-describedby')).toBe('template-subject-count')
  expect(document.getElementById('template-subject-count')!.textContent).toBe('4/200 characters')
  await userEvent.clear(subject)
  await userEvent.click(subject)
  await userEvent.paste('é'.repeat(201))
  expect(subject.getAttribute('aria-invalid')).toBe('true')
  expect(document.getElementById('template-subject-count')!.textContent).toBe('201/200 characters, too long')
  expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true)
})

it('announces preview updates and asks before discarding template edits', async () => {
  open()
  await userEvent.click(await screen.findByRole('button', { name: 'Edit Login code (English)' }))
  const subject = await screen.findByLabelText('Subject')
  await waitFor(() => expect(screen.getByRole('status').textContent).toMatch(/^Preview updated\. Subject: /), { timeout: 2000 })
  await userEvent.type(subject, 'Draft')
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  const confirm = await screen.findByRole('dialog', { name: 'Discard changes?' })
  await userEvent.click(within(confirm).getByRole('button', { name: 'Cancel' }))
  expect((screen.getByLabelText('Subject') as HTMLInputElement).value).toBe('Draft')
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  await userEvent.click(within(await screen.findByRole('dialog', { name: 'Discard changes?' })).getByRole('button', { name: 'Discard' }))
  await waitFor(() => expect(screen.queryByLabelText('Subject')).toBeNull())
})

it('asks before discarding delivery changes and links hints to fields', async () => {
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Configure email delivery/ }))
  const url = screen.getByLabelText('Webhook URL')
  expect(document.getElementById(url.getAttribute('aria-describedby')!)!.textContent).toContain('Must be HTTPS')
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  await waitFor(() => expect(screen.queryByLabelText('Webhook URL')).toBeNull())
  await userEvent.click(await screen.findByRole('button', { name: /Configure email delivery/ }))
  await userEvent.type(screen.getByLabelText('Webhook URL'), 'https://x.io')
  await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(await screen.findByRole('dialog', { name: 'Discard changes?' })).toBeTruthy()
})

it('shows an Edit button per email and edits the app name with the wording', async () => {
  open()
  const edit = await screen.findByRole('button', { name: 'Edit Invitation (English)' })
  expect(edit.textContent).toContain('Edit')
  await userEvent.click(edit)
  const name = await screen.findByLabelText('App name') as HTMLInputElement
  expect(name.value).toBe('Acme')
  expect(document.getElementById(name.getAttribute('aria-describedby')!)!.textContent).toContain('every email')
  await userEvent.clear(name)
  await userEvent.type(name, 'Globex')
  await waitFor(() => expect(screen.getByLabelText('Preview subject').textContent).toBe('Your sign-in code for Globex'), { timeout: 2000 })
  expect(calls('POST').at(-1)!.body).toMatchObject({ purpose: 'invitation', locale: 'en', app_name: 'Globex' })
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  // Only the name changed: the branding is saved (language untouched), not the template.
  await waitFor(() => expect(calls('PUT').map(c => c.url)).toEqual(['/management/v1/environments/env1/login-settings']))
  const saved = calls('PUT')[0].body
  expect(saved).toMatchObject({ display_name: 'Globex', accent_color: '#2563eb', theme: { mode: 'dark' } })
  expect(saved).not.toHaveProperty('locale')
  await userEvent.clear(name)
  await userEvent.paste('é'.repeat(101))
  expect(name.getAttribute('aria-invalid')).toBe('true')
  expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true)
})

it('explains what the invitation page is for', async () => {
  open()
  expect((await screen.findByText(/emails them a link to this page, where they accept the invitation/)).textContent).toContain('an existing one joins')
  await userEvent.click(await screen.findByRole('button', { name: /Configure email delivery/ }))
  const field = screen.getByLabelText('Invitation page (optional)')
  const described = field.getAttribute('aria-describedby')!.split(' ').map(id => document.getElementById(id)!.textContent).join(' ')
  expect(described).toContain('where they accept')
  expect(described).toContain('Empty: your webhook gets the token but no link.')
  expect(field.getAttribute('autocomplete')).toBe('off')
  await userEvent.click(screen.getByRole('radio', { name: /SMTP/ }))
  expect(document.getElementById('invitation-url-hint')!.textContent).toContain('Empty: the email links to IAMKit’s hosted invitation page.')
})

it('lets viewers see templates without editing them', async () => {
  role = 'viewer'
  open()
  await userEvent.click(await screen.findByRole('button', { name: 'View Login code (English)' }))
  expect((await screen.findByLabelText('Subject')).matches(':disabled')).toBe(true)
  expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
  await waitFor(() => expect(screen.getByLabelText('Preview subject').textContent).toBe('Saved purpose=login&locale=en'), { timeout: 2000 })
  expect(calls('POST')).toEqual([])
})
