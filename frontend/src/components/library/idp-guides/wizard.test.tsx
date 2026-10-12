// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { GuidedSetupDialog, type GuidedTransport } from './wizard'
import { ScimGuides } from './guide-view'
import { ldapGuide, oidcGuides, samlGuides, scimGuides } from './guides'

const open = vi.fn()
const sp = { entity_id: 'https://iam.example/sp/env1/c1', acs_url: 'https://iam.example/identity/v1/federation/saml/acs', metadata_url: 'https://iam.example/identity/v1/federation/saml/metadata/env1/c1' }

function transport(over: Partial<GuidedTransport> = {}): GuidedTransport {
  return {
    create: vi.fn(async () => ({ id: 'c1' })),
    find: vi.fn(async () => ({ draft: true, saml: sp })),
    update: vi.fn(async () => undefined),
    test: vi.fn(async () => ({ url: 'https://iam.example/identity/v1/federation/test/env1/c1?ticket=ik_fedtest_x', expires_at: '2099-01-01T00:00:00Z' })),
    enable: vi.fn(async () => undefined),
    ...over,
  }
}

function dialog(t: GuidedTransport, extra: { onDone?: () => void; onAdvanced?: () => void } = {}) {
  render(<GuidedSetupDialog base="" organization={{ id: 'org1', name: 'Acme' }} transport={t} onClose={() => {}} onDone={extra.onDone ?? (() => {})} onAdvanced={extra.onAdvanced ?? (() => {})} />)
}

beforeEach(() => {
  vi.stubGlobal('open', open)
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({ issuer: 'https://iam.example' })))
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.clearAllMocks() })

it('ships every guide the product promises, each with steps, attributes and troubleshooting', () => {
  expect(samlGuides.map(g => g.label)).toEqual(['Okta', 'Microsoft Entra ID', 'Google Workspace', 'OneLogin', 'JumpCloud', 'ADFS', 'PingFederate', 'Generic SAML'])
  expect(oidcGuides.map(g => g.id)).toEqual(['okta-oidc', 'entra-oidc', 'google-oidc', 'generic-oidc'])
  expect(scimGuides.map(g => g.id)).toEqual(['okta-scim', 'entra-scim'])
  for (const g of [...samlGuides, ...oidcGuides, ldapGuide, ...scimGuides]) {
    expect(g.steps.length).toBeGreaterThan(0)
    expect(g.attributes.length).toBeGreaterThan(0)
    expect(g.troubleshooting.length).toBeGreaterThan(0)
  }
  // Every SAML guide hands the IdP the ACS URL and the entity ID (or the metadata URL).
  for (const g of samlGuides) expect(g.steps.flatMap(s => s.values ?? [])).toEqual(expect.arrayContaining(['acs']))
  for (const g of oidcGuides) expect(g.steps.flatMap(s => s.values ?? [])).toContain('redirect_uri')
})

it('creates a SAML draft on picking a provider, shows the IAMKit values and saves the pasted metadata', async () => {
  const user = userEvent.setup()
  const t = transport()
  dialog(t)
  await user.click(screen.getByRole('button', { name: 'Okta' }))
  await user.click(screen.getByRole('button', { name: 'Continue' }))

  await waitFor(() => expect(t.create).toHaveBeenCalledWith({ provider: 'saml', name: 'Okta', organization_id: 'org1', draft: true, options: {} }))
  expect(t.find).toHaveBeenCalledWith('c1')
  // The values to copy into the IdP, with copy buttons.
  expect(await screen.findByText(sp.acs_url)).toBeTruthy()
  expect(screen.getByText(sp.entity_id)).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Copy ACS URL (HTTP-POST)' })).toBeTruthy()

  await user.click(screen.getByRole('button', { name: 'I have done this' }))
  await user.type(screen.getByLabelText('Identity provider metadata URL'), 'https://acme.okta.example/app/x/sso/saml/metadata')
  await user.click(screen.getByRole('button', { name: 'Save metadata' }))
  await waitFor(() => expect(t.update).toHaveBeenCalledWith('c1', { options: { metadata_url: 'https://acme.okta.example/app/x/sso/saml/metadata' } }))
})

it('asks for metadata before saving and sends pasted XML as metadata_xml', async () => {
  const user = userEvent.setup()
  const t = transport()
  dialog(t)
  await user.click(within(screen.getByRole('group', { name: 'SAML 2.0' })).getByRole('button', { name: 'Google Workspace' }))
  await user.click(screen.getByRole('button', { name: 'Continue' }))
  await user.click(await screen.findByRole('button', { name: 'I have done this' }))
  await user.click(screen.getByRole('button', { name: 'Save metadata' }))
  expect(await screen.findByText('Paste the metadata URL or the metadata XML of your identity provider.')).toBeTruthy()
  expect(t.update).not.toHaveBeenCalled()

  await user.click(screen.getByLabelText('Or the metadata XML'))
  await user.paste('<EntityDescriptor entityID="https://idp.example"/>')
  await user.click(screen.getByRole('button', { name: 'Save metadata' }))
  await waitFor(() => expect(t.update).toHaveBeenCalledWith('c1', { options: { metadata_xml: '<EntityDescriptor entityID="https://idp.example"/>' } }))
})

it('tests in a new tab, then enables with the chosen enforcement', async () => {
  const user = userEvent.setup()
  const t = transport()
  const done = vi.fn()
  dialog(t, { onDone: done })
  await user.click(within(screen.getByRole('group', { name: 'SAML 2.0' })).getByRole('button', { name: 'Microsoft Entra ID' }))
  await user.click(screen.getByRole('button', { name: 'Continue' }))
  await user.click(await screen.findByRole('button', { name: 'I have done this' }))
  await user.type(screen.getByLabelText('Identity provider metadata URL'), 'https://login.example/meta')
  await user.click(screen.getByRole('button', { name: 'Save metadata' }))

  await user.click(await screen.findByRole('button', { name: 'Test connection' }))
  await waitFor(() => expect(open).toHaveBeenCalledWith('https://iam.example/identity/v1/federation/test/env1/c1?ticket=ik_fedtest_x', '_blank', 'noopener'))

  await user.selectOptions(screen.getByLabelText('Sign-in mode'), 'enforced')
  await user.click(screen.getByRole('button', { name: 'Enable connection' }))
  await waitFor(() => expect(t.enable).toHaveBeenCalledWith('c1'))
  expect(t.update).toHaveBeenLastCalledWith('c1', { enforcement: 'enforced' })
  expect(done).toHaveBeenCalled()
})

it('shows the redirect URI for OIDC, creates the connection from the pasted credentials and never creates a draft', async () => {
  const user = userEvent.setup()
  const t = transport()
  dialog(t)
  await user.click(screen.getByRole('button', { name: 'Okta (OIDC)' }))
  await user.click(screen.getByRole('button', { name: 'Continue' }))
  expect(await screen.findByText('https://iam.example/identity/v1/federation/callback')).toBeTruthy()
  expect(t.create).not.toHaveBeenCalled()

  await user.click(screen.getByRole('button', { name: 'I have done this' }))
  await user.type(screen.getByLabelText('Issuer URL'), 'https://acme.okta.example')
  await user.type(screen.getByLabelText('Client ID'), 'client-1')
  await user.type(screen.getByLabelText('Client secret'), 'pasted-value')
  await user.click(screen.getByRole('button', { name: 'Save and continue' }))
  await waitFor(() => expect(t.create).toHaveBeenCalledWith(expect.objectContaining({ provider: 'oidc', name: 'Okta (OIDC)', organization_id: 'org1', issuer: 'https://acme.okta.example', client_id: 'client-1', client_secret: 'pasted-value' })))
  expect(await screen.findByRole('button', { name: 'Test connection' })).toBeTruthy()
})

it('keeps the old form reachable as Advanced', async () => {
  const user = userEvent.setup()
  const advanced = vi.fn()
  dialog(transport(), { onAdvanced: advanced })
  await user.click(screen.getByRole('button', { name: 'Advanced' }))
  expect(advanced).toHaveBeenCalled()
})

it('shows the SCIM URL in the directory guides, and the token once one was issued', async () => {
  const user = userEvent.setup()
  const { rerender } = render(<ScimGuides url="https://iam.example/scim/v2" />)
  await user.selectOptions(screen.getByLabelText('Directory guide'), 'okta-scim')
  expect(screen.getByText('https://iam.example/scim/v2')).toBeTruthy()
  expect(screen.getByText(/shown once when you add a token/)).toBeTruthy()
  rerender(<ScimGuides url="https://iam.example/scim/v2" token="ik_scim_example" />)
  expect(screen.getByText('ik_scim_example')).toBeTruthy()
})
