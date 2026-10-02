import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { UnsavedChangesGuard } from '@/components/library/unsaved-changes'
import type { ReactNode } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Monitor, Moon, Plus, Smartphone, Sun, Trash2, TriangleAlert } from 'lucide-react'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { cn, message } from '@/lib/utils'
import { body, defaults, emailForm, emptyBranding, emptyLegal, fonts, hex, methodPages, normalize, pages, resolved, same, sampleButtons, warnings } from '@/lib/branding'
import type { Branding, Font, Legal, Page, Palette, PreviewButton, PreviewMethods, Scheme, Theme } from '@/lib/branding'
import { localeLabel, type Locale } from '@/lib/delivery'
import { everyMethod, type SignIn } from './sign-in-options'
import { Button, buttonVariants } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog, ErrorState, PageHeader } from '@/components/library/patterns'
import { clientName, PreviewFrame } from '@/components/library/preview-frame'
import { t } from '@/lib/i18n'

interface Client { id: string; application_name: string; resource_name: string; hosted_login: boolean }

const selectClass = 'h-8 w-full rounded-lg border border-input bg-background px-2 text-sm disabled:opacity-50'

function Field({ label, hint, children, id }: { label: string; hint?: string; children: ReactNode; id: string }) {
  return <div className="space-y-1.5">
    <label className="text-sm font-medium" htmlFor={id}>{label}</label>
    {children}
    {hint && <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint}</p>}
  </div>
}

function Section({ title, open, children }: { title: string; open?: boolean; children: ReactNode }) {
  return <details open={open} className="group rounded-lg border">
    <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-3 font-mono text-sm font-medium select-none">
      {title}<span className="text-muted-foreground transition-transform group-open:rotate-90">›</span>
    </summary>
    <div className="space-y-4 border-t px-4 py-4">{children}</div>
  </details>
}

// useLocales lists the languages of the hosted pages and emails (null
// while loading; failed when the list could not be loaded).
function useLocales(environment?: string) {
  const [locales, setLocales] = useState<Locale[] | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    api.get<{ items: Locale[] }>(`/environments/${environment}/login-settings/locales`)
      .then(r => { setLocales(r?.items ?? []); setFailed(false) }).catch(() => setFailed(true))
  }, [environment])
  return { locales, failed }
}

// LanguageSettings: the environment default chooses the languages hosted
// pages may use and its default (pages and the emails IAMKit writes); a
// client style or an organization picks its own default among them.
function LanguageSettings({ draft, set, environmentDefault, enabled }: { draft: Branding; set: (patch: Partial<Branding>) => void; environmentDefault: boolean; enabled?: string[] }) {
  const { environment } = useParams()
  const { locales, failed } = useLocales(environment)
  // The saved language stays selectable (and visible) even when the list
  // failed to load or no longer offers it, so saving never changes it silently.
  const current = draft.locale ?? ''
  const languages = environmentDefault ? draft.languages ?? [] : enabled ?? []
  const offered = locales?.filter(l => !languages.length || languages.includes(l.code))
  const retired = !!current && !!locales && !locales.some(l => l.code === current)
  const unlisted = current && !offered?.some(l => l.code === current)
  const hint = environmentDefault
    ? t('Sign-in pages and emails use this language unless the application asks for another (ui_locales). Automatic: pages follow the visitor’s browser, emails the server default.')
    : t('Sign-in pages use this language unless the application asks for another (ui_locales). Inherited: the environment’s language applies.')
  const problem = failed ? t(' The list of languages could not be loaded.')
    : retired ? ' ' + (environmentDefault ? t('“{{current}}” is no longer available; the automatic language applies until you choose another.', { current }) : t('“{{current}}” is no longer available; the inherited language applies until you choose another.', { current }))
      : unlisted && locales ? ' ' + (environmentDefault ? t('“{{current}}” is not an enabled language; the automatic language applies until you choose another.', { current }) : t('“{{current}}” is not an enabled language; the inherited language applies until you choose another.', { current })) : ''
  const toggle = (code: string, on: boolean) => {
    const next = on ? [...languages, code] : languages.filter(c => c !== code)
    // Every language enabled is the same as none listed: all of them.
    set({ languages: locales && next.length === locales.length ? [] : next })
  }
  return <Section title={t('Language')} open>
    <Field id="locale" label={t('Language')} hint={hint + problem}>
      <select id="locale" aria-describedby="locale-hint" className={selectClass} value={current} onChange={e => set({ locale: e.target.value })}>
        <option value="">{environmentDefault ? t('Automatic') : t('Inherited')}</option>
        {unlisted && <option value={current}>{retired || !locales ? (locales ? t('{{current}} (not available)', { current }) : current) : t('{{value}} (not enabled)', { value: locales.find(l => l.code === current)?.name ?? current })}</option>}
        {offered?.map(l => <option key={l.code} value={l.code}>{localeLabel(l)}</option>)}
      </select>
    </Field>
    {environmentDefault && locales && locales.length > 1 && <fieldset className="space-y-2">
      <legend className="text-sm font-medium">{t('Enabled languages')}</legend>
      <p className="text-xs text-muted-foreground">{t('Visitors only see these languages, whatever their browser or the application asks for. None checked: every language.')}</p>
      <div className="grid grid-cols-2 gap-1.5">
        {locales.map(l => <label key={l.code} className="flex items-center gap-2 text-sm">
          <input type="checkbox" className="size-4 accent-primary" checked={languages.includes(l.code)}
            disabled={l.code === current && languages.includes(l.code)}
            onChange={e => toggle(l.code, e.target.checked)} />
          {localeLabel(l)}
        </label>)}
      </div>
    </fieldset>}
  </Section>
}

function ColorInput({ label, value, fallback, onChange }: { label: string; value: string; fallback: string; onChange: (v: string) => void }) {
  return <div className="flex items-center gap-1.5">
    <input type="color" aria-label={t('Pick a color for {{field}}', { field: label })} className="h-8 w-9 shrink-0 cursor-pointer rounded-md border bg-transparent p-0.5 disabled:cursor-not-allowed"
      value={hex.test(value) ? value.toLowerCase() : fallback} onChange={e => onChange(e.target.value)} />
    <Input aria-label={label} className="font-mono" value={value} placeholder={fallback} maxLength={7} spellCheck={false} onChange={e => onChange(e.target.value.trim())} />
  </div>
}

const colorRows: [keyof Palette, string][] = [['primary', t('Primary')], ['background', t('Page background')], ['card', t('Card')], ['text', t('Text')], ['header', t('Header')]]

// BrandingEditorPage edits the environment default (no clientId) or one
// OAuth client's style, with a live preview of the real hosted pages.
export default function BrandingEditorPage() {
  const { project, environment, clientId } = useParams()
  const navigate = useNavigate()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const base = `/environments/${environment}/login-settings`
  const path = clientId ? `${base}/clients/${clientId}` : base
  const back = `/projects/${project}/environments/${environment}/hosted-login`

  const [saved, setSaved] = useState<Branding | null>(null) // null: client without its own style yet
  const [draft, setDraft] = useState<Branding | null>(null)
  const [client, setClient] = useState<Client>()
  // The environment's enabled languages, offered to a client style.
  const [enabled, setEnabled] = useState<string[]>([])
  const [loadError, setLoadError] = useState('')
  const [saveError, setSaveError] = useState('')
  const [busy, setBusy] = useState(false)
  const [reset, setReset] = useState(false)
  const pending = useRef(false)
  // Set while leaving on purpose (Discard of a new style, Reset) so the
  // unsaved-changes guard does not ask again.
  const discarding = useRef(false)

  const load = () => {
    setLoadError('')
    const own = api.get<Branding>(path).then(normalize)
    const fallback = clientId ? own.catch(async e => {
      if (!(e instanceof ApiError && e.status === 404)) throw e
      return null
    }) : own
    Promise.all([fallback, clientId ? api.get<Branding>(base).then(normalize) : Promise.resolve(null)]).then(([style, environmentDefault]) => {
      setSaved(style)
      setEnabled(environmentDefault?.languages ?? [])
      // A new client style starts as a copy of the environment default
      // (its own language: inherited).
      setDraft(style ?? { ...(environmentDefault ?? emptyBranding()), client_id: clientId, updated_at: undefined, locale: '', languages: undefined })
    }).catch(e => setLoadError(message(e)))
    if (clientId) api.get<{ items: Client[] }>(`/environments/${environment}/oauth-clients?limit=100`).then(r => setClient(r.items.find(c => c.id === clientId))).catch(() => {})
  }
  useEffect(load, [path])

  const dirty = !!draft && (!saved || !same(draft, saved))
  const guard = <UnsavedChangesGuard when={dirty && canWrite} bypass={discarding} message={t('Your style changes have not been saved.')} />

  const title = clientId ? `Style: ${clientName(client) || clientId}` : t('Default style')
  const description = clientId ? t('Sign-in pages of this OAuth client; an organization’s own branding lays over it. Invitation pages use the default style.') : t('Used by every hosted sign-in and invitation page, unless an OAuth client has its own style. Organizations can override parts of it (organization › Branding).')
  const header = <PageHeader title={title} description={description} actions={<Link to={back} className={buttonVariants({ variant: 'outline' })}><ArrowLeft className="size-4" /> {t('Branding')}</Link>} />
  if (loadError) return <div className="space-y-6">{header}<ErrorState error={loadError} retry={load} /></div>
  if (!draft) return <div className="space-y-6">{header}<p role="status" className="text-sm text-muted-foreground">{t('Loading…')}</p></div>

  const save = async () => {
    if (pending.current) return
    pending.current = true; setBusy(true); setSaveError('')
    try {
      const out = normalize(await api.put<Branding>(path, body(draft)))
      setSaved(out); setDraft(out); toast.success(clientId ? t('Client style saved') : t('Default style saved'))
    } catch (e) { setSaveError(message(e)) } finally { pending.current = false; setBusy(false) }
  }

  return <div className="space-y-6 pb-20">
    {guard}
    {header}
    {clientId && !saved && <div role="status" className="rounded-lg border border-dashed px-4 py-3 text-sm text-muted-foreground">
      {t('This client uses the default style. The editor starts from a copy of it; saving gives the client its own style.')}
    </div>}
    <div className="grid items-start gap-6 xl:grid-cols-[minmax(340px,420px)_1fr]">
      <Settings draft={draft} setDraft={setDraft} canWrite={canWrite} environmentDefault={!clientId} enabled={enabled} />
      <Preview environment={environment!} clientId={clientId} draft={draft} live={canWrite} savedStyle={!!saved}
        onAdaptive={canWrite ? () => setDraft({ ...draft, theme: { ...draft.theme, mode: 'adaptive' } }) : undefined} />
    </div>
    {saveError && <ErrorState error={saveError} />}
    {clientId && saved && canWrite && <div className="flex justify-start">
      <Button variant="outline" onClick={() => setReset(true)}><Trash2 className="size-4" /> {t('Reset to default style')}</Button>
    </div>}
    {canWrite && dirty && <div className="fixed inset-x-0 bottom-0 z-40 border-t bg-background/95 backdrop-blur md:left-(--sidebar-width)">
      <div className="mx-auto flex max-w-screen-2xl items-center justify-between gap-4 px-6 py-3">
        <span className="text-sm text-muted-foreground">{saved ? t('Unsaved changes') : t('New client style (not saved)')}</span>
        <div className="flex gap-2">
          <Button variant="outline" disabled={busy} onClick={() => { setSaveError(''); if (saved) setDraft(saved); else { discarding.current = true; navigate(back) } }}>{t('Discard')}</Button>
          <Button disabled={busy} onClick={() => void save()}>{busy ? t('Saving…') : t('Save')}</Button>
        </div>
      </div>
    </div>}
    {reset && <ConfirmDialog title={t('Reset to the default style?')} description={t('The client\'s own style is deleted and its sign-in pages use the environment default again.')} confirmLabel={t('Reset')} onClose={() => setReset(false)}
      confirm={async () => { await api.delete(path); toast.success(t('Client style reset')); discarding.current = true; navigate(back) }} />}
  </div>
}

// OrgMode adapts the editor to an organization's overrides: empty fields
// inherit (placeholders show what), and the theme is either inherited or
// the organization's own.
interface OrgMode { own: boolean; setOwn: (own: boolean) => void; inherited: Branding }

export function Settings({ draft, setDraft, canWrite, environmentDefault, org, enabled }: { draft: Branding; setDraft: (b: Branding) => void; canWrite: boolean; environmentDefault: boolean; org?: OrgMode; enabled?: string[] }) {
  const id = useId()
  const th = draft.theme
  const set = (patch: Partial<Branding>) => setDraft({ ...draft, ...patch })
  const theme = (patch: Partial<Theme>) => setDraft({ ...draft, theme: { ...th, ...patch } })
  const color = (scheme: Scheme, key: keyof Palette, value: string) => theme({ [scheme]: { ...th[scheme], [key]: value } })
  const schemes: Scheme[] = th.mode === 'adaptive' ? ['light', 'dark'] : [th.mode]
  const links = th.footer.links
  const setLinks = (next: typeof links) => theme({ footer: { ...th.footer, links: next } })
  const lightPrimary = resolved(draft, 'light').primary
  const issues = schemes.flatMap(s => warnings(draft, s).map(w => schemes.length > 1 ? (s === 'light' ? t('Light: {{warning}}', { warning: w }) : t('Dark: {{warning}}', { warning: w })) : w))
  const themed = !org || org.own
  const inherited = (value: string) => value ? t('Inherited: {{value}}', { value }) : t('Inherited')

  return <fieldset disabled={!canWrite} className="min-w-0 space-y-3">
    <legend className="sr-only">{t('Style settings')}</legend>
    <Section title={t('Brand')} open>
      <Field id={`${id}-name`} label={t('Display name')} hint={org ? t('Shown under the logo and in the browser tab. Empty: inherited.') : t('Shown under the logo and in the browser tab.')}>
        <Input id={`${id}-name`} maxLength={100} value={draft.display_name} placeholder={org ? inherited(org.inherited.display_name) : t('Acme')} onChange={e => set({ display_name: e.target.value })} />
      </Field>
      <Field id={`${id}-logo`} label={t('Logo URL')} hint={org ? t('HTTPS only. Shown at up to 200×48 px. Empty: inherited.') : t('HTTPS only. Shown at up to 200×48 px.')}>
        <Input id={`${id}-logo`} type="url" value={draft.logo_url} placeholder={org ? inherited(org.inherited.logo_url) : 'https://cdn.example.com/logo.png'} onChange={e => set({ logo_url: e.target.value.trim() })} />
      </Field>
      {org && !org.own && <Field id={`${id}-accent`} label={t('Primary color')} hint={t('Buttons and links. Empty: inherited.')}>
        <ColorInput label={t('Primary color')} value={draft.accent_color} fallback={resolved(org.inherited, 'light').primary} onChange={v => set({ accent_color: v })} />
      </Field>}
      {themed && th.mode !== 'light' && <Field id={`${id}-logo-dark`} label={t('Dark mode logo URL')} hint={t('Optional. Replaces the logo on dark pages.')}>
        <Input id={`${id}-logo-dark`} type="url" value={th.logo_dark_url} placeholder="https://cdn.example.com/logo-dark.png" onChange={e => theme({ logo_dark_url: e.target.value.trim() })} />
      </Field>}
      {themed && <Field id={`${id}-favicon`} label={t('Favicon URL')} hint={t('HTTPS only. ICO, PNG or SVG.')}>
        <Input id={`${id}-favicon`} type="url" value={th.favicon_url} placeholder="https://cdn.example.com/favicon.ico" onChange={e => theme({ favicon_url: e.target.value.trim() })} />
      </Field>}
    </Section>
    <LanguageSettings draft={draft} set={set} environmentDefault={environmentDefault} enabled={enabled} />
    {org && <label className="flex items-start gap-2 rounded-lg border px-4 py-3 text-sm">
      <input type="checkbox" className="mt-0.5 size-4 accent-primary" checked={org.own}
        onChange={e => { if (e.target.checked) setDraft({ ...draft, theme: org.inherited.theme }); org.setOwn(e.target.checked) }} />
      <span><span className="font-medium">{t('Customize the theme')}</span><span className="block text-xs text-muted-foreground">{t('Off: the theme (mode, colors, header, footer) of the client or environment applies. On: the organization\'s own, starting from a copy of the environment default.')}</span></span>
    </label>}
    {themed && <>

    <Section title={t('Theme')} open>
      <Field id={`${id}-mode`} label={t('Mode')} hint={th.mode === 'adaptive' ? t('Follows the light or dark setting of the visitor’s device.') : undefined}>
        <select id={`${id}-mode`} className={selectClass} value={th.mode} onChange={e => theme({ mode: e.target.value as Theme['mode'] })}>
          <option value="light">{t('Light')}</option><option value="dark">{t('Dark')}</option><option value="adaptive">{t('Adaptive (browser setting)')}</option>
        </select>
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field id={`${id}-spacing`} label={t('Spacing')}>
          <select id={`${id}-spacing`} className={selectClass} value={th.spacing} onChange={e => theme({ spacing: e.target.value as Theme['spacing'] })}>
            <option value="compact">{t('Compact')}</option><option value="normal">{t('Normal')}</option><option value="roomy">{t('Roomy')}</option>
          </select>
        </Field>
        <Field id={`${id}-align`} label={t('Form position')}>
          <select id={`${id}-align`} className={selectClass} value={th.align} onChange={e => theme({ align: e.target.value as Theme['align'] })}>
            <option value="left">{t('Left')}</option><option value="center">{t('Center')}</option><option value="right">{t('Right')}</option>
          </select>
        </Field>
      </div>
      <Field id={`${id}-radius`} label={t('Corner radius: {{radius}}px', { radius: th.radius })}>
        <input id={`${id}-radius`} type="range" min={0} max={24} step={1} value={th.radius} className="w-full accent-primary" onChange={e => theme({ radius: Number(e.target.value) })} />
      </Field>
      <Field id={`${id}-background`} label={t('Background image URL')} hint={t('Optional. HTTPS only; covers the page behind the form. Use a wide image (1920 px or more).')}>
        <Input id={`${id}-background`} type="url" value={th.background_image_url} placeholder="https://cdn.example.com/background.jpg"
          onChange={e => theme({ background_image_url: e.target.value.trim() })} />
      </Field>
      {th.background_image_url && <Field id={`${id}-overlay`} label={t('Background tint: {{background_overlay}}%', { background_overlay: th.background_overlay })} hint={t('Covers the image with the page background color (light or dark), so the header and footer stay readable.')}>
        <input id={`${id}-overlay`} type="range" min={0} max={90} step={5} value={th.background_overlay} className="w-full accent-primary" onChange={e => theme({ background_overlay: Number(e.target.value) })} />
      </Field>}
    </Section>

    <Section title={t('Fonts')}>
      <FontField id={`${id}-font`} label={t('Text font')} value={th.font} onChange={font => theme({ font })} />
      <FontField id={`${id}-heading-font`} label={t('Heading font')} value={th.heading_font} heading onChange={heading_font => theme({ heading_font })} />
      <p className="text-xs text-muted-foreground">{t('Inter, Roboto, Open Sans and Lora are served by IAMKit itself: no request to a third party. A custom font loads from your HTTPS URL (WOFF2).')}</p>
    </Section>

    <Section title={t('Colors')} open>
      <p className="text-xs text-muted-foreground">{t('Empty colors use the default shown as placeholder.')}{th.mode === 'adaptive' ? (' ' + t('Adaptive pages use the light column or the dark column following the device.')) : ''}</p>
      <div className={cn('grid gap-x-3 gap-y-2', schemes.length > 1 ? 'grid-cols-[auto_1fr_1fr]' : 'grid-cols-[auto_1fr]')}>
        <span />{schemes.map(s => <span key={s} className="text-xs font-medium text-muted-foreground">{s === 'light' ? t('Light') : t('Dark')}</span>)}
        {colorRows.map(([key, label]) => <div key={key} className="contents">
          <span className="self-center text-sm">{label}</span>
          {schemes.map(s => {
            const fallback = key === 'primary' ? (s === 'light' ? defaults.light.primary : lightPrimary) : key === 'header' ? resolved(draft, s).card : defaults[s][key]
            return <ColorInput key={s} label={`${s === 'light' ? t('Light') : t('Dark')} ${label.toLowerCase()}`} value={th[s][key]} fallback={fallback} onChange={v => color(s, key, v)} />
          })}
        </div>)}
      </div>
      {issues.length > 0 && <ul aria-label={t('Contrast warnings')} className="space-y-1 rounded-lg bg-warning/10 p-3 text-xs text-warning-foreground">
        {issues.map(w => <li key={w} className="flex gap-1.5"><TriangleAlert className="mt-px size-3.5 shrink-0 text-warning" />{w}</li>)}
      </ul>}
    </Section>

    <Section title={t('Header & footer')}>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" className="size-4 accent-primary" checked={th.header.show} onChange={e => theme({ header: { show: e.target.checked }, logo_position: e.target.checked ? th.logo_position : 'card' })} />
        {t('Show a header bar')}
      </label>
      {th.header.show && <Field id={`${id}-position`} label={t('Logo and name')}>
        <select id={`${id}-position`} className={selectClass} value={th.logo_position} onChange={e => theme({ logo_position: e.target.value as Theme['logo_position'] })}>
          <option value="card">{t('In the card')}</option><option value="header">{t('In the header')}</option>
        </select>
      </Field>}
      <Field id={`${id}-footer`} label={t('Footer text')} hint={t('Optional, up to 200 characters.')}>
        <Input id={`${id}-footer`} maxLength={200} value={th.footer.text} placeholder={t('© Acme Inc.')} onChange={e => theme({ footer: { ...th.footer, text: e.target.value } })} />
      </Field>
      <div className="space-y-2">
        <p className="text-sm font-medium">{t('Footer links')}</p>
        {links.map((l, i) => <div key={i} className="flex gap-1.5">
          <Input aria-label={t('Link {{value}} label', { value: i + 1 })} className="w-32 shrink-0" maxLength={40} value={l.label} placeholder={t('Privacy')} onChange={e => setLinks(links.map((x, j) => j === i ? { ...x, label: e.target.value } : x))} />
          <Input aria-label={t('Link {{value}} URL', { value: i + 1 })} value={l.url} placeholder="https://acme.example/privacy" onChange={e => setLinks(links.map((x, j) => j === i ? { ...x, url: e.target.value.trim() } : x))} />
          <Button type="button" variant="ghost" size="icon" aria-label={t('Remove link {{value}}', { value: i + 1 })} onClick={() => setLinks(links.filter((_, j) => j !== i))}><Trash2 className="size-4" /></Button>
        </div>)}
        {links.length < 5 && <Button type="button" variant="outline" size="sm" onClick={() => setLinks([...links, { label: '', url: '' }])}><Plus className="size-3.5" /> {t('Add link')}</Button>}
        <p className="text-xs text-muted-foreground">{t('Up to 5 links (HTTPS or mailto). They open in a new tab.')}</p>
      </div>
    </Section>
    </>}
    {!org && <LegalSettings legal={draft.legal ?? emptyLegal()} inherit={!environmentDefault} onChange={legal => set({ legal })} />}
  </fieldset>
}

function FontField({ id, label, value, heading, onChange }: { id: string; label: string; value: Font; heading?: boolean; onChange: (f: Font) => void }) {
  return <div className="space-y-2">
    <Field id={id} label={label}>
      <select id={id} className={selectClass} value={value.family} onChange={e => onChange(e.target.value === 'custom' ? { family: 'custom', url: value.url ?? '' } : { family: e.target.value })}>
        {fonts.map(([family, name]) => <option key={family} value={family}>{family === 'system' && heading ? t('Same as text') : name}</option>)}
      </select>
    </Field>
    {value.family === 'custom' && <Input aria-label={`${label} URL`} type="url" value={value.url ?? ''} placeholder="https://cdn.example.com/brand.woff2" onChange={e => onChange({ family: 'custom', url: e.target.value.trim() })} />}
  </div>
}

// LegalSettings edits the policy links of the sign-in and sign-up pages.
function LegalSettings({ legal, inherit, onChange }: { legal: Legal; inherit: boolean; onChange: (l: Legal) => void }) {
  const id = useId()
  const fields: [keyof Legal, string, string][] = [
    ['privacy_url', t('Privacy policy URL'), 'https://acme.example/privacy'], ['terms_url', t('Terms of service URL'), 'https://acme.example/terms'],
    ['help_url', t('Help URL'), 'https://help.acme.example'], ['support_email', t('Support email'), 'support@acme.example'],
  ]
  return <Section title={t('Legal links')}>
    <p className="text-xs text-muted-foreground">{t('Shown under the sign-in and sign-up forms. The terms are linked from the sign-up checkbox when the sign-in methods require accepting them.')}{inherit ? (' ' + t('Empty: the environment default’s.')) : ''}</p>
    {fields.map(([key, label, placeholder]) => <Field key={key} id={`${id}-${key}`} label={label} hint={key === 'support_email' ? undefined : t('HTTPS only.')}>
      <Input id={`${id}-${key}`} type={key === 'support_email' ? 'email' : 'url'} value={legal[key]} placeholder={placeholder} onChange={e => onChange({ ...legal, [key]: e.target.value.trim() })} />
    </Field>)}
  </Section>
}

// Preview renders the draft with the real page templates. Viewers see the
// saved style (they cannot change it, and drafts are a write operation).
// With organization set, the preview shows the organization's overrides:
// the unsaved ones (live) over the environment default, or the saved ones.
export function Preview({ environment, clientId, draft, live, savedStyle, onAdaptive, organization }: { environment: string; clientId?: string; draft: Branding; live: boolean; savedStyle: boolean; onAdaptive?: () => void; organization?: { id: string; overrides: Record<string, unknown> } }) {
  const [page, setPage] = useState<Page>('identify')
  const [scheme, setScheme] = useState<Scheme>(draft.theme.mode === 'dark' ? 'dark' : 'light')
  const [phone, setPhone] = useState(false)
  const [html, setHtml] = useState('')
  const [error, setError] = useState('')
  const [methods, setMethods] = useState<PreviewMethods | null>(null)
  const [buttons, setButtons] = useState<PreviewButton[]>([])
  const [sample, setSample] = useState(false)
  const [initial, setInitial] = useState<PreviewMethods | null>(null)
  // '' previews the environment language (as visitors without ui_locales see it).
  const [locale, setLocale] = useState('')
  const { locales } = useLocales(environment)
  const mode = draft.theme.mode
  useEffect(() => { if (mode !== 'adaptive') setScheme(mode) }, [mode])
  // Previewing a scheme the mode never shows: say so, and offer Adaptive.
  const unseen = mode !== 'adaptive' && scheme !== mode
  const request = useMemo(() => JSON.stringify(organization ? organization.overrides : body(draft)), [draft, organization])
  const signIn = useMemo(() => methods && methodPages.includes(page) ? JSON.stringify(methods) : '', [methods, page])

  // Start from what the page really offers: the client's methods (or every
  // method) with the environment's social logins, or sample buttons.
  useEffect(() => {
    const base = `/environments/${environment}`
    Promise.all([
      clientId ? api.get<SignIn>(`${base}/login-settings/clients/${clientId}/sign-in`).catch(() => everyMethod(clientId)) : Promise.resolve(null),
      api.get<{ items: { id: string; name: string; provider: string; active: boolean }[] }>(`${base}/federation-connections?scope=environment&limit=100`).then(r => r.items.filter(c => c.active)).catch(() => []),
    ]).then(([options, connections]) => {
      const real = connections.map(c => ({ name: c.name, provider: c.provider }))
      const list = real.length ? real : sampleButtons.slice(0, 2)
      const shown = options && !options.all_connections ? connections.filter(c => options.connection_ids.includes(c.id)).map(c => ({ name: c.name, provider: c.provider })) : list
      const start = { password: options?.password ?? true, email_code: options?.email_code ?? true, organization_sso: options?.organization_sso ?? true, connections: shown }
      setSample(!real.length); setButtons(real.length ? real : sampleButtons); setMethods(start); setInitial(start)
    })
  }, [environment, clientId])

  useEffect(() => {
    if (!methods) return
    const base = `/environments/${environment}/login-settings/preview`
    let stale = false
    const timer = window.setTimeout(() => {
      const q = new URLSearchParams({ page, scheme })
      if (clientId && savedStyle) q.set('client', clientId)
      if (organization) q.set('organization', organization.id)
      if (signIn) q.set('sign_in', signIn)
      if (locale) q.set('locale', locale)
      const call = live
        ? api.post<{ html: string }>(base, { page, scheme, [organization ? 'organization' : 'settings']: JSON.parse(request), ...(locale && { locale }), ...(signIn && { sign_in: JSON.parse(signIn) }) })
        : api.get<{ html: string }>(`${base}?${q}`)
      call.then(r => { if (!stale) { setHtml(r.html); setError('') } }).catch(e => { if (!stale) setError(message(e)) })
    }, 300)
    return () => { stale = true; window.clearTimeout(timer) }
  }, [environment, clientId, savedStyle, live, page, scheme, locale, request, signIn, methods, organization?.id])

  const toggle = (active: boolean) => cn('gap-1.5', active && 'bg-muted')
  return <section aria-label={t('Preview')} className="min-w-0 space-y-3 xl:sticky xl:top-4">
    <div className="flex flex-wrap items-center gap-2">
      <select aria-label={t('Preview page')} className={cn(selectClass, 'w-auto')} value={page} onChange={e => setPage(e.target.value as Page)}>
        {pages.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select>
      <div className="flex rounded-lg border p-0.5" role="group" aria-label={t('Color scheme')}>
        <Button size="sm" variant="ghost" className={toggle(scheme === 'light')} aria-pressed={scheme === 'light'} onClick={() => setScheme('light')}><Sun className="size-3.5" />{t('Light')}</Button>
        <Button size="sm" variant="ghost" className={toggle(scheme === 'dark')} aria-pressed={scheme === 'dark'} onClick={() => setScheme('dark')}><Moon className="size-3.5" />{t('Dark')}</Button>
      </div>
      <div className="flex rounded-lg border p-0.5" role="group" aria-label={t('Viewport')}>
        <Button size="sm" variant="ghost" className={toggle(!phone)} aria-pressed={!phone} onClick={() => setPhone(false)}><Monitor className="size-3.5" />{t('Desktop')}</Button>
        <Button size="sm" variant="ghost" className={toggle(phone)} aria-pressed={phone} onClick={() => setPhone(true)}><Smartphone className="size-3.5" />{t('Phone')}</Button>
      </div>
      {locales && locales.length > 1 && <select aria-label={t('Preview language')} className={cn(selectClass, 'w-auto')} value={locale} onChange={e => setLocale(e.target.value)}>
        <option value="">{t('Page language')}</option>
        {locales.map(l => <option key={l.code} value={l.code}>{l.name}</option>)}
      </select>}
      {!live && <Badge variant="secondary">{t('Saved style')}</Badge>}
    </div>
    {unseen && <div role="status" className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-dashed px-3 py-2 text-xs text-muted-foreground">
      <span>{t('Visitors never see this {{scheme}} version: the mode is {{mode}}.', { scheme: scheme === 'dark' ? t('dark') : t('light'), mode: mode === 'dark' ? t('dark') : t('light') })}{onAdaptive ? (' ' + t('Adaptive follows each visitor’s device.')) : ''}</span>
      {onAdaptive && <Button type="button" size="xs" variant="outline" onClick={onAdaptive}>{t('Use adaptive')}</Button>}
    </div>}
    {methods && methodPages.includes(page) && <MethodPicker methods={methods} buttons={buttons} sample={sample} changed={!!initial && JSON.stringify(initial) !== JSON.stringify(methods)} client={!!clientId}
      onChange={setMethods} onReset={() => initial && setMethods(initial)} />}
    {error && <p role="alert" className="rounded-lg border border-destructive/30 px-3 py-2 text-sm text-destructive">{error}</p>}
    <div className="overflow-hidden rounded-lg border bg-muted/40 p-3">
      <div className={cn('mx-auto overflow-hidden rounded-md border shadow-sm transition-[max-width]', phone ? 'max-w-[390px]' : 'max-w-full')}>
        {html ? <PreviewFrame html={html} className="h-[640px]" /> : <div role="status" className="flex h-[640px] items-center justify-center text-sm text-muted-foreground">{t('Rendering preview…')}</div>}
      </div>
    </div>
    <p className="text-xs text-muted-foreground">{t('Rendered by the hosted page templates with sample data. Buttons and links are inactive.')}</p>
  </section>
}

// MethodPicker chooses which sign-in methods the preview shows, e.g. only
// social login buttons. It only changes the preview.
function MethodPicker({ methods, buttons, sample, changed, client, onChange, onReset }: {
  methods: PreviewMethods; buttons: PreviewButton[]; sample: boolean; changed: boolean; client: boolean
  onChange: (m: PreviewMethods) => void; onReset: () => void
}) {
  const shown = (b: PreviewButton) => methods.connections.some(c => c.name === b.name && c.provider === b.provider)
  const count = (m: PreviewMethods) => Number(m.password) + Number(m.email_code) + Number(m.organization_sso) + m.connections.length
  // The last method cannot be turned off: a page needs one.
  const set = (next: PreviewMethods) => { if (count(next) > 0) onChange(next) }
  const flip = (b: PreviewButton) => set({ ...methods, connections: shown(b) ? methods.connections.filter(c => !(c.name === b.name && c.provider === b.provider)) : buttons.filter(x => x === b || shown(x)) })
  const chip = (on: boolean, label: string, onClick: () => void) => <button key={label} type="button" aria-pressed={on} onClick={onClick}
    className={cn('inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-xs transition-colors', on ? 'border-primary/40 bg-primary/10 text-foreground' : 'text-muted-foreground hover:bg-muted')}>
    <span aria-hidden className={cn('size-1.5 rounded-full', on ? 'bg-primary' : 'bg-muted-foreground/40')} />{label}
  </button>
  const preset = (label: string, next: PreviewMethods) => <Button key={label} type="button" size="xs" variant="ghost" onClick={() => set(next)}>{label}</Button>
  const none = { password: false, email_code: false, organization_sso: false, connections: [] as PreviewButton[] }
  return <div role="group" aria-label={t('Sign-in methods in the preview')} className="space-y-2 rounded-lg border px-3 py-2.5">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <p className="text-xs font-medium">{t('Show in preview')}</p>
      <div className="flex flex-wrap items-center gap-0.5">
        {preset(t('Everything'), { password: true, email_code: true, organization_sso: true, connections: buttons })}
        {preset(t('Social only'), { ...none, connections: buttons })}
        {preset(t('Email only'), { ...none, password: true, email_code: true, organization_sso: true })}
        {changed && <Button type="button" size="xs" variant="ghost" onClick={onReset}>{t('Reset')}</Button>}
      </div>
    </div>
    <div className="flex flex-wrap gap-1.5">
      {chip(methods.password, t('Password'), () => set({ ...methods, password: !methods.password }))}
      {chip(methods.email_code, t('Email code'), () => set({ ...methods, email_code: !methods.email_code }))}
      {chip(methods.organization_sso, t('Organization SSO'), () => set({ ...methods, organization_sso: !methods.organization_sso }))}
      {buttons.map(b => chip(shown(b), b.name, () => flip(b)))}
    </div>
    <p className="text-xs text-muted-foreground">
      {!emailForm(methods) ? (t('No email field: people only see the social login buttons.') + ' ') : ''}
      {sample ? (t('Sample buttons: add social login under Sign-in providers.') + ' ') : ''}
      {t('Only changes this preview.')} {client ? t('Set what this client really offers with “Sign-in methods” on the Hosted login page.') : t('Choose what each client really offers with “Sign-in methods” on the Hosted login page.')}
    </p>
  </div>
}
