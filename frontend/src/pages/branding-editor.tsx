import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { UnsavedChangesGuard } from '@/components/library/unsaved-changes'
import type { ReactNode } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, Monitor, Moon, Plus, Smartphone, Sun, Trash2, TriangleAlert } from 'lucide-react'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { cn, message } from '@/lib/utils'
import { body, defaults, emptyBranding, hex, normalize, pages, resolved, same, warnings } from '@/lib/branding'
import type { Branding, Page, Palette, Scheme, Theme } from '@/lib/branding'
import { Button, buttonVariants } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog, ErrorState, PageHeader } from '@/components/library/patterns'
import { clientName, PreviewFrame } from '@/components/library/preview-frame'

interface Client { id: string; application_name: string; resource_name: string; hosted_login: boolean }

const selectClass = 'h-8 w-full rounded-lg border border-input bg-background px-2 text-sm disabled:opacity-50'

function Field({ label, hint, children, id }: { label: string; hint?: string; children: ReactNode; id: string }) {
  return <div className="space-y-1.5">
    <label className="text-sm font-medium" htmlFor={id}>{label}</label>
    {children}
    {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
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

function ColorInput({ label, value, fallback, onChange }: { label: string; value: string; fallback: string; onChange: (v: string) => void }) {
  return <div className="flex items-center gap-1.5">
    <input type="color" aria-label={`Pick ${label.toLowerCase()}`} className="h-8 w-9 shrink-0 cursor-pointer rounded-md border bg-transparent p-0.5 disabled:cursor-not-allowed"
      value={hex.test(value) ? value.toLowerCase() : fallback} onChange={e => onChange(e.target.value)} />
    <Input aria-label={label} className="font-mono" value={value} placeholder={fallback} maxLength={7} spellCheck={false} onChange={e => onChange(e.target.value.trim())} />
  </div>
}

const colorRows: [keyof Palette, string][] = [['primary', 'Primary'], ['background', 'Page background'], ['card', 'Card'], ['text', 'Text'], ['header', 'Header']]

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
      // A new client style starts as a copy of the environment default.
      setDraft(style ?? { ...(environmentDefault ?? emptyBranding()), client_id: clientId, updated_at: undefined })
    }).catch(e => setLoadError(message(e)))
    if (clientId) api.get<{ items: Client[] }>(`/environments/${environment}/oauth-clients?limit=100`).then(r => setClient(r.items.find(c => c.id === clientId))).catch(() => {})
  }
  useEffect(load, [path])

  const dirty = !!draft && (!saved || !same(draft, saved))
  const guard = <UnsavedChangesGuard when={dirty && canWrite} bypass={discarding} message="Your style changes have not been saved." />

  const title = clientId ? `Style: ${clientName(client) || clientId}` : 'Default style'
  const description = clientId ? 'Sign-in pages of this OAuth client. Invitation pages always use the default style.' : 'Used by every hosted sign-in and invitation page, unless an OAuth client has its own style.'
  const header = <PageHeader title={title} description={description} actions={<Link to={back} className={buttonVariants({ variant: 'outline' })}><ArrowLeft className="size-4" /> Branding</Link>} />
  if (loadError) return <div className="space-y-6">{header}<ErrorState error={loadError} retry={load} /></div>
  if (!draft) return <div className="space-y-6">{header}<p role="status" className="text-sm text-muted-foreground">Loading…</p></div>

  const save = async () => {
    if (pending.current) return
    pending.current = true; setBusy(true); setSaveError('')
    try {
      const out = normalize(await api.put<Branding>(path, body(draft)))
      setSaved(out); setDraft(out); toast.success(clientId ? 'Client style saved' : 'Default style saved')
    } catch (e) { setSaveError(message(e)) } finally { pending.current = false; setBusy(false) }
  }

  return <div className="space-y-6 pb-20">
    {guard}
    {header}
    {clientId && !saved && <div role="status" className="rounded-lg border border-dashed px-4 py-3 text-sm text-muted-foreground">
      This client uses the default style. The editor starts from a copy of it; saving gives the client its own style.
    </div>}
    <div className="grid items-start gap-6 xl:grid-cols-[minmax(340px,420px)_1fr]">
      <Settings draft={draft} setDraft={setDraft} canWrite={canWrite} />
      <Preview environment={environment!} clientId={clientId} draft={draft} live={canWrite} savedStyle={!!saved} />
    </div>
    {saveError && <ErrorState error={saveError} />}
    {clientId && saved && canWrite && <div className="flex justify-start">
      <Button variant="outline" onClick={() => setReset(true)}><Trash2 className="size-4" /> Reset to default style</Button>
    </div>}
    {canWrite && dirty && <div className="fixed inset-x-0 bottom-0 z-40 border-t bg-background/95 backdrop-blur md:left-(--sidebar-width)">
      <div className="mx-auto flex max-w-screen-2xl items-center justify-between gap-4 px-6 py-3">
        <span className="text-sm text-muted-foreground">{saved ? 'Unsaved changes' : 'New client style (not saved)'}</span>
        <div className="flex gap-2">
          <Button variant="outline" disabled={busy} onClick={() => { setSaveError(''); if (saved) setDraft(saved); else { discarding.current = true; navigate(back) } }}>Discard</Button>
          <Button disabled={busy} onClick={() => void save()}>{busy ? 'Saving…' : 'Save'}</Button>
        </div>
      </div>
    </div>}
    {reset && <ConfirmDialog title="Reset to the default style?" description="The client's own style is deleted and its sign-in pages use the environment default again." confirmLabel="Reset" onClose={() => setReset(false)}
      confirm={async () => { await api.delete(path); toast.success('Client style reset'); discarding.current = true; navigate(back) }} />}
  </div>
}

function Settings({ draft, setDraft, canWrite }: { draft: Branding; setDraft: (b: Branding) => void; canWrite: boolean }) {
  const id = useId()
  const t = draft.theme
  const set = (patch: Partial<Branding>) => setDraft({ ...draft, ...patch })
  const theme = (patch: Partial<Theme>) => setDraft({ ...draft, theme: { ...t, ...patch } })
  const color = (scheme: Scheme, key: keyof Palette, value: string) => theme({ [scheme]: { ...t[scheme], [key]: value } })
  const schemes: Scheme[] = t.mode === 'adaptive' ? ['light', 'dark'] : [t.mode]
  const links = t.footer.links
  const setLinks = (next: typeof links) => theme({ footer: { ...t.footer, links: next } })
  const lightPrimary = resolved(draft, 'light').primary
  const issues = schemes.flatMap(s => warnings(draft, s).map(w => (schemes.length > 1 ? `${s === 'light' ? 'Light' : 'Dark'}: ` : '') + w))

  return <fieldset disabled={!canWrite} className="min-w-0 space-y-3">
    <legend className="sr-only">Style settings</legend>
    <Section title="Brand" open>
      <Field id={`${id}-name`} label="Display name" hint="Shown under the logo and in the browser tab.">
        <Input id={`${id}-name`} maxLength={100} value={draft.display_name} placeholder="Acme" onChange={e => set({ display_name: e.target.value })} />
      </Field>
      <Field id={`${id}-logo`} label="Logo URL" hint="HTTPS only. Shown at up to 200×48 px.">
        <Input id={`${id}-logo`} type="url" value={draft.logo_url} placeholder="https://cdn.example.com/logo.png" onChange={e => set({ logo_url: e.target.value.trim() })} />
      </Field>
      {t.mode !== 'light' && <Field id={`${id}-logo-dark`} label="Dark mode logo URL" hint="Optional. Replaces the logo on dark pages.">
        <Input id={`${id}-logo-dark`} type="url" value={t.logo_dark_url} placeholder="https://cdn.example.com/logo-dark.png" onChange={e => theme({ logo_dark_url: e.target.value.trim() })} />
      </Field>}
      <Field id={`${id}-favicon`} label="Favicon URL" hint="HTTPS only. ICO, PNG or SVG.">
        <Input id={`${id}-favicon`} type="url" value={t.favicon_url} placeholder="https://cdn.example.com/favicon.ico" onChange={e => theme({ favicon_url: e.target.value.trim() })} />
      </Field>
    </Section>

    <Section title="Theme" open>
      <Field id={`${id}-mode`} label="Mode" hint={t.mode === 'adaptive' ? 'Follows the light or dark setting of the visitor’s device.' : undefined}>
        <select id={`${id}-mode`} className={selectClass} value={t.mode} onChange={e => theme({ mode: e.target.value as Theme['mode'] })}>
          <option value="light">Light</option><option value="dark">Dark</option><option value="adaptive">Adaptive (browser setting)</option>
        </select>
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field id={`${id}-spacing`} label="Spacing">
          <select id={`${id}-spacing`} className={selectClass} value={t.spacing} onChange={e => theme({ spacing: e.target.value as Theme['spacing'] })}>
            <option value="compact">Compact</option><option value="normal">Normal</option><option value="roomy">Roomy</option>
          </select>
        </Field>
        <Field id={`${id}-align`} label="Form position">
          <select id={`${id}-align`} className={selectClass} value={t.align} onChange={e => theme({ align: e.target.value as Theme['align'] })}>
            <option value="left">Left</option><option value="center">Center</option><option value="right">Right</option>
          </select>
        </Field>
      </div>
      <Field id={`${id}-radius`} label={`Corner radius: ${t.radius}px`}>
        <input id={`${id}-radius`} type="range" min={0} max={24} step={1} value={t.radius} className="w-full accent-primary" onChange={e => theme({ radius: Number(e.target.value) })} />
      </Field>
    </Section>

    <Section title="Colors" open>
      <p className="text-xs text-muted-foreground">Empty colors use the default shown as placeholder.{t.mode === 'adaptive' ? ' Adaptive pages use the light column or the dark column following the device.' : ''}</p>
      <div className={cn('grid gap-x-3 gap-y-2', schemes.length > 1 ? 'grid-cols-[auto_1fr_1fr]' : 'grid-cols-[auto_1fr]')}>
        <span />{schemes.map(s => <span key={s} className="text-xs font-medium text-muted-foreground">{s === 'light' ? 'Light' : 'Dark'}</span>)}
        {colorRows.map(([key, label]) => <div key={key} className="contents">
          <span className="self-center text-sm">{label}</span>
          {schemes.map(s => {
            const fallback = key === 'primary' ? (s === 'light' ? defaults.light.primary : lightPrimary) : key === 'header' ? resolved(draft, s).card : defaults[s][key]
            return <ColorInput key={s} label={`${s === 'light' ? 'Light' : 'Dark'} ${label.toLowerCase()}`} value={t[s][key]} fallback={fallback} onChange={v => color(s, key, v)} />
          })}
        </div>)}
      </div>
      {issues.length > 0 && <ul aria-label="Contrast warnings" className="space-y-1 rounded-lg bg-warning/10 p-3 text-xs text-warning-foreground">
        {issues.map(w => <li key={w} className="flex gap-1.5"><TriangleAlert className="mt-px size-3.5 shrink-0 text-warning" />{w}</li>)}
      </ul>}
    </Section>

    <Section title="Header & footer">
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" className="size-4 accent-primary" checked={t.header.show} onChange={e => theme({ header: { show: e.target.checked }, logo_position: e.target.checked ? t.logo_position : 'card' })} />
        Show a header bar
      </label>
      {t.header.show && <Field id={`${id}-position`} label="Logo and name">
        <select id={`${id}-position`} className={selectClass} value={t.logo_position} onChange={e => theme({ logo_position: e.target.value as Theme['logo_position'] })}>
          <option value="card">In the card</option><option value="header">In the header</option>
        </select>
      </Field>}
      <Field id={`${id}-footer`} label="Footer text" hint="Optional, up to 200 characters.">
        <Input id={`${id}-footer`} maxLength={200} value={t.footer.text} placeholder="© Acme Inc." onChange={e => theme({ footer: { ...t.footer, text: e.target.value } })} />
      </Field>
      <div className="space-y-2">
        <p className="text-sm font-medium">Footer links</p>
        {links.map((l, i) => <div key={i} className="flex gap-1.5">
          <Input aria-label={`Link ${i + 1} label`} className="w-32 shrink-0" maxLength={40} value={l.label} placeholder="Privacy" onChange={e => setLinks(links.map((x, j) => j === i ? { ...x, label: e.target.value } : x))} />
          <Input aria-label={`Link ${i + 1} URL`} value={l.url} placeholder="https://acme.example/privacy" onChange={e => setLinks(links.map((x, j) => j === i ? { ...x, url: e.target.value.trim() } : x))} />
          <Button type="button" variant="ghost" size="icon" aria-label={`Remove link ${i + 1}`} onClick={() => setLinks(links.filter((_, j) => j !== i))}><Trash2 className="size-4" /></Button>
        </div>)}
        {links.length < 5 && <Button type="button" variant="outline" size="sm" onClick={() => setLinks([...links, { label: '', url: '' }])}><Plus className="size-3.5" /> Add link</Button>}
        <p className="text-xs text-muted-foreground">Up to 5 links (HTTPS or mailto). They open in a new tab.</p>
      </div>
    </Section>
  </fieldset>
}

// Preview renders the draft with the real page templates. Viewers see the
// saved style (they cannot change it, and drafts are a write operation).
function Preview({ environment, clientId, draft, live, savedStyle }: { environment: string; clientId?: string; draft: Branding; live: boolean; savedStyle: boolean }) {
  const [page, setPage] = useState<Page>('identify')
  const [scheme, setScheme] = useState<Scheme>(draft.theme.mode === 'dark' ? 'dark' : 'light')
  const [phone, setPhone] = useState(false)
  const [html, setHtml] = useState('')
  const [error, setError] = useState('')
  const mode = draft.theme.mode
  useEffect(() => { if (mode !== 'adaptive') setScheme(mode) }, [mode])
  const request = useMemo(() => JSON.stringify(body(draft)), [draft])

  useEffect(() => {
    const base = `/environments/${environment}/login-settings/preview`
    let stale = false
    const timer = window.setTimeout(() => {
      const q = new URLSearchParams({ page, scheme })
      if (clientId && savedStyle) q.set('client', clientId)
      const call = live
        ? api.post<{ html: string }>(base, { page, scheme, settings: JSON.parse(request) })
        : api.get<{ html: string }>(`${base}?${q}`)
      call.then(r => { if (!stale) { setHtml(r.html); setError('') } }).catch(e => { if (!stale) setError(message(e)) })
    }, 300)
    return () => { stale = true; window.clearTimeout(timer) }
  }, [environment, clientId, savedStyle, live, page, scheme, request])

  const toggle = (active: boolean) => cn('gap-1.5', active && 'bg-muted')
  return <section aria-label="Preview" className="min-w-0 space-y-3 xl:sticky xl:top-4">
    <div className="flex flex-wrap items-center gap-2">
      <select aria-label="Preview page" className={cn(selectClass, 'w-auto')} value={page} onChange={e => setPage(e.target.value as Page)}>
        {pages.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select>
      <div className="flex rounded-lg border p-0.5" role="group" aria-label="Color scheme">
        <Button size="sm" variant="ghost" className={toggle(scheme === 'light')} aria-pressed={scheme === 'light'} disabled={mode === 'dark'} onClick={() => setScheme('light')}><Sun className="size-3.5" />Light</Button>
        <Button size="sm" variant="ghost" className={toggle(scheme === 'dark')} aria-pressed={scheme === 'dark'} disabled={mode === 'light'} onClick={() => setScheme('dark')}><Moon className="size-3.5" />Dark</Button>
      </div>
      <div className="flex rounded-lg border p-0.5" role="group" aria-label="Viewport">
        <Button size="sm" variant="ghost" className={toggle(!phone)} aria-pressed={!phone} onClick={() => setPhone(false)}><Monitor className="size-3.5" />Desktop</Button>
        <Button size="sm" variant="ghost" className={toggle(phone)} aria-pressed={phone} onClick={() => setPhone(true)}><Smartphone className="size-3.5" />Phone</Button>
      </div>
      {!live && <Badge variant="secondary">Saved style</Badge>}
    </div>
    {error && <p role="alert" className="rounded-lg border border-destructive/30 px-3 py-2 text-sm text-destructive">{error}</p>}
    <div className="overflow-hidden rounded-lg border bg-muted/40 p-3">
      <div className={cn('mx-auto overflow-hidden rounded-md border shadow-sm transition-[max-width]', phone ? 'max-w-[390px]' : 'max-w-full')}>
        {html ? <PreviewFrame html={html} className="h-[640px]" /> : <div role="status" className="flex h-[640px] items-center justify-center text-sm text-muted-foreground">Rendering preview…</div>}
      </div>
    </div>
    <p className="text-xs text-muted-foreground">Rendered by the hosted page templates with sample data. Buttons and links are inactive.</p>
  </section>
}
