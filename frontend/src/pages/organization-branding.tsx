import { useEffect, useMemo, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { emptyBranding, normalize } from '@/lib/branding'
import type { Branding, Theme } from '@/lib/branding'
import { Button } from '@/components/ui/button'
import { ConfirmDialog, ErrorState } from '@/components/library/patterns'
import { UnsavedChangesGuard } from '@/components/library/unsaved-changes'
import { useOrganization } from './organization-layout'
import { Preview, Settings } from './branding-editor'
import { rich, t } from '@/lib/i18n'

/** Overrides is the API shape: null fields inherit the client style or
 * environment default. */
export interface Overrides {
  organization_id?: string
  display_name: string | null; logo_url: string | null; accent_color: string | null
  theme: Theme | null; updated_at?: string
  /** Language of its pages and invitation emails; null inherits. */
  locale?: string | null
}

// toDraft turns overrides into editor state ('' = inherited).
export function toDraft(o: Overrides, inherited: Branding): { draft: Branding; own: boolean } {
  const theme = o.theme ? normalize({ theme: o.theme }).theme : inherited.theme
  return { draft: { ...emptyBranding(), display_name: o.display_name ?? '', logo_url: o.logo_url ?? '', accent_color: o.theme ? '' : o.accent_color ?? '', theme, locale: o.locale ?? '' }, own: !!o.theme }
}

// toOverrides turns editor state back into overrides.
export function toOverrides(draft: Branding, own: boolean): Overrides {
  const text = (v: string) => v.trim() ? v.trim() : null
  return {
    display_name: text(draft.display_name), logo_url: text(draft.logo_url),
    accent_color: own ? text(draft.theme.light.primary) : text(draft.accent_color),
    theme: own ? draft.theme : null,
    locale: text(draft.locale ?? ''),
  }
}

const key = (o: Overrides) => JSON.stringify([o.display_name, o.logo_url, o.accent_color, o.theme, o.locale ?? null])

/** OrganizationBrandingPage: the organization's overrides of the hosted
 * pages, shown when the organization is known (organization hint, chosen
 * organization, verified email domain) and on its invitations. */
export function OrganizationBrandingPage() {
  const { environment } = useParams()
  const { org } = useOrganization()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/login-settings/organizations/${org.id}`
  const [inherited, setInherited] = useState<Branding | null>(null)
  const [saved, setSaved] = useState<Overrides | null>(null)
  const [draft, setDraft] = useState<Branding | null>(null)
  const [own, setOwn] = useState(false)
  const [error, setError] = useState('')
  const [saveError, setSaveError] = useState('')
  const [busy, setBusy] = useState(false)
  const [reset, setReset] = useState(false)
  const pending = useRef(false)

  const apply = (o: Overrides, base: Branding) => { const d = toDraft(o, base); setSaved(o); setDraft(d.draft); setOwn(d.own) }
  const load = () => {
    setError('')
    Promise.all([api.get<Branding>(`/environments/${environment}/login-settings`).then(normalize), api.get<Overrides>(path)])
      .then(([base, o]) => { setInherited(base); apply(o, base) }).catch(e => setError(message(e)))
  }
  useEffect(load, [path])

  const current = useMemo(() => draft ? toOverrides(draft, own) : null, [draft, own])
  const custom = !!saved && (saved.display_name !== null || saved.logo_url !== null || saved.accent_color !== null || saved.theme !== null || !!saved.locale)
  const dirty = !!current && !!saved && key(current) !== key(saved)
  const preview = useMemo(() => current ? { id: org.id, overrides: current as unknown as Record<string, unknown> } : undefined, [current, org.id])

  if (error) return <ErrorState error={error} retry={load} />
  if (!draft || !inherited || !current) return <p role="status" className="text-sm text-muted-foreground">{t('Loading…')}</p>

  const save = async () => {
    if (pending.current) return
    pending.current = true; setBusy(true); setSaveError('')
    try { apply(await api.put<Overrides>(path, current), inherited); toast.success(t('Organization branding saved')) }
    catch (e) { setSaveError(message(e)) } finally { pending.current = false; setBusy(false) }
  }

  return <div className="space-y-6 pb-20">
    <UnsavedChangesGuard when={dirty && canWrite} message={t('Your branding changes have not been saved.')} />
    <div className="space-y-1">
      <h2 className="font-mono text-lg font-semibold">{t('Branding')}</h2>
      <p className="text-sm text-muted-foreground">{rich('Sign-in pages show it once they know the organization — the application’s organization hint ({{code}} or the {{code2}} scope), the chosen organization, or a verified email domain — and so do its invitation pages and emails. Empty fields inherit the OAuth client’s style or the environment default; codes and other emails keep the environment brand.', { code: <code>{'organization_id'}</code>, code2: <code>{'urn:iamkit:org:id:…'}</code> })}</p>
    </div>
    <div className="grid items-start gap-6 xl:grid-cols-[minmax(340px,420px)_1fr]">
      <Settings draft={draft} setDraft={setDraft} canWrite={canWrite} environmentDefault={false} org={{ own, setOwn, inherited }} enabled={inherited.languages ?? []} />
      <Preview environment={environment!} draft={draft} live={canWrite} savedStyle={custom} organization={preview} />
    </div>
    {saveError && <ErrorState error={saveError} />}
    {custom && canWrite && <Button variant="outline" onClick={() => setReset(true)}><Trash2 className="size-4" /> {t('Remove organization branding')}</Button>}
    {canWrite && dirty && <div data-save-bar className="fixed inset-x-0 bottom-0 z-40 border-t bg-background/95 backdrop-blur md:left-(--sidebar-width)">
      <div className="mx-auto flex max-w-screen-2xl items-center justify-between gap-4 px-6 py-3">
        <span className="text-sm text-muted-foreground">{t('Unsaved changes')}</span>
        <div className="flex gap-2">
          <Button variant="outline" disabled={busy} onClick={() => { setSaveError(''); if (saved) apply(saved, inherited) }}>{t('Discard')}</Button>
          <Button disabled={busy} onClick={() => void save()}>{busy ? t('Saving…') : t('Save')}</Button>
        </div>
      </div>
    </div>}
    {reset && <ConfirmDialog title={t('Remove the organization branding?')} description={t('Its sign-in and invitation pages use the client style or environment default again.')} confirmLabel={t('Remove')} onClose={() => setReset(false)}
      confirm={async () => { await api.delete(path); toast.success(t('Organization branding removed')); load() }} />}
  </div>
}
