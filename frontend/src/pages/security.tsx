import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { Plus, ShieldCheck, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { cn, message } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { RowActions } from '@/components/ui/menu'
import { Skeleton } from '@/components/ui/skeleton'
import { TagInput } from '@/components/ui/tag-input'
import { ConfirmDialog, DataTable, DetailSection, EmptyState, ErrorState, PageHeader, SwitchField, Time, selectClass } from '@/components/library/patterns'
import { SignInAttempts } from '@/components/library/sign-in-attempts'
import {
  actionLabels, allowedActions, detectionHints, detectionLabels, detections, kindLabels, providerLabels, restrictionError, validHostname,
  type CaptchaConfig, type Restriction, type RiskPolicy, type RiskStatus, type Thresholds,
} from '@/lib/risk'
import { rich, t } from '@/lib/i18n'

const tabs = [['bot', t('Bot protection')], ['policy', t('Risk policy')], ['restrictions', t('Restrictions')], ['attempts', t('Sign-in attempts')]] as const
type Tab = (typeof tabs)[number][0]

/** SecurityPage is the environment's security settings: bot protection
 * (CAPTCHA), the risk policy, allow/deny restrictions and the sign-in log. */
export default function SecurityPage() {
  const { environment } = useParams()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [params, setParams] = useSearchParams()
  const requested = params.get('tab')
  const tab: Tab = tabs.find(([v]) => v === requested)?.[0] ?? 'bot'
  const show = (value: Tab) => setParams(value === 'bot' ? {} : { tab: value }, { replace: true })
  const base = `/environments/${environment}`
  const [status, setStatus] = useState<RiskStatus | null>(null)
  useEffect(() => { api.get<RiskStatus>(`${base}/risk/status`).then(setStatus).catch(() => setStatus(null)) }, [base])

  return <div className="space-y-6">
    <PageHeader title={t('Security')} description={t('Protect sign-in from bots and abuse: a CAPTCHA, detections with their actions, allow and deny rules, and the log of sign-in attempts.')} />
    <div role="tablist" aria-label={t('Security')} className="inline-flex flex-wrap rounded-lg border p-0.5">
      {tabs.map(([value, label]) => <button key={value} id={`security-tab-${value}`} type="button" role="tab" aria-selected={tab === value} aria-controls="security-panel" tabIndex={tab === value ? 0 : -1}
        className={cn('h-7 rounded-md px-3 text-sm transition-colors outline-none focus-visible:ring-3 focus-visible:ring-ring/50', tab === value ? 'bg-secondary font-medium text-foreground' : 'text-muted-foreground hover:text-foreground')}
        onClick={() => show(value)}>{label}</button>)}
    </div>
    <div id="security-panel" role="tabpanel" aria-labelledby={`security-tab-${tab}`} className="space-y-6">
      {tab === 'bot' && <BotProtection base={base} canWrite={canWrite} status={status} />}
      {tab === 'policy' && <PolicyTab base={base} canWrite={canWrite} status={status} />}
      {tab === 'restrictions' && <RestrictionsTab base={base} canWrite={canWrite} status={status} />}
      {tab === 'attempts' && <SignInAttempts />}
    </div>
  </div>
}

function FeatureOff({ name, environment }: { name: string; environment?: string }) {
  const { project } = useParams()
  return <p role="status" className="rounded-lg border border-warning/40 bg-warning/5 p-3 text-sm text-warning">
    {rich('The {{feature}} feature is off for this environment, so this has no effect. Turn it on under {{link}}.', { feature: <code>{name}</code>, link: <Link className="underline" to={`/projects/${project}/environments/${environment}/features`}>{t('Features (beta)')}</Link> })}
  </p>
}

function Field({ id, label, hint, error, children }: { id: string; label: string; hint?: ReactNode; error?: string; children: ReactNode }) {
  return <div className="space-y-1.5">
    <label htmlFor={id} className="text-sm font-medium">{label}</label>
    {children}
    {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
  </div>
}

// ───────────────────────── Bot protection ─────────────────────────

interface CaptchaDraft { provider: string; site_key: string; secret: string; hosted: boolean; headless: boolean; hostnames: string[] }
const toDraft = (c: CaptchaConfig | null): CaptchaDraft => ({ provider: c?.provider ?? 'turnstile', site_key: c?.site_key ?? '', secret: '', hosted: c?.hosted ?? true, headless: c?.headless ?? true, hostnames: c?.hostnames ?? [] })

/** testMessage explains a failed CAPTCHA test in the operator's words. */
function testMessage(e: unknown) {
  if (e instanceof ApiError) {
    if (e.code === 'CAPTCHA_SECRET_INVALID') return t('The provider rejected the stored secret. Save the right secret and test again.')
    if (e.code === 'ENCRYPTION_KEY_REQUIRED') return t('Secrets are stored encrypted. Set IAMKIT_ENCRYPTION_KEY on the server and restart it.')
    if (e.status === 502) return t('The CAPTCHA provider could not be reached. Try again in a moment.')
  }
  return message(e)
}

function BotProtection({ base, canWrite, status }: { base: string; canWrite: boolean; status: RiskStatus | null }) {
  const { environment } = useParams()
  const path = `${base}/captcha`
  const [saved, setSaved] = useState<CaptchaConfig | null | undefined>(undefined)
  const [error, setError] = useState('')
  const load = useCallback(() => {
    setError('')
    api.get<CaptchaConfig>(path).then(setSaved).catch(e => { if (e instanceof ApiError && e.status === 404) setSaved(null); else setError(message(e)) })
  }, [path])
  useEffect(load, [load])
  if (error) return <ErrorState error={error} retry={load} />
  if (saved === undefined) return <div role="status"><Skeleton className="h-64" /><span className="sr-only">{t('Loading bot protection…')}</span></div>
  return <CaptchaForm key={saved?.updated_at ?? 'new'} path={path} saved={saved} canWrite={canWrite} captchaOff={status?.captcha === false} environment={environment} onSaved={setSaved} onDeleted={() => setSaved(null)} />
}

function CaptchaForm({ path, saved, canWrite, captchaOff, environment, onSaved, onDeleted }: { path: string; saved: CaptchaConfig | null; canWrite: boolean; captchaOff: boolean; environment?: string; onSaved: (c: CaptchaConfig) => void; onDeleted: () => void }) {
  const [d, setD] = useState<CaptchaDraft>(toDraft(saved))
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState(false)
  const [formError, setFormError] = useState('')
  const [tested, setTested] = useState<{ ok: boolean; text: string } | null>(null)
  const [removing, setRemoving] = useState(false)
  const pending = useRef(false)
  const set = (patch: Partial<CaptchaDraft>) => { setD(x => ({ ...x, ...patch })); setFormError('') }
  const badHost = d.hostnames.find(h => !validHostname(h))

  const save = async (event: React.FormEvent) => {
    event.preventDefault()
    if (pending.current) return
    const siteKey = d.site_key.trim()
    if (!siteKey || /\s/.test(siteKey)) return setFormError(t('Enter the site key, without spaces.'))
    if (!saved?.has_secret && !d.secret.trim()) return setFormError(t('Enter the secret key.'))
    if (badHost) return setFormError(t('Hostnames must be host names only, without scheme, port or path: {{host}}', { host: badHost }))
    pending.current = true; setBusy(true); setFormError(''); setTested(null)
    try {
      const body: Record<string, unknown> = { provider: d.provider, site_key: siteKey, hosted: d.hosted, headless: d.headless, hostnames: d.hostnames }
      if (d.secret.trim()) body.secret = d.secret.trim()
      onSaved(await api.put<CaptchaConfig>(path, body))
      toast.success(t('Bot protection saved'))
    } catch (e) {
      setFormError(e instanceof ApiError && e.code === 'ENCRYPTION_KEY_REQUIRED' ? t('Secrets are stored encrypted. Set IAMKIT_ENCRYPTION_KEY on the server and restart it.') : message(e))
    } finally { pending.current = false; setBusy(false) }
  }
  const test = async () => {
    setTesting(true); setTested(null)
    try { await api.post(`${path}/test`); setTested({ ok: true, text: t('The provider accepted the stored secret.') }) } catch (e) { setTested({ ok: false, text: testMessage(e) }) } finally { setTesting(false) }
  }

  return <div className="space-y-4">
    {captchaOff && <FeatureOff name="captcha" environment={environment} />}
    <form onSubmit={save} noValidate>
      <DetailSection title={t('Bot protection')} description={t('Ask people to pass a CAPTCHA before sign-in, sign-up and device approval. Create the widget in your provider\'s dashboard, then paste its keys here.')}
        actions={saved && <Badge variant="secondary" className="bg-success/10 text-success">{t('Configured')}</Badge>}>
        <fieldset disabled={!canWrite || busy} className="min-w-0 space-y-4">
          <Field id="captcha-provider" label={t('Provider')}>
            <select id="captcha-provider" className={cn(selectClass, 'max-w-xs')} value={d.provider} onChange={e => set({ provider: e.target.value })}>
              {Object.entries(providerLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </Field>
          <Field id="captcha-site-key" label={t('Site key')} hint={t('Public: shown to the browser by the widget.')}>
            <Input id="captcha-site-key" value={d.site_key} onChange={e => set({ site_key: e.target.value })} autoComplete="off" spellCheck={false} className="font-mono" />
          </Field>
          <Field id="captcha-secret" label={t('Secret key')} hint={saved?.has_secret ? t('A secret is configured. Type a new one only to replace it; it is never shown again.') : t('Stored encrypted and never shown again.')}>
            <Input id="captcha-secret" type="password" value={d.secret} onChange={e => set({ secret: e.target.value })} autoComplete="new-password" spellCheck={false} placeholder={saved?.has_secret ? t('Configured') : ''} />
          </Field>
          <SwitchField label={t('Hosted sign-in pages')} hint={t('Show the CAPTCHA on IAMKit\'s hosted login, sign-up and device pages.')} checked={d.hosted} onCheckedChange={hosted => set({ hosted })} />
          <SwitchField label={t('Your own sign-in UI (headless API)')} hint={t('Require a captcha_token on the sign-in, sign-up and challenge calls of your own UI.')} checked={d.headless} onCheckedChange={headless => set({ headless })} />
          <Field id="captcha-hostnames" label={t('Allowed hostnames')} hint={t('Headless only: hostnames the widget may run on, e.g. app.example.com. Leave empty to accept any.')} error={badHost ? t('Hostnames must be host names only, without scheme, port or path: {{host}}', { host: badHost }) : undefined}>
            <TagInput id="captcha-hostnames" name="hostnames" defaultValue={d.hostnames} disabled={!canWrite || busy} placeholder="app.example.com" onChange={hostnames => set({ hostnames: hostnames.map(h => h.toLowerCase()) })} />
          </Field>
        </fieldset>
        {formError && <div className="mt-4"><ErrorState error={formError} /></div>}
        {tested && <p role={tested.ok ? 'status' : 'alert'} className={cn('mt-4 text-sm', tested.ok ? 'text-success' : 'text-destructive')}>{tested.text}</p>}
        {canWrite && <div className="mt-4 flex flex-wrap justify-between gap-2 border-t pt-4">
          <div className="flex gap-2">
            <Button type="submit" disabled={busy}>{busy ? t('Saving…') : t('Save')}</Button>
            {saved?.has_secret && <Button type="button" variant="outline" disabled={testing || busy} onClick={() => void test()}>{testing ? t('Testing…') : t('Test')}</Button>}
          </div>
          {saved && <Button type="button" variant="outline" className="text-destructive" disabled={busy} onClick={() => setRemoving(true)}><Trash2 /> {t('Delete')}</Button>}
        </div>}
      </DetailSection>
    </form>
    {removing && <ConfirmDialog title={t('Delete bot protection?')} description={t('People will no longer be asked for a CAPTCHA. The stored secret is erased.')} confirmLabel={t('Delete')}
      onClose={() => setRemoving(false)} confirm={async () => { await api.delete(path); toast.success(t('Bot protection deleted')); onDeleted() }} />}
  </div>
}

// ───────────────────────── Risk policy ─────────────────────────

const thresholdFields: { key: keyof Thresholds; label: string; min: number; max: number; hint: string }[] = [
  { key: 'ip_failures_per_hour', label: t('Failed sign-ins per IP address, per hour'), min: 1, max: 10000, hint: t('IP address velocity fires above this.') },
  { key: 'ip_distinct_logins_per_hour', label: t('Different logins tried per IP address, per hour'), min: 1, max: 10000, hint: t('IP address velocity fires above this.') },
  { key: 'user_failures_per_hour', label: t('Failed sign-ins per account, per hour'), min: 1, max: 1000, hint: t('Brute force fires above this.') },
  { key: 'stale_after_days', label: t('Days without signing in before an account is stale'), min: 7, max: 3650, hint: t('From 7 to 3650 days.') },
  { key: 'travel_speed_kmh', label: t('Travel speed that counts as impossible (km/h)'), min: 100, max: 20000, hint: t('Between two sign-ins faster than this.') },
]

function GeoBanner({ status }: { status: RiskStatus | null }) {
  if (!status) return null
  const g = status.geoip
  if (g.error) return <p role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">{t('GeoIP could not be read: {{error}}', { error: g.error })}</p>
  if (g.source === 'none' || (!g.countries && !g.travel)) return <p role="status" className="rounded-lg border border-warning/40 bg-warning/5 p-3 text-sm text-warning">{t('GeoIP is not configured on this deployment, so impossible travel and country restrictions are unavailable. Set IAMKIT_GEOIP_DB or IAMKIT_GEOIP_HEADER on the server.')}</p>
  const where = g.source === 'header' ? t('country header {{header}}', { header: g.header ?? '' }) : t('database {{database}}', { database: g.database ?? 'mmdb' })
  return <p role="status" className="rounded-lg border p-3 text-sm text-muted-foreground">
    {g.travel ? t('GeoIP is configured ({{where}}): countries and impossible travel work.', { where }) : t('GeoIP is configured ({{where}}): country rules work, but impossible travel needs a City database with coordinates.', { where })}
  </p>
}

interface PolicyDraft { actions: Record<string, string>; thresholds: Record<keyof Thresholds, string>; notify_user: boolean; block_if_unverifiable: boolean }
const toPolicyDraft = (p: RiskPolicy): PolicyDraft => ({
  actions: Object.fromEntries(detections.map(d => [d, p.actions?.[d] || 'off'])),
  thresholds: Object.fromEntries(thresholdFields.map(f => [f.key, String(p.thresholds?.[f.key] ?? '')])) as Record<keyof Thresholds, string>,
  notify_user: p.notify_user, block_if_unverifiable: p.block_if_unverifiable,
})

function PolicyTab({ base, canWrite, status }: { base: string; canWrite: boolean; status: RiskStatus | null }) {
  const { environment } = useParams()
  const path = `${base}/risk-policy`
  const [saved, setSaved] = useState<RiskPolicy | null>(null)
  const [error, setError] = useState('')
  const load = useCallback(() => { setError(''); api.get<RiskPolicy>(path).then(setSaved).catch(e => setError(message(e))) }, [path])
  useEffect(load, [load])
  if (error) return <ErrorState error={error} retry={load} />
  if (!saved) return <div role="status"><Skeleton className="h-64" /><span className="sr-only">{t('Loading risk policy…')}</span></div>
  return <PolicyForm key={saved.updated_at ?? 'default'} path={path} saved={saved} canWrite={canWrite} status={status} environment={environment} onSaved={setSaved} reload={load} />
}

function PolicyForm({ path, saved, canWrite, status, environment, onSaved, reload }: { path: string; saved: RiskPolicy; canWrite: boolean; status: RiskStatus | null; environment?: string; onSaved: (p: RiskPolicy) => void; reload: () => void }) {
  const [d, setD] = useState<PolicyDraft>(toPolicyDraft(saved))
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState('')
  const [resetting, setResetting] = useState(false)
  const pending = useRef(false)
  const noTravel = status ? !status.geoip.travel : false
  const logging = detections.some(x => d.actions[x] === 'log')
  const setAction = (detection: string, action: string) => { setD(x => ({ ...x, actions: { ...x.actions, [detection]: action } })); setFormError('') }

  const save = async (event: React.FormEvent) => {
    event.preventDefault()
    if (pending.current) return
    const thresholds = {} as Thresholds
    for (const f of thresholdFields) {
      const raw = d.thresholds[f.key].trim()
      const n = Number(raw)
      if (!raw || !Number.isInteger(n) || n < f.min || n > f.max) return setFormError(t('{{label}} must be a whole number from {{min}} to {{max}}.', { label: f.label, min: f.min, max: f.max }))
      thresholds[f.key] = n
    }
    pending.current = true; setBusy(true); setFormError('')
    try {
      onSaved(await api.put<RiskPolicy>(path, { actions: d.actions, thresholds, notify_user: d.notify_user, block_if_unverifiable: d.block_if_unverifiable }))
      toast.success(t('Risk policy saved'))
    } catch (e) {
      setFormError(e instanceof ApiError && e.code === 'GEOIP_REQUIRED' ? t('Impossible travel needs GeoIP. Configure IAMKIT_GEOIP_DB on the server, or turn it off.') : message(e))
    } finally { pending.current = false; setBusy(false) }
  }

  const columns = ['off', 'log', 'notify', 'challenge', 'block']
  return <div className="space-y-4">
    {status && !status.risk_signals && <FeatureOff name="risk_signals" environment={environment} />}
    <GeoBanner status={status} />
    <form onSubmit={save} noValidate className="space-y-4">
      <DetailSection title={t('Detections and actions')} description={t('Choose what happens when each detection fires. Every detection starts off; start with Log only to see what it would catch before it affects anyone.')}
        actions={!saved.saved && <Badge variant="secondary">{t('Default policy')}</Badge>}>
        <fieldset disabled={!canWrite || busy} className="min-w-0">
          <div className="overflow-x-auto rounded-lg border">
            <table className="w-full text-sm">
              <thead><tr className="border-b text-left text-xs text-muted-foreground">
                <th scope="col" className="px-3 py-2 font-normal">{t('Detection')}</th>
                {columns.map(c => <th key={c} scope="col" className="px-2 py-2 text-center font-normal">{c === 'off' ? t('Off') : c === 'log' ? t('Log') : c === 'notify' ? t('Notify') : c === 'challenge' ? t('Challenge') : t('Block')}</th>)}
              </tr></thead>
              <tbody>{detections.map(det => {
                const locked = det === 'impossible_travel' && noTravel
                return <tr key={det} className="border-b last:border-0">
                  <th scope="row" className="px-3 py-2.5 text-left font-medium"><span className="block">{detectionLabels[det]}</span><span className="block text-xs font-normal text-muted-foreground">{detectionHints[det]}</span>
                    {locked && <span className="block text-xs font-normal text-warning">{t('Unavailable: this deployment has no GeoIP with coordinates.')}</span>}</th>
                  {columns.map(action => <td key={action} className="px-2 py-2 text-center">
                    {allowedActions[det].includes(action)
                      ? <input type="radio" name={`action-${det}`} className="size-4 accent-primary" aria-label={t('{{detection}}: {{action}}', { detection: detectionLabels[det], action: actionLabels[action] })}
                        checked={d.actions[det] === action} disabled={locked && action !== 'off'} onChange={() => setAction(det, action)} />
                      : <span aria-hidden className="text-muted-foreground">—</span>}
                  </td>)}
                </tr>
              })}</tbody>
            </table>
          </div>
          {logging && <p role="note" className="mt-3 text-xs text-muted-foreground">{t('Log only records the detection in the sign-in attempts and the event log. Nobody is notified, challenged or blocked.')}</p>}
          <div className="mt-4 space-y-3">
            <SwitchField label={t('Email the user about notifications')} hint={t('Detections set to Notify send the user a security alert email.')} checked={d.notify_user} onCheckedChange={notify_user => setD(x => ({ ...x, notify_user }))} />
            <SwitchField label={t('Block when a challenge cannot be answered')} hint={t('If the user has no verified email to receive the code, block the sign-in instead of letting it through.')} checked={d.block_if_unverifiable} onCheckedChange={block_if_unverifiable => setD(x => ({ ...x, block_if_unverifiable }))} />
          </div>
        </fieldset>
      </DetailSection>
      <DetailSection title={t('Thresholds')} description={t('When each detection fires.')}>
        <fieldset disabled={!canWrite || busy} className="grid min-w-0 gap-4 sm:grid-cols-2">
          {thresholdFields.map(f => <Field key={f.key} id={`threshold-${f.key}`} label={f.label} hint={f.hint}>
            <Input id={`threshold-${f.key}`} type="number" inputMode="numeric" min={f.min} max={f.max} value={d.thresholds[f.key]} onChange={e => { const value = e.target.value; setD(x => ({ ...x, thresholds: { ...x.thresholds, [f.key]: value } })); setFormError('') }} />
          </Field>)}
        </fieldset>
        {formError && <div className="mt-4"><ErrorState error={formError} /></div>}
        {canWrite && <div className="mt-4 flex flex-wrap justify-between gap-2 border-t pt-4">
          <Button type="submit" disabled={busy}>{busy ? t('Saving…') : t('Save policy')}</Button>
          {saved.saved && <Button type="button" variant="outline" disabled={busy} onClick={() => setResetting(true)}>{t('Reset to default')}</Button>}
        </div>}
      </DetailSection>
    </form>
    {resetting && <ConfirmDialog title={t('Reset the risk policy?')} description={t('Every detection goes back to off and the thresholds to their defaults. Restrictions are not affected.')} confirmLabel={t('Reset')}
      onClose={() => setResetting(false)} confirm={async () => { await api.delete(path); toast.success(t('Risk policy reset')); reload() }} />}
  </div>
}

// ───────────────────────── Restrictions ─────────────────────────

function RestrictionsTab({ base, canWrite, status }: { base: string; canWrite: boolean; status: RiskStatus | null }) {
  const path = `${base}/risk-restrictions`
  const [items, setItems] = useState<Restriction[] | null>(null)
  const [error, setError] = useState('')
  const [removing, setRemoving] = useState<Restriction | null>(null)
  const load = useCallback(() => { setError(''); api.get<{ items: Restriction[] }>(path).then(r => setItems(r.items ?? [])).catch(e => setError(message(e))) }, [path])
  useEffect(load, [load])
  const noCountries = status ? !status.geoip.countries : false

  return <div className="space-y-4">
    {noCountries && <p role="status" className="rounded-lg border border-warning/40 bg-warning/5 p-3 text-sm text-warning">{t('Country rules are unavailable: this deployment has no GeoIP. Set IAMKIT_GEOIP_DB or IAMKIT_GEOIP_HEADER on the server.')}</p>}
    {canWrite && <AddRestriction path={path} noCountries={noCountries} onAdded={load} />}
    <DetailSection title={t('Restrictions')} description={t('Deny rules refuse a sign-in or sign-up before any password is checked. Allow rules skip the detections (never the CAPTCHA).')}>
      <DataTable
        columns={[t('Type'), t('Value'), t('Rule'), { header: t('Note'), hideBelow: 'md' }, { header: t('Added'), nowrap: true, hideBelow: 'md' }, ...(canWrite ? [t('Actions')] : [])]}
        loading={items === null && !error} error={error} retry={load}
        empty={<EmptyState icon={<ShieldCheck />} title={t('No restrictions')} description={t('Add an IP range, country or email domain to allow or deny.')} />}
        rows={(items ?? []).map(r => [
          kindLabels[r.kind] ?? r.kind,
          <span className="font-mono text-xs">{r.value}</span>,
          <Badge variant="secondary" className={r.action === 'deny' ? 'bg-destructive/10 text-destructive' : 'bg-success/10 text-success'}>{r.action === 'deny' ? t('Deny') : t('Allow')}</Badge>,
          r.note || '—',
          <Time value={r.created_at} />,
          ...(canWrite ? [<RowActions label={t('Actions for {{name}}', { name: r.value })} actions={[{ label: t('Remove'), icon: <Trash2 />, destructive: true, onSelect: () => setRemoving(r) }]} />] : []),
        ])} />
    </DetailSection>
    {removing && <ConfirmDialog title={t('Remove this restriction?')} description={removing.action === 'deny' ? t('The deny rule for {{value}} stops applying at once.', { value: removing.value }) : t('The allow rule for {{value}} stops applying at once.', { value: removing.value })} confirmLabel={t('Remove')}
      onClose={() => setRemoving(null)} confirm={async () => { await api.delete(`${path}/${removing.id}`); toast.success(t('Restriction removed')); load() }} />}
  </div>
}

function AddRestriction({ path, noCountries, onAdded }: { path: string; noCountries: boolean; onAdded: () => void }) {
  const [kind, setKind] = useState('ip')
  const [value, setValue] = useState('')
  const [action, setAction] = useState('deny')
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (pending.current) return
    const problem = restrictionError(kind, value) || (note.trim().length > 200 ? t('The note can have at most 200 characters.') : '')
    if (problem) return setError(problem)
    pending.current = true; setBusy(true); setError('')
    try {
      await api.post(path, { kind, value: value.trim(), action, ...(note.trim() && { note: note.trim() }) })
      toast.success(t('Restriction added')); setValue(''); setNote(''); onAdded()
    } catch (e) {
      setError(e instanceof ApiError && e.code === 'GEOIP_REQUIRED' ? t('Country rules need GeoIP on the server.') : message(e))
    } finally { pending.current = false; setBusy(false) }
  }
  return <DetailSection title={t('Add a restriction')}>
    <form onSubmit={submit} noValidate className="space-y-3">
      <fieldset disabled={busy} className="grid min-w-0 gap-3 sm:grid-cols-2 lg:grid-cols-[10rem_1fr_8rem_1fr]">
        <Field id="restriction-kind" label={t('Type')}>
          <select id="restriction-kind" className={selectClass} value={kind} onChange={e => { setKind(e.target.value); setError('') }}>
            {Object.entries(kindLabels).map(([k, label]) => <option key={k} value={k} disabled={k === 'country' && noCountries}>{label}</option>)}
          </select>
        </Field>
        <Field id="restriction-value" label={t('Value')}>
          <Input id="restriction-value" value={value} onChange={e => { setValue(e.target.value); setError('') }} autoComplete="off" spellCheck={false} className="font-mono"
            placeholder={kind === 'ip' ? '203.0.113.0/24' : kind === 'country' ? 'US' : 'example.com'} />
        </Field>
        <Field id="restriction-action" label={t('Rule')}>
          <select id="restriction-action" className={selectClass} value={action} onChange={e => setAction(e.target.value)}>
            <option value="deny">{t('Deny')}</option><option value="allow">{t('Allow')}</option>
          </select>
        </Field>
        <Field id="restriction-note" label={t('Note')}>
          <Input id="restriction-note" value={note} maxLength={200} onChange={e => setNote(e.target.value)} placeholder={t('Why (optional)')} />
        </Field>
      </fieldset>
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      <Button type="submit" disabled={busy}><Plus /> {busy ? t('Adding…') : t('Add restriction')}</Button>
    </form>
  </DetailSection>
}
