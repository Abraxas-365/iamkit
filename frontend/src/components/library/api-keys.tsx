import { useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Ban } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { RowActions } from '@/components/ui/menu'
import { ConfirmDialog, CopyField, CopyText, DataTable, EntityRef, Time, selectClass, type Column } from '@/components/library/patterns'
import { SecretDialog } from '@/pages/integrations'
import { t } from '@/lib/i18n'

/** An API key as every surface returns it (apikey.APIKey). The value is
 * never part of it: only creation answers with it (`IssuedKey`). */
export interface APIKey {
  id: string
  owner: { type: 'user' | 'organization' | 'machine'; user_id?: string }
  organization_id: string
  application_id?: string
  resource_id: string
  name: string
  /** null = a machine key that carries everything its user holds. */
  permissions: string[] | null
  obfuscated_value: string
  expires_at: string
  /** false = the key never expires. */
  expires: boolean
  last_used_at: string | null
  revoked_at: string | null
  created_by: { kind: string; id?: string }
  created_at: string
  state: 'active' | 'revoked' | 'expired'
  user_name?: string
  organization_name?: string
  application_name?: string
  resource_name?: string
}
export interface IssuedKey extends APIKey { value: string }

/** What a caller may create (GET …/admin/api-keys/options). */
export interface KeyOptions {
  enabled: boolean
  max_ttl_days: number | null
  resources: { id: string; name: string; audience: string; permissions: string[] }[]
}

/** The environment's API key policy (GET|PUT …/api-key-policy). */
export interface KeyPolicy {
  user_keys: boolean
  organization_keys: boolean
  max_ttl_days: number | null
  max_per_user: number
  max_per_organization: number
  updated_at?: string
}

const creatorKinds: Record<string, string> = {
  operator: t('Operator'), user: t('End user'), machine: t('Machine user'), service_account: t('Service account'),
  setup_link: t('Setup link'), system: t('System'),
}
const ownerKinds: Record<APIKey['owner']['type'], string> = { user: t('User'), organization: t('Organization'), machine: t('Machine user') }
export const ownerLabel = (type: string) => ownerKinds[type as APIKey['owner']['type']] ?? type

// --- Expiry ---

/** expiryChoices are the lifetimes a key may be created with: 30 days,
 * 90 days, 1 year and never, narrowed by the environment's maximum. */
export function expiryChoices(maxDays?: number | null): { value: string; label: string }[] {
  const presets = [{ days: 30, value: '720h', label: t('30 days') }, { days: 90, value: '2160h', label: t('90 days') }, { days: 365, value: '8760h', label: t('1 year') }]
  if (maxDays == null) return [...presets.map(({ value, label }) => ({ value, label })), { value: 'never', label: t('Never') }]
  const fit = presets.filter(p => p.days <= maxDays).map(({ value, label }) => ({ value, label }))
  // A maximum between two presets is itself a choice.
  if (!presets.some(p => p.days === maxDays)) fit.push({ value: `${maxDays * 24}h`, label: t('{{count}} days', { count: maxDays }) })
  return fit
}

/** useExpiry holds the chosen lifetime (90 days unless the maximum forbids it). */
export function useExpiry(maxDays?: number | null) {
  const [picked, setPicked] = useState<string | null>(null)
  const choices = useMemo(() => expiryChoices(maxDays), [maxDays])
  const value = picked !== null && choices.some(c => c.value === picked) ? picked : (choices.find(c => c.value === '2160h') ?? choices[choices.length - 1]).value
  return { value, setValue: setPicked, choices }
}

export function ExpiryField({ id, expiry, disabled }: { id: string; expiry: ReturnType<typeof useExpiry>; disabled?: boolean }) {
  return <div className="space-y-1.5">
    <label className="text-sm font-medium" htmlFor={id}>{t('Expires in')}</label>
    <select id={id} className={selectClass} value={expiry.value} disabled={disabled} onChange={e => expiry.setValue(e.target.value)}>
      {expiry.choices.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
    </select>
  </div>
}

// --- Permissions ---

/** PermissionChecks picks the permissions a key carries out of those it may. */
export function PermissionChecks({ available, selected, onChange, disabled, hint }: { available: string[]; selected: string[]; onChange: (next: string[]) => void; disabled?: boolean; hint?: ReactNode }) {
  const toggle = (p: string) => onChange(selected.includes(p) ? selected.filter(x => x !== p) : [...selected, p])
  return <fieldset className="space-y-1.5" disabled={disabled}>
    <legend className="text-sm font-medium">{t('Permissions')}</legend>
    {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    <div className="grid max-h-48 gap-1 overflow-auto rounded-lg border p-2">
      {available.map(p => <label key={p} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 text-sm hover:bg-accent">
        <input type="checkbox" className="accent-primary" checked={selected.includes(p)} onChange={() => toggle(p)} />
        <code className="font-mono text-xs">{p}</code>
      </label>)}
    </div>
  </fieldset>
}

/** PermissionChips shows a key's permissions compactly; the full list is the tooltip. */
export function PermissionChips({ permissions }: { permissions: string[] | null }) {
  if (permissions === null) return <span className="text-xs text-muted-foreground">{t('All of the machine user\'s permissions')}</span>
  if (!permissions.length) return <span className="text-muted-foreground">—</span>
  const rest = permissions.length - 2
  return <span className="flex flex-wrap gap-1" title={permissions.join('\n')}>
    {permissions.slice(0, 2).map(p => <Badge key={p} variant="outline" className="font-mono">{p}</Badge>)}
    {rest > 0 && <Badge variant="secondary">{t('+{{count}} more', { count: rest })}</Badge>}
  </span>
}

// --- Table ---

export interface KeyColumns { owner?: boolean; member?: boolean; organization?: boolean; resource?: boolean; createdBy?: boolean }

function Owner({ k, console }: { k: APIKey; console?: string }) {
  const name = k.owner.type === 'organization' ? k.organization_name : k.user_name
  const id = k.owner.type === 'organization' ? k.organization_id : k.owner.user_id
  const to = console && id ? `${console}/${k.owner.type === 'organization' ? 'organizations' : 'users'}/${id}` : undefined
  return <span className="flex min-w-0 flex-col gap-0.5">
    <Badge variant="secondary" className="w-fit">{ownerLabel(k.owner.type)}</Badge>
    <EntityRef name={name} id={id} to={to} />
  </span>
}

/** KeysTable lists API keys; the caller picks the columns its surface needs.
 * `onRevoke` adds the row action for active keys. */
export function KeysTable({ keys, loading, error, retry, columns, console, empty, onRevoke }: {
  keys: APIKey[]; loading: boolean; error: string; retry: () => void; columns: KeyColumns; console?: string; empty: ReactNode; onRevoke?: (key: APIKey) => void
}) {
  const specs: { header: string | Column; cell: (k: APIKey) => ReactNode }[] = [
    { header: t('Name'), cell: k => <EntityRef name={k.name} id={k.id} /> },
    { header: { header: t('Value'), nowrap: true }, cell: k => <code className="font-mono text-xs">{k.obfuscated_value}</code> },
    ...(columns.owner ? [{ header: { header: t('Owner'), hideBelow: 'md' as const }, cell: (k: APIKey) => <Owner k={k} console={console} /> }] : []),
    ...(columns.member ? [{ header: t('Member'), cell: (k: APIKey) => <EntityRef name={k.user_name} id={k.owner.user_id} /> }] : []),
    ...(columns.organization ? [{ header: { header: t('Organization'), hideBelow: 'lg' as const }, cell: (k: APIKey) => <EntityRef name={k.organization_name} id={k.organization_id} to={console ? `${console}/organizations/${k.organization_id}` : undefined} /> }] : []),
    ...(columns.resource ? [{ header: { header: t('Resource'), hideBelow: 'lg' as const }, cell: (k: APIKey) => <EntityRef name={k.resource_name} id={k.resource_id} to={console ? `${console}/resources/${k.resource_id}` : undefined} secondary={k.application_name && <Link className="hover:underline" to={console ? `${console}/applications/${k.application_id}` : '#'}>{k.application_name}</Link>} /> }] : []),
    { header: { header: t('Permissions'), hideBelow: 'md' }, cell: k => <PermissionChips permissions={k.permissions} /> },
    { header: { header: t('Expires'), nowrap: true }, cell: k => k.expires ? <Time value={k.expires_at} /> : <span className="text-muted-foreground">{t('Never')}</span> },
    { header: { header: t('Last used'), nowrap: true, hideBelow: 'sm' }, cell: k => <Time value={k.last_used_at} /> },
    ...(columns.createdBy ? [{ header: { header: t('Created by'), hideBelow: 'xl' as const }, cell: (k: APIKey) => <span className="flex flex-col gap-0.5"><span className="text-xs">{creatorKinds[k.created_by.kind] ?? k.created_by.kind}</span>{k.created_by.id && <CopyText value={k.created_by.id} short label={t('Copy creator ID')} />}</span> }] : []),
    { header: t('State'), cell: k => <StateBadge state={k.state} /> },
    ...(onRevoke ? [{ header: t('Actions'), cell: (k: APIKey) => k.state === 'active' ? <RowActions label={t('Actions for {{name}}', { name: k.name })} actions={[{ label: t('Revoke'), icon: <Ban />, destructive: true, onSelect: () => onRevoke(k) }]} /> : null }] : []),
  ]
  return <DataTable columns={specs.map(s => s.header)} loading={loading} error={error} retry={retry} empty={empty}
    rows={keys.map(k => specs.map(s => s.cell(k)))} />
}

export function StateBadge({ state }: { state: APIKey['state'] }) {
  return state === 'active' ? <Badge variant="secondary" className="bg-success/10 text-success">{t('Active')}</Badge>
    : <Badge variant="secondary" className="bg-muted text-muted-foreground">{state === 'revoked' ? t('Revoked') : t('Expired')}</Badge>
}

// --- Dialogs ---

/** IssuedKeyDialog shows a new key's value, once. */
export function IssuedKeyDialog({ issued, onClose }: { issued: IssuedKey; onClose: () => void }) {
  return <SecretDialog title={t('API key created')} description={t('Copy the key now. It is shown only once and cannot be retrieved later: store it like a password.')} confirm={t('I have saved the key')} onClose={onClose}>
    <CopyField label={t('API key')} value={issued.value} secret hint={issued.expires ? <>{t('Expires')} <Time value={issued.expires_at} /></> : t('This key never expires.')} />
    <div role="note" className="rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs text-muted-foreground">{t('Anyone holding this key can act with its permissions. If it leaks, revoke it and create another.')}</div>
  </SecretDialog>
}

/** RevokeKeyDialog confirms ending a key. */
export function RevokeKeyDialog({ apiKey, remove, onClose }: { apiKey: APIKey; remove: () => Promise<void>; onClose: () => void }) {
  return <ConfirmDialog title={t('Revoke {{name}}?', { name: apiKey.name })} description={t('Anything using this key is refused at once. This cannot be undone.')} confirmLabel={t('Revoke')} onClose={onClose} confirm={remove} />
}
