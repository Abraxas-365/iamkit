import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Ban, KeyRound, Plus, TriangleAlert } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { RowActions } from '@/components/ui/menu'
import { SearchSelect } from '@/components/ui/search-select'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ConfirmDialog, CopyField, DataTable, DetailSection, EmptyState, EntityRef, ErrorState, Time, selectClass } from '@/components/library/patterns'
import { CredentialStatus, SecretDialog, credentialState } from './integrations'
import { rich, t } from '@/lib/i18n'

export interface AccessToken { id: string; name: string; organization_id: string; organization_name?: string; application_id: string; application_name?: string; resource_id: string; resource_name?: string; expires_at: string; last_used_at: string | null; revoked_at: string | null; created_at: string }
interface Issued extends AccessToken { token: string }

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id) })

/** AccessTokens lists a machine user's personal access tokens and creates
 * (secret shown once) or revokes them. */
export function AccessTokens({ base, console, user, canWrite }: { base: string; console: string; user: { id: string; name: string }; canWrite: boolean }) {
  const path = `${base}/users/${user.id}/access-tokens`
  const list = usePaginatedList<AccessToken>(path, { limit: 50 })
  const [adding, setAdding] = useState(false)
  const [issued, setIssued] = useState<Issued | null>(null)
  const [revoke, setRevoke] = useState<AccessToken | null>(null)
  const add = canWrite && <Button variant="outline" size="sm" onClick={() => setAdding(true)}><Plus /> {t('Create token')}</Button>
  return <DetailSection title={t('Personal access tokens')} description={t('Each token acts as this machine user in one organization for one resource, with the permissions it holds there each time it is used. Use it as a bearer token or exchange it at /identity/v1/token-exchange.')} actions={list.data.length > 0 && add}>
    <DataTable
      columns={[t('Token'), { header: t('Access'), hideBelow: 'md' }, { header: t('Last used'), nowrap: true, hideBelow: 'sm' }, { header: t('Expires'), nowrap: true }, t('Status'), ...(canWrite ? [t('Actions')] : [])]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<KeyRound />} title={t('No personal access tokens')} description={t('Add the machine user to an organization first, then create a token. The token is shown once.')} action={add} />}
      rows={list.data.map(tok => {
        const state = credentialState(tok)
        return [
          <EntityRef name={tok.name} id={tok.id} />,
          <EntityRef name={tok.application_name || t('Application')} id={tok.application_id} to={`${console}/applications/${tok.application_id}`} secondary={(() => {
            const organization = <Link className="hover:underline" to={`${console}/organizations/${tok.organization_id}`}>{tok.organization_name || t('organization')}</Link>
            return tok.resource_name ? rich('→ {{resource}} in {{organization}}', { resource: tok.resource_name, organization }) : rich('in {{organization}}', { organization })
          })()} />,
          <Time value={tok.last_used_at} />,
          <Time value={tok.expires_at} />,
          <CredentialStatus state={state} />,
          ...(canWrite ? [state === 'active' ? <RowActions label={t('Actions for {{name}}', { name: tok.name })} actions={[{ label: t('Revoke'), icon: <Ban />, destructive: true, onSelect: () => setRevoke(tok) }]} /> : null] : []),
        ]
      })} />
    {adding && <TokenForm base={base} user={user.id} path={path} onClose={() => setAdding(false)} onCreated={tok => { setIssued(tok); list.reload() }} />}
    {issued && <SecretDialog title={t('Personal access token created')} description={t('Copy the token now — it is shown only once.')} onClose={() => setIssued(null)} confirm={t('I have saved the token')}>
      <CopyField label={t('Token')} value={issued.token} secret hint={<>{rich('Expires {{time}}. Send it as Authorization: Bearer to /api/v1 or your resource (introspection), or POST it to /identity/v1/token-exchange for an access token.', { time: <Time value={issued.expires_at} /> })}</>} />
    </SecretDialog>}
    {revoke && <ConfirmDialog title={t('Revoke {{name}}?', { name: revoke.name })} description={t('Calls using this token, and access tokens exchanged from it, stop working immediately. This cannot be undone.')} confirmLabel={t('Revoke')} onClose={() => setRevoke(null)} confirm={async () => { await api.delete(`${path}/${revoke.id}`); toast.success(t('Token revoked')); list.reload() }} />}
  </DetailSection>
}

function TokenForm({ base, user, path, onClose, onCreated }: { base: string; user: string; path: string; onClose: () => void; onCreated: (tok: Issued) => void }) {
  const id = useId()
  const [organization, setOrganization] = useState('')
  const [application, setApplication] = useState('')
  const [resource, setResource] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  const memberOf = useMemo(() => ({ user_id: user }), [user])
  const unauthorized = useNoRoles(base, user, organization, resource)
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{t('Create personal access token')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('The token carries the roles and grants the machine user holds in the organization, checked at every use.')}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current) return
        const form = new FormData(event.currentTarget)
        const data = {
          name: String(form.get('name') ?? '').trim(),
          organization_id: String(form.get('organization_id') ?? ''),
          application_id: String(form.get('application_id') ?? ''),
          resource_id: String(form.get('resource_id') ?? ''),
          expires_in: String(form.get('expires_in') ?? '24h'),
        }
        pending.current = true; setBusy(true); setError('')
        try {
          const result = await api.post<Issued>(path, data)
          toast.success(t('Token created')); onCreated(result); onClose()
        } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
      }}>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-name`}>{t('Name')}</label>
          <Input id={`${id}-name`} name="name" required disabled={busy} placeholder={t('e.g. nightly export')} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-org`}>{t('Organization')}</label>
          <SearchSelect id={`${id}-org`} name="organization_id" path={`${base}/organizations`} params={memberOf} mapItem={named} required disabled={busy} placeholder={t('Search its organizations…')} onChange={setOrganization} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-app`}>{t('Application')}</label>
          <SearchSelect id={`${id}-app`} name="application_id" path={`${base}/applications`} mapItem={named} required disabled={busy} placeholder={t('Search applications…')} onChange={value => { setApplication(value); setResource('') }} />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-res`}>{t('Resource')}</label>
          {application
            ? <SearchSelect key={application} id={`${id}-res`} name="resource_id" path={`${base}/applications/${application}/resources`} mapItem={named} required disabled={busy} placeholder={t('Search the application\'s resources…')} onChange={setResource} />
            : <p className="text-sm text-muted-foreground">{t('Choose an application first.')}</p>}
        </div>
        {unauthorized && <div role="note" aria-label={t('No roles on this resource')} className="flex gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-xs">
          <TriangleAlert aria-hidden className="mt-px size-4 shrink-0 text-warning" />
          <div className="space-y-1">
            <p className="font-medium">{t('The machine user holds no role on this resource in this organization')}</p>
            <p className="text-muted-foreground">{t('The token is refused (401) until it gets one. Assign a role, directly or through a group, before or after creating the token.')}</p>
          </div>
        </div>}
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-ttl`}>{t('Expires in')}</label>
          <select id={`${id}-ttl`} name="expires_in" className={selectClass} defaultValue="720h" disabled={busy}>
            <option value="24h">{t('24 hours')}</option>
            <option value="168h">{t('7 days')}</option>
            <option value="720h">{t('30 days')}</option>
            <option value="2160h">{t('90 days')}</option>
            <option value="8760h">{t('1 year')}</option>
            <option value="never">{t('No expiry')}</option>
          </select>
        </div>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
          <Button type="submit" disabled={busy}>{busy ? t('Creating…') : t('Create')}</Button>
        </div>
      </form>
    </DialogContent>
  </Dialog>
}

/** useNoRoles reports whether the user holds no role (direct or through a
 * group) on the resource in the organization, once both are chosen: a token
 * for it would be refused at every use. A failed lookup warns nothing. */
function useNoRoles(base: string, user: string, organization: string, resource: string) {
  const [none, setNone] = useState(false)
  useEffect(() => {
    setNone(false)
    if (!organization || !resource) return
    const controller = new AbortController()
    api.list<{ resource_id: string }>(`${base}/effective-roles?organization_id=${organization}&user_id=${user}`, controller.signal)
      .then(r => setNone(!r.data.some(role => role.resource_id === resource)))
      .catch(() => {})
    return () => controller.abort()
  }, [base, user, organization, resource])
  return none
}
