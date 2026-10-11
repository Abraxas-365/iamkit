import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { Plus, KeySquare, TriangleAlert } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { SearchSelect } from '@/components/ui/search-select'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { DetailSection, EmptyState, ErrorState } from '@/components/library/patterns'
import { ExpiryField, IssuedKeyDialog, KeysTable, PermissionChecks, RevokeKeyDialog, useExpiry, type APIKey, type IssuedKey } from '@/components/library/api-keys'
import { t } from '@/lib/i18n'

const named = (item: Record<string, unknown>) => ({ id: String(item.id), label: String(item.name || item.id) })

/** UserAPIKeys lists a user's API keys. Machine users also create them (the
 * value is shown once); a human's keys are their own, so operators only
 * read and revoke them. */
export function UserAPIKeys({ base, console, user, machine, canWrite }: { base: string; console: string; user: { id: string; name: string }; machine: boolean; canWrite: boolean }) {
  const path = `${base}/users/${user.id}/api-keys`
  const list = usePaginatedList<APIKey>(path, { limit: 50 })
  const [adding, setAdding] = useState(false)
  const [issued, setIssued] = useState<IssuedKey | null>(null)
  const [revoke, setRevoke] = useState<APIKey | null>(null)
  const add = machine && canWrite && <Button variant="outline" size="sm" onClick={() => setAdding(true)}><Plus /> {t('Create API key')}</Button>
  return <DetailSection title={t('API keys')} description={machine
    ? t('Each key acts as this machine user in one organization for one resource, with every permission the machine user holds there or only the ones you pick. Send it as a bearer token.')
    : t('Personal keys this user created for themselves. They can only revoke them here: new keys are made by the user.')} actions={list.data.length > 0 && add}>
    <KeysTable keys={list.data} loading={list.loading} error={list.error} retry={list.reload} console={console}
      columns={{ organization: true, resource: true, createdBy: !machine }}
      onRevoke={canWrite ? setRevoke : undefined}
      empty={<EmptyState icon={<KeySquare />} title={t('No API keys')} description={machine ? t('Add the machine user to an organization first, then create a key. The key is shown once.') : t('This user has not created any API keys.')} action={add} />} />
    {adding && <KeyForm base={base} user={user.id} path={path} onClose={() => setAdding(false)} onCreated={key => { setIssued(key); list.reload() }} />}
    {issued && <IssuedKeyDialog issued={issued} onClose={() => setIssued(null)} />}
    {revoke && <RevokeKeyDialog apiKey={revoke} onClose={() => setRevoke(null)} remove={async () => { await api.delete(`${path}/${revoke.id}`); toast.success(t('Key revoked')); list.reload() }} />}
  </DetailSection>
}

function KeyForm({ base, user, path, onClose, onCreated }: { base: string; user: string; path: string; onClose: () => void; onCreated: (key: IssuedKey) => void }) {
  const id = useId()
  const [organization, setOrganization] = useState('')
  const [application, setApplication] = useState('')
  const [resource, setResource] = useState('')
  const [available, setAvailable] = useState<string[]>([])
  const [permissions, setPermissions] = useState<string[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  const expiry = useExpiry()
  const memberOf = useMemo(() => ({ user_id: user }), [user])
  const unauthorized = useNoRoles(base, user, organization, resource)
  useEffect(() => {
    setAvailable([]); setPermissions([])
    if (!resource) return
    const controller = new AbortController()
    api.get<{ permissions?: string[] }>(`${base}/resources/${resource}`, controller.signal).then(r => setAvailable(r.permissions ?? [])).catch(() => {})
    return () => controller.abort()
  }, [base, resource])
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}>
    <DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{t('Create API key')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('The key carries the roles and grants the machine user holds in the organization, checked at every use. Pick permissions to narrow it further.')}</DialogDescription>
      <form className="space-y-4" onSubmit={async event => {
        event.preventDefault(); if (pending.current) return
        const form = new FormData(event.currentTarget)
        const data = {
          name: String(form.get('name') ?? '').trim(),
          organization_id: String(form.get('organization_id') ?? ''),
          application_id: String(form.get('application_id') ?? ''),
          resource_id: String(form.get('resource_id') ?? ''),
          ...(permissions.length ? { permissions } : {}),
          expires_in: expiry.value,
        }
        pending.current = true; setBusy(true); setError('')
        try {
          const result = await api.post<IssuedKey>(path, data)
          toast.success(t('API key created')); onCreated(result); onClose()
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
            <p className="text-muted-foreground">{t('The key is refused (401) until it gets one. Assign a role, directly or through a group, before or after creating the key.')}</p>
          </div>
        </div>}
        {available.length > 0 && <PermissionChecks available={available} selected={permissions} onChange={setPermissions} disabled={busy} hint={t('Optional. With none selected the key carries all of the machine user\'s permissions.')} />}
        <ExpiryField id={`${id}-ttl`} expiry={expiry} disabled={busy} />
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
 * group) on the resource in the organization, once both are chosen: a key
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
