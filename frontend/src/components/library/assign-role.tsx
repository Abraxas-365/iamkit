import { useEffect, useId, useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { SearchSelect } from '@/components/ui/search-select'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ErrorState, RadioCards } from './patterns'
import { t } from '@/lib/i18n'

export type AssignTarget = 'user' | 'group'
interface Ref { id: string; name: string }

type Item = Record<string, unknown>
const named = (item: Item) => ({ id: String(item.id), label: String(item.name || item.id), inactive: item.active === false })
const member = (item: Item) => ({ id: String(item.user_id), label: item.user_email ? `${item.user_name || item.user_email} (${item.user_email})` : String(item.user_name ?? item.user_id), inactive: item.active === false })
const role = (item: Item) => ({ id: String(item.id), label: item.resource_name ? `${item.name} · ${item.resource_name}` : String(item.name ?? item.id) })

/**
 * useHeldRoles maps the roles the subject already holds in the organization to
 * a picker hint: "Assigned" for a direct (or group) binding, "Via <group>" for
 * a user's role inherited from a group. Empty until both are known.
 */
// Held is how the subject holds a role: directly (no group) or through a group.
type Held = { group?: string }

function useHeldRoles(base: string, target: AssignTarget, org: string, subject: string) {
  const [held, setHeld] = useState<Map<string, Held>>(new Map())
  useEffect(() => {
    setHeld(new Map())
    if (!org || !subject) return
    const controller = new AbortController()
    const q = new URLSearchParams({ organization_id: org })
    const request = target === 'group'
      ? api.list<Item>(`${base}/group-role-assignments?${q}&group_id=${subject}&limit=100`, controller.signal)
        .then(r => new Map<string, Held>(r.data.map(a => [String(a.role_id), {}])))
      : api.list<Item>(`${base}/effective-roles?${q}&user_id=${subject}`, controller.signal)
        .then(r => {
          const out = new Map<string, Held>()
          for (const a of r.data) {
            const id = String(a.role_id)
            if (a.source === 'direct') out.set(id, {})
            else if (!out.has(id)) out.set(id, { group: String(a.group_name) })
          }
          return out
        })
    // Best effort: without it the server still rejects duplicates clearly.
    request.then(setHeld).catch(() => {})
    return () => controller.abort()
  }, [base, target, org, subject])
  return held
}

function heldHint(held: Held | undefined): string | undefined {
  if (!held) return undefined
  return held.group ? t('Via {{group}}', { group: held.group }) : t('Assigned')
}

const targets = [
  { value: 'user', label: t('A user'), description: t('One member of the organization.') },
  { value: 'group', label: t('A group'), description: t('Every member of the group, now and later.') },
]

/**
 * AssignRoleDialog gives a role to a user or a group within one organization.
 * Whatever is preset (organization, user or group) is fixed; the rest is picked.
 * Users are picked among the organization's members, since only members can
 * hold roles in it, and groups among its groups.
 */
export function AssignRoleDialog({ base, organization, user, group, target: initial = 'user', onClose, onAssigned }: {
  base: string
  organization?: Ref
  user?: Ref
  group?: Ref
  target?: AssignTarget
  onClose: () => void
  onAssigned?: (target: AssignTarget) => void
}) {
  const id = useId()
  const fixed: AssignTarget | undefined = user ? 'user' : group ? 'group' : undefined
  const [target, setTarget] = useState<AssignTarget>(fixed ?? initial)
  const [org, setOrg] = useState(organization?.id ?? '')
  const [subject, setSubject] = useState(user?.id ?? group?.id ?? '')
  const [picked, setPicked] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const held = useHeldRoles(base, target, org, subject)
  const already = picked ? held.get(picked) : undefined

  const who = user?.name ?? group?.name
  const description = fixed === 'group'
    ? (organization ? t('Every member of {{who}} holds the role in {{organization}}, in addition to their own roles.', { who, organization: organization.name }) : t('Every member of {{who}} holds the role, in addition to their own roles.', { who }))
    : fixed === 'user'
      ? (organization ? t('{{who}} gets the role’s permissions in {{organization}}.', { who, organization: organization.name }) : t('{{who}} gets the role’s permissions.', { who }))
      : t('Give a user, or every member of a group, a role within one organization.')

  const submit = async () => {
    setBusy(true); setError('')
    try {
      if (target === 'group') await api.post(`${base}/group-role-assignments`, { organization_id: org, group_id: subject, role_id: picked })
      else await api.post(`${base}/role-assignments`, { organization_id: org, user_id: subject, role_id: picked })
      toast.success(t('Role assigned'))
      onAssigned?.(target)
      onClose()
    } catch (e) {
      setError(message(e))
    } finally {
      setBusy(false)
    }
  }

  return <Dialog open onOpenChange={open => { if (!open && !busy) onClose() }}>
    <DialogContent>
      <DialogTitle className="text-base font-semibold">{who ? t('Assign a role to {{who}}', { who }) : t('Assign a role')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{description}</DialogDescription>
      <div className="space-y-4">
        {!fixed && <RadioCards name="target" label={t('Assign to')} options={targets} value={target} disabled={busy} onChange={v => { setTarget(v as AssignTarget); setSubject('') }} />}
        {!organization && <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-org`}>{t('Organization')}</label>
          <SearchSelect id={`${id}-org`} name="organization_id" path={`${base}/organizations`} mapItem={named} disabled={busy} placeholder={t('Search organizations…')} onChange={v => { setOrg(v); if (!fixed) setSubject('') }} />
        </div>}
        {!fixed && <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-subject`}>{target === 'group' ? t('Group') : t('User')}</label>
          {org
            ? <SearchSelect key={`${target}:${org}`} id={`${id}-subject`} name={target === 'group' ? 'group_id' : 'user_id'} path={`${base}/organizations/${org}/${target === 'group' ? 'groups' : 'members'}`} mapItem={target === 'group' ? named : member} disabled={busy} placeholder={target === 'group' ? t('Search groups…') : t('Search members…')} onChange={setSubject} />
            : <p id={`${id}-subject`} className="rounded-lg border border-dashed px-2.5 py-1.5 text-sm text-muted-foreground">{t('Pick an organization first.')}</p>}
        </div>}
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-role`}>{t('Role')}</label>
          <SearchSelect id={`${id}-role`} name="role_id" path={`${base}/roles`} mapItem={item => ({ ...role(item), hint: heldHint(held.get(String(item.id))) })} disabled={busy} placeholder={t('Search roles…')} onChange={setPicked} />
          {already && <p className="text-xs text-muted-foreground" role="status">{!already.group ? (target === 'group' ? t('The group already holds this role here.') : t('The user already holds this role here.')) : t('The user already holds this role {{how}}; a direct assignment keeps it if they leave the group.', { how: t('via {{group}}', { group: already.group }) })}</p>}
        </div>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button>
          <Button disabled={busy || !org || !subject || !picked || (!!already && !already.group)} onClick={submit}>{busy ? t('Assigning…') : t('Assign role')}</Button>
        </div>
      </div>
    </DialogContent>
  </Dialog>
}
