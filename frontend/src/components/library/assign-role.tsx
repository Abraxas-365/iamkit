import { useEffect, useId, useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { SearchSelect } from '@/components/ui/search-select'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ErrorState, RadioCards } from './patterns'

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
function useHeldRoles(base: string, target: AssignTarget, org: string, subject: string) {
  const [held, setHeld] = useState<Map<string, string>>(new Map())
  useEffect(() => {
    setHeld(new Map())
    if (!org || !subject) return
    const controller = new AbortController()
    const q = new URLSearchParams({ organization_id: org })
    const request = target === 'group'
      ? api.list<Item>(`${base}/group-role-assignments?${q}&group_id=${subject}&limit=100`, controller.signal)
        .then(r => new Map(r.data.map(a => [String(a.role_id), 'Assigned'])))
      : api.list<Item>(`${base}/effective-roles?${q}&user_id=${subject}`, controller.signal)
        .then(r => {
          const out = new Map<string, string>()
          for (const a of r.data) {
            const id = String(a.role_id)
            if (a.source === 'direct') out.set(id, 'Assigned')
            else if (!out.has(id)) out.set(id, `Via ${a.group_name}`)
          }
          return out
        })
    // Best effort: without it the server still rejects duplicates clearly.
    request.then(setHeld).catch(() => {})
    return () => controller.abort()
  }, [base, target, org, subject])
  return held
}

const targets = [
  { value: 'user', label: 'A user', description: 'One member of the organization.' },
  { value: 'group', label: 'A group', description: 'Every member of the group, now and later.' },
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
  const where = organization ? ` in ${organization.name}` : ''
  const description = fixed === 'group' ? `Every member of ${who} holds the role${where}, in addition to their own roles.`
    : fixed === 'user' ? `${who} gets the role's permissions${where}.`
      : 'Give a user, or every member of a group, a role within one organization.'

  const submit = async () => {
    setBusy(true); setError('')
    try {
      if (target === 'group') await api.post(`${base}/group-role-assignments`, { organization_id: org, group_id: subject, role_id: picked })
      else await api.post(`${base}/role-assignments`, { organization_id: org, user_id: subject, role_id: picked })
      toast.success('Role assigned')
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
      <DialogTitle className="text-base font-semibold">{who ? `Assign a role to ${who}` : 'Assign a role'}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{description}</DialogDescription>
      <div className="space-y-4">
        {!fixed && <RadioCards name="target" label="Assign to" options={targets} value={target} disabled={busy} onChange={v => { setTarget(v as AssignTarget); setSubject('') }} />}
        {!organization && <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-org`}>Organization</label>
          <SearchSelect id={`${id}-org`} name="organization_id" path={`${base}/organizations`} mapItem={named} disabled={busy} placeholder="Search organizations…" onChange={v => { setOrg(v); if (!fixed) setSubject('') }} />
        </div>}
        {!fixed && <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-subject`}>{target === 'group' ? 'Group' : 'User'}</label>
          {org
            ? <SearchSelect key={`${target}:${org}`} id={`${id}-subject`} name={target === 'group' ? 'group_id' : 'user_id'} path={`${base}/organizations/${org}/${target === 'group' ? 'groups' : 'members'}`} mapItem={target === 'group' ? named : member} disabled={busy} placeholder={target === 'group' ? 'Search groups…' : 'Search members…'} onChange={setSubject} />
            : <p id={`${id}-subject`} className="rounded-lg border border-dashed px-2.5 py-1.5 text-sm text-muted-foreground">Pick an organization first.</p>}
        </div>}
        <div className="space-y-1.5">
          <label className="text-sm font-medium" htmlFor={`${id}-role`}>Role</label>
          <SearchSelect id={`${id}-role`} name="role_id" path={`${base}/roles`} mapItem={item => ({ ...role(item), hint: held.get(String(item.id)) })} disabled={busy} placeholder="Search roles…" onChange={setPicked} />
          {already && <p className="text-xs text-muted-foreground" role="status">{already === 'Assigned' ? `${target === 'group' ? 'The group' : 'The user'} already holds this role here.` : `The user already holds this role ${already.replace(/^Via /, 'via ')}; a direct assignment keeps it if they leave the group.`}</p>}
        </div>
        {error && <ErrorState error={error} />}
        <div className="flex justify-end gap-2 border-t pt-4">
          <Button variant="outline" disabled={busy} onClick={onClose}>Cancel</Button>
          <Button disabled={busy || !org || !subject || !picked || already === 'Assigned'} onClick={submit}>{busy ? 'Assigning…' : 'Assign role'}</Button>
        </div>
      </div>
    </DialogContent>
  </Dialog>
}
