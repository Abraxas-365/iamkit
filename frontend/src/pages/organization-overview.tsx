import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Ban, KeyRound, Pencil, Plus, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ConfirmDialog, DataTable, DetailSection, EmptyState, FormDialog, Properties, SwitchField } from '@/components/library/patterns'
import { CreateConnectionDialog, providerLabel } from './federation-connection-form'
import { useOrganization } from './organization-layout'
import { OrganizationPasswordRequirements } from './organization-password'

const methods = [
  ['allow_password', 'Password', 'Email and password, including password reset.'],
  ['allow_email_code', 'Email code', 'A one-time code sent by email.'],
  ['allow_social', 'Social', 'Environment connections such as Google or Microsoft.'],
] as const

/** OrganizationOverview holds the organization's settings: name,
 * metadata, MFA policy, sign-in methods, password requirements and
 * activation. */
export function OrganizationOverview() {
  const { project, environment } = useParams()
  const { org, reload } = useOrganization()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const path = `/environments/${environment}/organizations/${org.id}`
  const [editing, setEditing] = useState(false)
  const [saving, setSaving] = useState('')
  const [toggle, setToggle] = useState(false)

  async function patch(field: string, body: Record<string, unknown>, done: string) {
    setSaving(field)
    try { await api.patch(path, body); toast.success(done); reload() } catch (e) { toast.error(message(e)) } finally { setSaving('') }
  }
  const metadata = org.metadata && Object.keys(org.metadata).length ? JSON.stringify(org.metadata, null, 2) : ''

  return <div className="space-y-6">
    <DetailSection title="Details" actions={canWrite && <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil /> Edit</Button>}>
      <Properties items={[
        ['Name', org.name],
        ['Metadata', metadata ? <pre className="max-h-48 overflow-auto rounded-md bg-muted/50 p-2 font-mono text-xs">{metadata}</pre> : <span className="text-muted-foreground">None</span>],
      ]} />
    </DetailSection>

    <DetailSection title="Multi-factor authentication" description="Applies to every member when they sign in to this organization.">
      <div className="space-y-4">
        <SwitchField label="Require a second factor" hint="Password and email-code sign-ins need an authenticator app; members without one enroll while signing in." checked={org.mfa_required} disabled={!canWrite || !!saving} onCheckedChange={v => patch('mfa_required', { mfa_required: v }, v ? 'Second factor required' : 'Second factor no longer required')} />
        <SwitchField label="Also require it for SSO sign-ins" hint="By default the identity provider is trusted to have done its own MFA." checked={org.mfa_for_federated} disabled={!canWrite || !!saving} onCheckedChange={v => patch('mfa_for_federated', { mfa_for_federated: v }, v ? 'SSO sign-ins now need a second factor' : 'SSO sign-ins trust the identity provider')} />
      </div>
    </DetailSection>

    <DetailSection title="Sign-in methods" description={<>Turn off methods the environment allows for members signing in to this organization; they cannot turn on what <Link className="text-primary hover:underline" to={`/projects/${project}/environments/${environment}/sign-in-policy`}>Sign-in methods</Link> turns off. The organization's own SSO is not affected.</>}>
      <div className="space-y-4">
        {methods.map(([key, label, hint]) => <SwitchField key={key} label={label} hint={hint} checked={org[key]} disabled={!canWrite || !!saving} onCheckedChange={v => patch(key, { [key]: v }, `${label} sign-in ${v ? 'allowed' : 'turned off'}`)} />)}
      </div>
    </DetailSection>

    <OrganizationPasswordRequirements organization={org.id} canWrite={canWrite} />

    {canWrite && <DetailSection danger title={org.active ? 'Deactivate organization' : 'Reactivate organization'} description={org.active ? 'Members can no longer sign in to this organization and existing sessions stop refreshing. Nothing is deleted.' : 'Members can sign in to this organization again.'}>
      <Button variant={org.active ? 'destructive' : 'outline'} onClick={() => setToggle(true)}>{org.active ? <><Ban /> Deactivate</> : <><RotateCcw /> Reactivate</>}</Button>
    </DetailSection>}

    {editing && <FormDialog title="Edit organization" description="Rename the organization or change its metadata." fields={[
      { name: 'name', label: 'Name', value: org.name },
      { name: 'metadata', label: 'Metadata (JSON)', optional: true, value: org.metadata ? JSON.stringify(org.metadata) : '', hint: 'Arbitrary JSON object, e.g. {"plan":"enterprise"}. Included in tokens for this organization.' },
    ]} onClose={() => setEditing(false)} submit={async values => {
      const body: Record<string, unknown> = { name: values.name }
      if (values.metadata) {
        try { body.metadata = JSON.parse(String(values.metadata)) } catch { throw new Error('Metadata must be valid JSON') }
      } else body.metadata = {}
      await api.patch(path, body); reload()
    }} />}
    {toggle && <ConfirmDialog title={org.active ? `Deactivate ${org.name}?` : `Reactivate ${org.name}?`} description={org.active ? 'Members are blocked from signing in to this organization until you reactivate it.' : 'Members regain access with their existing roles and grants.'} confirmLabel={org.active ? 'Deactivate' : 'Reactivate'} onClose={() => setToggle(false)} confirm={async () => { await api.patch(path, { active: !org.active }); toast.success(org.active ? 'Organization deactivated' : 'Organization reactivated'); reload() }} />}
  </div>
}

interface Connection { id: string; name: string; provider: string; issuer: string; active: boolean; linked: number; enforcement: string; jit_provisioning: boolean }

/** OrganizationConnections lists the SSO connections that belong to this
 * organization. */
export function OrganizationConnections() {
  const { project, environment } = useParams()
  const { org } = useOrganization()
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const console = `/projects/${project}/environments/${environment}`
  const extra = useMemo(() => ({ organization_id: org.id }), [org.id])
  const list = usePaginatedList<Connection>(`/environments/${environment}/federation-connections`, { extraParams: extra })
  const [adding, setAdding] = useState(false)
  const add = canWrite && <Button onClick={() => setAdding(true)}><Plus /> Add SSO connection</Button>
  return <div className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <p className="max-w-2xl text-sm text-muted-foreground">Enterprise identity providers (Entra ID, Okta, Google Workspace…) that members of {org.name} sign in with. Social login buttons shared by every organization are under Sign-in providers.</p>
      {list.data.length > 0 && add}
    </div>
    <DataTable
      columns={['Connection', { header: 'Sign-in', hideBelow: 'sm' }, { header: 'Linked users', hideBelow: 'md', align: 'right' }, 'Status']}
      loading={list.loading} error={list.error} retry={list.reload}
      rowHref={i => `${console}/federation/${list.data[i].id}`}
      empty={<EmptyState icon={<KeyRound />} title="No SSO connection" description={`Connect ${org.name}'s identity provider so its members sign in with their work account.`} action={add} />}
      rows={list.data.map(c => [
        <span className="block min-w-0"><Link to={`${console}/federation/${c.id}`} className="font-medium hover:text-primary hover:underline">{c.name}</Link><span className="block truncate text-xs text-muted-foreground">{providerLabel(c.provider)}</span></span>,
        c.enforcement === 'enforced' ? <Badge variant="secondary" className="bg-primary/10 text-primary">SSO required</Badge> : <span className="text-sm text-muted-foreground">Optional</span>,
        <span className="tabular-nums">{c.linked}</span>,
        <Badge variant="secondary" className={c.active ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}>{c.active ? 'Active' : 'Disabled'}</Badge>,
      ])} />
    {adding && <CreateConnectionDialog base={`/environments/${environment}`} kind="sso" organization={org} onClose={() => setAdding(false)} onCreated={list.reload} />}
  </div>
}
