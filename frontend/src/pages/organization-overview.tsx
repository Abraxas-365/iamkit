import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { Ban, KeyRound, Pencil, Plus, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { message } from '@/lib/utils'
import { FACTORS, toggleFactor } from '@/lib/factors'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ConfirmDialog, DataTable, DetailSection, EmptyState, FormDialog, Properties, SwitchField } from '@/components/library/patterns'
import { CreateConnectionDialog, providerLabel } from './federation-connection-form'
import { useOrganization } from './organization-layout'
import { OrganizationPasswordRequirements } from './organization-password'
import { MetadataEditor } from '@/components/library/metadata-editor'
import { HistorySection } from './history'
import { t } from '@/lib/i18n'

const methods = [
  ['allow_password', t('Password'), t('Email and password, including password reset.')],
  ['allow_email_code', t('Email code'), t('A one-time code sent by email.')],
  ['allow_social', t('Social'), t('Environment connections such as Google or Microsoft.')],
  ['allow_passkey', t('Passkey'), t('A passkey alone, without password or second factor. Needs security keys among the allowed factors.')],
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

  return <div className="space-y-6">
    <DetailSection title={t('Details')} actions={canWrite && <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil /> {t('Edit')}</Button>}>
      <Properties items={[
        [t('Name'), org.name],
      ]} />
    </DetailSection>

    <MetadataEditor path={path} metadata={org.metadata} canWrite={canWrite} reload={reload} description={t('Free-form operator data, included in tokens for this organization: up to 64 keys, 4 KiB per value, 32 KiB in total. Every change is audited.')} />

    <DetailSection title={t('Multi-factor authentication')} description={t('Applies to every member when they sign in to this organization.')}>
      <div className="space-y-4">
        <SwitchField label={t('Require a second factor')} hint={t('Password and email-code sign-ins need a second factor; members without one enroll while signing in.')} checked={org.mfa_required} disabled={!canWrite || !!saving} onCheckedChange={v => patch('mfa_required', { mfa_required: v }, v ? t('Second factor required') : t('Second factor no longer required'))} />
        <SwitchField label={t('Also require it for SSO sign-ins')} hint={t('By default the identity provider is trusted to have done its own MFA.')} checked={org.mfa_for_federated} disabled={!canWrite || !!saving} onCheckedChange={v => patch('mfa_for_federated', { mfa_for_federated: v }, v ? t('SSO sign-ins now need a second factor') : t('SSO sign-ins trust the identity provider'))} />
        <div className="space-y-3 border-t pt-4">
          <p className="text-sm font-medium">{t('Accepted second factors')}</p>
          <p className="text-xs text-muted-foreground">{t('Narrows the environment\'s')} <Link className="text-primary hover:underline" to={`/projects/${project}/environments/${environment}/sign-in-policy`}>{t('allowed factors')}</Link> {t('for this organization; it cannot allow what the environment refuses.')}</p>
          {FACTORS.map(f => {
            const factors = org.allowed_factors ?? FACTORS.map(x => x.kind)
            const on = factors.includes(f.kind)
            return <SwitchField key={f.kind} label={f.label} hint={f.hint} checked={on} disabled={!canWrite || !!saving || (on && factors.length === 1)} onCheckedChange={v => patch(`factor-${f.kind}`, { allowed_factors: toggleFactor(factors, f.kind, v) }, v ? t('{{factor}} accepted', { factor: f.label }) : t('{{factor}} no longer accepted', { factor: f.label }))} />
          })}
        </div>
      </div>
    </DetailSection>

    <DetailSection title={t('Sign-in methods')} description={<>{t('Turn off methods the environment allows for members signing in to this organization; they cannot turn on what')} <Link className="text-primary hover:underline" to={`/projects/${project}/environments/${environment}/sign-in-policy`}>{t('Sign-in methods')}</Link> {t('turns off. The organization\'s own SSO is not affected.')}</>}>
      <div className="space-y-4">
        {methods.map(([key, label, hint]) => <SwitchField key={key} label={label} hint={hint} checked={org[key]} disabled={!canWrite || !!saving} onCheckedChange={v => patch(key, { [key]: v }, v ? t('{{method}} sign-in allowed', { method: label }) : t('{{method}} sign-in turned off', { method: label }))} />)}
      </div>
    </DetailSection>

    <OrganizationPasswordRequirements organization={org.id} canWrite={canWrite} />

    {canWrite && <DetailSection danger title={org.active ? t('Deactivate organization') : t('Reactivate organization')} description={org.active ? t('Members can no longer sign in to this organization and existing sessions stop refreshing. Nothing is deleted.') : t('Members can sign in to this organization again.')}>
      <Button variant={org.active ? 'destructive' : 'outline'} onClick={() => setToggle(true)}>{org.active ? <><Ban /> {t('Deactivate')}</> : <><RotateCcw /> {t('Reactivate')}</>}</Button>
    </DetailSection>}

    <HistorySection path={path} refresh={org} />

    {editing && <FormDialog title={t('Edit organization')} description={t('Rename the organization.')} fields={[
      { name: 'name', label: t('Name'), value: org.name },
    ]} onClose={() => setEditing(false)} submit={async values => {
      await api.patch(path, { name: values.name }); reload()
    }} />}
    {toggle && <ConfirmDialog title={org.active ? t('Deactivate {{name}}?', { name: org.name }) : t('Reactivate {{name}}?', { name: org.name })} description={org.active ? t('Members are blocked from signing in to this organization until you reactivate it.') : t('Members regain access with their existing roles and grants.')} confirmLabel={org.active ? t('Deactivate') : t('Reactivate')} onClose={() => setToggle(false)} confirm={async () => { await api.patch(path, { active: !org.active }); toast.success(org.active ? t('Organization deactivated') : t('Organization reactivated')); reload() }} />}
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
  const add = canWrite && <Button onClick={() => setAdding(true)}><Plus /> {t('Add SSO connection')}</Button>
  return <div className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <p className="max-w-2xl text-sm text-muted-foreground">{t('Enterprise identity providers (Entra ID, Okta, Google Workspace…) that members of {{name}} sign in with. Social login buttons shared by every organization are under Sign-in providers.', { name: org.name })}</p>
      {list.data.length > 0 && add}
    </div>
    <DataTable
      columns={[t('Connection'), { header: t('Sign-in'), hideBelow: 'sm' }, { header: t('Linked users'), hideBelow: 'md', align: 'right' }, t('Status')]}
      loading={list.loading} error={list.error} retry={list.reload}
      rowHref={i => `${console}/federation/${list.data[i].id}`}
      empty={<EmptyState icon={<KeyRound />} title={t('No SSO connection')} description={t('Connect {{name}}\'s identity provider so its members sign in with their work account.', { name: org.name })} action={add} />}
      rows={list.data.map(c => [
        <span className="block min-w-0"><Link to={`${console}/federation/${c.id}`} className="font-medium hover:text-primary hover:underline">{c.name}</Link><span className="block truncate text-xs text-muted-foreground">{providerLabel(c.provider)}</span></span>,
        c.enforcement === 'enforced' ? <Badge variant="secondary" className="bg-primary/10 text-primary">{t('SSO required')}</Badge> : <span className="text-sm text-muted-foreground">{t('Optional')}</span>,
        <span className="tabular-nums">{c.linked}</span>,
        <Badge variant="secondary" className={c.active ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}>{c.active ? t('Active') : t('Disabled')}</Badge>,
      ])} />
    {adding && <CreateConnectionDialog base={`/environments/${environment}`} kind="sso" organization={org} onClose={() => setAdding(false)} onCreated={list.reload} />}
  </div>
}
