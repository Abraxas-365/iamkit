import { useCallback, useEffect, useMemo, useState } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { Activity as ActivityIcon, Ban, ChevronLeft, ChevronRight, KeyRound } from 'lucide-react'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import { message } from '@/lib/utils'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { useList } from '@/hooks/use-list'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { RowActions } from '@/components/ui/menu'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { ConfirmDialog, CopyText, DataTable, EmptyState, EntityRef, PageHeader, Time, selectClass } from '@/components/library/patterns'
import { language, t } from '@/lib/i18n'

interface Session { id: string; user_id: string; user_name: string; user_email: string; organization_id: string; organization_name: string; application_id: string; application_name: string; resource_id: string; resource_name: string; authenticated_at: string; expires_at: string; revoked_at: string | null }
interface IAMEvent { id: number; type: string; actor: { kind: string; id: string }; subject: { kind: string; id: string }; organization_id?: string; data?: Record<string, unknown>; occurred_at: string }
interface EventPage { items: IAMEvent[]; next: number }
interface AuditEvent { id: string; actor_id: string; actor_label: string; actor_kind?: string; action: string; target_id: string; target_label?: string; created_at: string }

// actorKinds labels who acted when it was not an operator.
const actorKinds: Record<string, string> = { user: t('End user'), service_account: t('Service account'), system: t('System'), directory: t('Directory (SCIM)') }

// Each verb is a whole sentence with the item as a placeholder, so a
// translation can reorder it and agree with the noun.
const verbs: Record<string, (thing: string) => string> = {
  POST: thing => t('Created {{thing}}', { thing }), PUT: thing => t('Set {{thing}}', { thing }),
  PATCH: thing => t('Updated {{thing}}', { thing }), DELETE: thing => t('Deleted {{thing}}', { thing }),
}
const nouns: Record<string, string> = {
  users: t('user'), organizations: t('organization'), applications: t('application'), resources: t('resource'), roles: t('role'), grants: t('grant'),
  'role-assignments': t('role assignment'), 'group-role-assignments': t('group role assignment'), 'service-accounts': t('service account'), 'federation-connections': t('federation connection'),
  'oauth-clients': t('OAuth client'), 'provisioning-credentials': t('SCIM credential'), memberships: t('membership'), members: t('member'),
  groups: t('group'), domains: t('domain'), invitations: t('invitation'), sessions: t('session'), 'login-settings': t('hosted login settings'),
  clients: t('client style'), 'sign-in': t('sign-in methods'), factors: t('second factors'), identities: t('linked identity'), 'mfa-policy': t('MFA policy'),
  verify: t('domain verification'), resend: t('invitation'), revoke: t('credential'), 'logout-deliveries': t('logout delivery'), links: t('application link'), 'delivery-settings': t('notification settings'),
}
const named: Record<string, string> = {
  'federation.jit': t('User signed up through federation'), 'federation.email': t('User linked by verified email through federation'),
  'federation.profile_updated': t('Profile updated from the identity provider'), 'invitation.accept': t('Invitation accepted'),
  'mfa.enrolled': t('Second factor enrolled'), 'mfa.removed': t('Second factor removed'), 'mfa.recovery_regenerated': t('Recovery codes regenerated'),
  'mfa.recovery_used': t('Recovery code used'), 'mfa.reset': t('Second factors reset'), 'mfa.locked': t('Second factor locked after failed attempts'),
  'mfa.clone_detected': t('Cloned security key refused'),
  'oauth.logout': t('Signed out of an application (OIDC logout)'), 'oauth.backchannel_failed': t('Back-channel logout delivery failed'), 'oauth.device_approved': t('Approved a device sign-in'), 'oauth.token_exchanged': t('Exchanged a token for another resource'), 'oauth.impersonated': t('A service account impersonated a user'),
  'service_account.authentication': t('Changed how a service account authenticates'),
  'service_account.impersonation': t('Changed whether a service account may impersonate users'),
  'signing_key.create': t('Created a signing key'), 'signing_key.activate': t('Activated a signing key'), 'signing_key.retire': t('Retired a signing key'),
  'saml_service_provider.create': t('Added a SAML application'), 'saml_service_provider.update': t('Updated a SAML application'), 'saml_service_provider.delete': t('Deleted a SAML application'), 'saml.assertion_issued': t('Signed in to a SAML application'),
  'sms.update': t('Updated SMS delivery'), 'sms.delete': t('Removed SMS delivery'), 'sms.test': t('Sent a test SMS'),
  impersonate: t('Impersonated a user'),
  'user.signup': t('User signed up'), 'user.deactivated': t('Deactivated a user'), 'user.reactivated': t('Reactivated user'),
  'user.locked': t('User locked after failed sign-ins'), 'user.unlocked': t('Unlocked a user'),
  'user.profile_updated': t('Updated a user profile'), 'user.metadata_set': t('Set user metadata'), 'user.metadata_deleted': t('Removed user metadata'),
  'user.phone_verified': t('Phone number verified'), 'user.phone_verified_set': t('Changed whether a phone number is verified'), 'user.phone_removed': t('Phone number removed'),
  'user.access_token_created': t('Created a personal access token'), 'user.access_token_revoked': t('Revoked a personal access token'),
  'user.key_added': t('Added a machine user key'), 'user.key_removed': t('Removed a machine user key'),
  'user.schema_updated': t('Updated the user schema'), 'user.schema_deleted': t('Removed the user schema'),
  'organization.metadata_set': t('Set organization metadata'), 'organization.metadata_deleted': t('Removed organization metadata'),
  'invitation.create': t('Invited a user'), 'invitation.resend': t('Resent invitation'), 'invitation.revoke': t('Revoked an invitation'),
  'action_target.create': t('Added an action target'), 'action_target.update': t('Updated an action target'), 'action_target.delete': t('Deleted an action target'),
  'action_target.rotate_secret': t('Rotated an action target secret'), 'action_execution.set': t('Bound action targets to a trigger'), 'action_execution.delete': t('Removed the actions of a trigger'),
  'org_admin_portal.enabled': t('Enabled the organization admin portal'), 'org_admin_portal.disabled': t('Disabled the organization admin portal'),
  'delivery.update': t('Updated email delivery'), 'delivery.delete': t('Removed email delivery'), 'delivery.test': t('Sent a test email'),
  'email_template.updated': t('Customized an email template'), 'email_template.reset': t('Reset an email template'),
  'password_policy.update': t('Updated the password policy'), 'password_policy.delete': t('Reset the password policy'),
  'organization_password_policy.update': t('Updated an organization password policy'), 'organization_password_policy.delete': t('Removed an organization password policy'),
  'sign_in_policy.update': t('Updated the sign-in policy'), 'sign_in_policy.delete': t('Reset the sign-in policy'),
  'webhook.create': t('Added a webhook'), 'webhook.update': t('Updated a webhook'), 'webhook.delete': t('Deleted a webhook'),
  'webhook.rotate_secret': t('Rotated a webhook secret'), 'webhook.replay': t('Replayed webhook events'), 'webhook.retry': t('Retried a webhook delivery'),
  'webhook.disabled': t('Webhook disabled after failing deliveries'),
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-/i

/** describeAction turns a stored audit action (a named event, or the HTTP
 * method of a management call) and its target path into a short sentence. */
export function describeAction(action: string, target = '') {
  if (named[action]) return named[action]
  if (action.startsWith('federation.')) return t('User linked through federation')
  const sentence = verbs[action]
  if (!sentence) return action
  const parts = target.split('?')[0].split('/').filter(Boolean)
  const i = parts.findIndex(p => p === 'environments')
  // Organization administration paths (/organizations/:id/admin/…) name
  // the same things as the operator routes.
  const rest = (i >= 0 ? parts.slice(i + 2) : parts).filter(p => !uuid.test(p) && p !== 'admin')
  const last = rest[rest.length - 1]
  if (!last) return sentence(t('environment'))
  if (last === 'verify') return t('Verified domain')
  if (last === 'resend') return t('Resent invitation')
  if (last === 'revoke') return t('Revoked credential')
  if (last === 'retry' && rest.includes('logout-deliveries')) return t('Retried a logout delivery')
  if (last === 'reactivate') return t('Reactivated user')
  if (last === 'suspend') return t('Suspended user')
  if (last === 'force-verify') return t('Marked domain verified')
  if (last === 'permanent') return t('Permanently deleted user')
  if (last === 'profile') return t('Updated member profile')
  // Action-style POSTs end in a verb segment (handled above); any other
  // POST creates the item its path names.
  return sentence(nouns[last] ?? last.replace(/-/g, ' '))
}

const eventWords: Record<string, string> = {
  action: t('action'), action_execution: t('action binding'), action_target: t('action target'), application: t('application'), branding: t('branding'),
  connection: t('federation connection'), delivery: t('email delivery'), device: t('device sign-in'), domain: t('domain'), email_template: t('email template'),
  feature: t('feature'), grant: t('grant'), group: t('group'), group_role: t('group role'), identity: t('linked identity'), impersonation: t('impersonation'),
  invitation: t('invitation'), login: t('sign-in'), logout_delivery: t('logout delivery'), membership: t('membership'), mfa: t('second factor'),
  oauth_client: t('OAuth client'), org_admin_portal: t('organization admin portal'), org_unit: t('org unit'), organization: t('organization'),
  password_policy: t('password policy'), position: t('position'), provisioning_credential: t('SCIM credential'), provisioning_identity: t('SCIM identity'),
  resource: t('resource'), resource_grant: t('resource grant'), role: t('role'), saml: t('SAML'), saml_service_provider: t('SAML application'),
  service_account: t('service account'), session: t('session'), sign_in_options: t('sign-in options'), sign_in_policy: t('sign-in methods'),
  sign_in_texts: t('sign-in texts'), signing_key: t('signing key'), sms: t('SMS delivery'), token: t('token'), user: t('user'), user_schema: t('user schema'),
  webhook: t('webhook'),
}
// eventVerbs are sentences about the event's subject, one per verb.
const eventVerbs: Record<string, (subject: string) => string> = {
  accepted: subject => t('{{subject}} accepted', { subject }), activated: subject => t('{{subject}} activated', { subject }),
  approved: subject => t('{{subject}} approved', { subject }), assigned: subject => t('{{subject}} assigned', { subject }),
  created: subject => t('{{subject}} created', { subject }), deactivated: subject => t('{{subject}} deactivated', { subject }),
  deleted: subject => t('{{subject}} deleted', { subject }), disabled: subject => t('{{subject}} disabled', { subject }),
  enabled: subject => t('{{subject}} enabled', { subject }), enrolled: subject => t('{{subject}} enrolled', { subject }),
  exchanged: subject => t('{{subject}} exchanged', { subject }), failed: subject => t('{{subject}} failed', { subject }),
  linked: subject => t('{{subject}} linked', { subject }), locked: subject => t('{{subject}} locked', { subject }),
  provisioned: subject => t('{{subject}} provisioned', { subject }), deprovisioned: subject => t('{{subject}} deprovisioned', { subject }),
  reactivated: subject => t('{{subject}} reactivated', { subject }), removed: subject => t('{{subject}} removed', { subject }),
  replayed: subject => t('{{subject}} replayed', { subject }), resent: subject => t('{{subject}} resent', { subject }),
  reset: subject => t('{{subject}} reset', { subject }), retired: subject => t('{{subject}} retired', { subject }),
  retried: subject => t('{{subject}} retried', { subject }), revoked: subject => t('{{subject}} revoked', { subject }),
  started: subject => t('{{subject}} started', { subject }), tested: subject => t('{{subject}} tested', { subject }),
  unassigned: subject => t('{{subject}} unassigned', { subject }), unlinked: subject => t('{{subject}} unlinked', { subject }),
  unlocked: subject => t('{{subject}} unlocked', { subject }), updated: subject => t('{{subject}} updated', { subject }),
  verified: subject => t('{{subject}} verified', { subject }), access_updated: subject => t('{{subject}} access updated', { subject }),
  secret_rotated: subject => t('{{subject}} secret rotated', { subject }), metadata_set: subject => t('{{subject}} metadata set', { subject }),
  metadata_deleted: subject => t('{{subject}} metadata deleted', { subject }), delivery_retried: subject => t('{{subject}} delivery retried', { subject }),
  profile_updated: subject => t('{{subject}} profile updated', { subject }), profile_synced: subject => t('{{subject}} profile synced', { subject }),
  phone_verified: subject => t('{{subject}} phone verified', { subject }), phone_removed: subject => t('{{subject}} phone removed', { subject }),
  key_added: subject => t('{{subject}} key added', { subject }), key_removed: subject => t('{{subject}} key removed', { subject }),
  access_token_created: subject => t('{{subject}} access token created', { subject }), access_token_revoked: subject => t('{{subject}} access token revoked', { subject }),
}
const eventNamed: Record<string, string> = {
  'login.failed': t('Sign-in failed'), 'session.created': t('Signed in'), 'session.revoked': t('Session ended'),
  'user.signed_up': t('User signed up'), 'user.provisioned': t('User provisioned by the directory'), 'user.deprovisioned': t('User deprovisioned by the directory'),
  'application.resource_linked': t('Linked a resource to an application'), 'application.resource_unlinked': t('Unlinked a resource from an application'),
  'group.members_changed': t('Changed group members'), 'grant.updated': t('Set a grant'), 'grant.deleted': t('Removed a grant'),
}

/** describeEvent turns a semantic event type (user.created) into a sentence. */
export function describeEvent(type: string) {
  if (eventNamed[type]) return eventNamed[type]
  const [subject, verb = ''] = type.split('.')
  const noun = eventWords[subject] ?? subject.replace(/_/g, ' ')
  // Types newer than this console keep their own words.
  const phrase = eventVerbs[verb]?.(noun) ?? `${noun} ${verb.replace(/_/g, ' ')}`.trim()
  return phrase.charAt(0).toLocaleUpperCase(language()) + phrase.slice(1)
}

export default function ActivityPage({ audit = false }: { audit?: boolean }) {
  return audit ? <Activity /> : <Sessions />
}

/** Activity shows the semantic event log, or the raw audit trail (also the
 * fallback when the event log cannot be read). */
function Activity() {
  const [view, setView] = useState<'events' | 'audit'>('events')
  const [unavailable, setUnavailable] = useState(false)
  const fallback = useCallback(() => setUnavailable(true), [])
  const audit = view === 'audit' || unavailable
  return <div className="space-y-6">
    <PageHeader title={t('Activity')} description={t('What happened in this environment, newest first.')}
      actions={!unavailable && <div role="group" aria-label={t('Activity view')} className="inline-flex rounded-md border p-0.5">
        {(['events', 'audit'] as const).map(v => <Button key={v} size="sm" variant={view === v ? 'secondary' : 'ghost'} aria-pressed={view === v} onClick={() => setView(v)}>{v === 'events' ? t('Events') : t('Change log')}</Button>)}
      </div>} />
    {audit ? <AuditEvents /> : <Events onUnavailable={fallback} />}
  </div>
}

function Events({ onUnavailable }: { onUnavailable: () => void }) {
  const { environment } = useParams()
  const [type, setType] = useState('')
  const [filter, setFilter] = useState('')
  const [cursors, setCursors] = useState<number[]>([0])
  const [state, setState] = useState<{ page: EventPage | null; loading: boolean; error: string }>({ page: null, loading: true, error: '' })
  const [version, setVersion] = useState(0)
  useEffect(() => { const id = setTimeout(() => { setFilter(type.trim()); setCursors([0]) }, 300); return () => clearTimeout(id) }, [type])
  const before = cursors[cursors.length - 1]
  useEffect(() => {
    const controller = new AbortController()
    const params = new URLSearchParams({ limit: '50' })
    if (filter) params.set('type', filter)
    if (before) params.set('before', String(before))
    setState(s => ({ ...s, loading: true, error: '' }))
    api.get<EventPage>(`/environments/${environment}/events?${params}`, controller.signal)
      .then(page => { if (!controller.signal.aborted) setState({ page, loading: false, error: '' }) })
      .catch(e => {
        if (controller.signal.aborted) return
        // Servers without the event log (404) fall back to the change log.
        if (e instanceof ApiError && e.status === 404 && !filter) onUnavailable()
        setState({ page: null, loading: false, error: message(e) })
      })
    return () => controller.abort()
  }, [environment, filter, before, version, onUnavailable])
  const items = state.page?.items ?? []
  return <>
    <div className="flex items-center justify-between gap-3">
      <Input aria-label={t('Filter by event type')} className="max-w-sm" placeholder={t('Filter by type (user.*, login.failed…)')} value={type} onChange={e => setType(e.target.value)} />
      <div className="flex items-center gap-2">
        <Button variant="outline" size="icon" className="size-7" disabled={cursors.length === 1} onClick={() => setCursors(c => c.slice(0, -1))} aria-label={t('Newer events')}><ChevronLeft className="size-4" /></Button>
        <Button variant="outline" size="icon" className="size-7" disabled={!state.page?.next} onClick={() => state.page && setCursors(c => [...c, state.page!.next])} aria-label={t('Older events')}><ChevronRight className="size-4" /></Button>
      </div>
    </div>
    <DataTable
      columns={[t('Event'), { header: t('By'), hideBelow: 'md' }, { header: t('Subject'), hideBelow: 'lg' }, { header: t('When'), nowrap: true }]}
      loading={state.loading} error={state.error} retry={() => setVersion(v => v + 1)}
      empty={<EmptyState icon={<ActivityIcon />} title={t('No events')} description={t('Sign-ins and changes to users, organizations, applications and settings are recorded here.')} />}
      rows={items.map(e => [
        <span className="flex flex-col"><span className="font-medium">{describeEvent(e.type)}</span><span className="font-mono text-xs text-muted-foreground">{e.type}</span></span>,
        <span className="flex flex-wrap items-center gap-2">{e.actor.id ? <CopyText value={e.actor.id} short label={t('Copy actor ID')} /> : null}{actorKinds[e.actor.kind] ? <Badge variant="secondary">{actorKinds[e.actor.kind]}</Badge> : !e.actor.id && <span className="text-muted-foreground">—</span>}</span>,
        e.subject.id ? <span className="flex items-center gap-2"><span className="text-xs text-muted-foreground">{e.subject.kind.replace(/_/g, ' ')}</span><CopyText value={e.subject.id} short label={t('Copy subject ID')} /></span> : <span className="text-muted-foreground">—</span>,
        <Time value={e.occurred_at} />,
      ])} />
  </>
}

function Sessions() {
  const { project, environment } = useParams()
  const base = `/projects/${project}/environments/${environment}`
  const path = `/environments/${environment}/sessions`
  const [search, setSearch] = useSearchParams()
  const organization = search.get('organization_id') ?? '', application = search.get('application_id') ?? ''
  const extraParams = useMemo(() => {
    const p: Record<string, string> = {}
    if (organization) p.organization_id = organization
    if (application) p.application_id = application
    return Object.keys(p).length ? p : undefined
  }, [organization, application])
  const list = usePaginatedList<Session>(path, { extraParams })
  const organizations = useList<{ id: string; name: string }>(`/environments/${environment}/organizations?limit=100`)
  const applications = useList<{ id: string; name: string }>(`/environments/${environment}/applications?limit=100`)
  const filter = (key: string, value: string) => setSearch(prev => { const next = new URLSearchParams(prev); if (value) next.set(key, value); else next.delete(key); return next }, { replace: true })
  const { principal } = useAuth()
  const [target, setTarget] = useState<Session | null>(null)
  const status = (s: Session) => s.revoked_at ? [t('Revoked'), 'bg-destructive/10 text-destructive'] : Date.parse(s.expires_at) <= Date.now() ? [t('Expired'), 'bg-muted text-muted-foreground'] : [t('Active'), 'bg-success/10 text-success']
  return <div className="space-y-6">
    <PageHeader title={t('Sessions')} description={t('End users signed in to your applications. Revoking a session signs the user out at the next token refresh.')} />
    <div className="flex flex-wrap items-center gap-2">
      <select aria-label={t('Filter by organization')} className={`${selectClass} w-56`} value={organization} onChange={e => filter('organization_id', e.target.value)}>
        <option value="">{t('All organizations')}</option>
        {organizations.data.map(o => <option key={o.id} value={o.id}>{o.name}</option>)}
        {organization && !organizations.data.some(o => o.id === organization) && <option value={organization}>{organization}</option>}
      </select>
      <select aria-label={t('Filter by application')} className={`${selectClass} w-56`} value={application} onChange={e => filter('application_id', e.target.value)}>
        <option value="">{t('All applications')}</option>
        {applications.data.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
        {application && !applications.data.some(a => a.id === application) && <option value={application}>{application}</option>}
      </select>
    </div>
    <PaginationBar state={list} noun="sessions" />
    <DataTable
      columns={[t('User'), { header: t('Application'), hideBelow: 'md' }, { header: t('Organization'), hideBelow: 'lg' }, { header: t('Signed in'), nowrap: true }, { header: t('Expires'), nowrap: true }, t('Status'), t('Actions')]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<KeyRound />} title={t('No sessions yet')} description={t('Sessions appear here when end users sign in to an application in this environment.')} />}
      rows={list.data.map(s => {
        const [label, tone] = status(s)
        return [
          <EntityRef name={s.user_name || s.user_email} id={s.user_id} secondary={s.user_name ? s.user_email : undefined} />,
          <EntityRef name={s.application_name} id={s.application_id} to={`${base}/applications/${s.application_id}`} secondary={s.resource_name} />,
          <EntityRef name={s.organization_name} id={s.organization_id} />,
          <Time value={s.authenticated_at} />,
          <Time value={s.expires_at} />,
          <Badge variant="secondary" className={tone}>{label}</Badge>,
          principal?.role !== 'viewer' && !s.revoked_at && <RowActions label={t('Actions for session of {{value}}', { value: s.user_email || s.user_id })} actions={[{ label: t('Revoke session'), icon: <Ban />, destructive: true, onSelect: () => setTarget(s) }]} />,
        ]
      })} />
    {target && <ConfirmDialog title={t('Revoke this session?')} description={t('{{user}} is signed out of {{application}} and must sign in again.', { user: target.user_email || t('The user'), application: target.application_name || t('the application') })} confirmLabel={t('Revoke session')} onClose={() => setTarget(null)} confirm={async () => { await api.delete(`${path}/${target.id}`); toast.success(t('Session revoked')); list.reload() }} />}
  </div>
}

function AuditEvents() {
  const { environment } = useParams()
  const list = usePaginatedList<AuditEvent>(`/environments/${environment}/audit-events`)
  return <>
    <PaginationBar state={list} noun="events" placeholder={t('Filter by action (POST, PATCH, mfa.reset…)')} />
    <DataTable
      columns={[t('Event'), { header: t('By'), hideBelow: 'md' }, { header: t('Target'), hideBelow: 'lg' }, { header: t('When'), nowrap: true }]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<ActivityIcon />} title={t('No audit events')} description={t('Changes to users, organizations, applications and settings are recorded here.')} />}
      rows={list.data.map(e => [
        <span className="font-medium">{describeAction(e.action, e.target_id)}</span>,
        <span className="flex flex-wrap items-center gap-2">{e.actor_label ? <span title={e.actor_id}>{e.actor_label}</span> : <CopyText value={e.actor_id} short label={t('Copy actor ID')} />}{e.actor_kind && actorKinds[e.actor_kind] && <Badge variant="secondary">{actorKinds[e.actor_kind]}</Badge>}</span>,
        e.target_label ? <span className="block max-w-xs truncate" title={e.target_id}>{e.target_label}</span> : <span className="block max-w-xs truncate font-mono text-xs text-muted-foreground" title={e.target_id}>{e.target_id}</span>,
        <Time value={e.created_at} />,
      ])} />
  </>
}
