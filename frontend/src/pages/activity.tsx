import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { Activity as ActivityIcon, Ban, KeyRound } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Badge } from '@/components/ui/badge'
import { RowActions } from '@/components/ui/menu'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { ConfirmDialog, CopyText, DataTable, EmptyState, EntityRef, PageHeader, Time } from '@/components/library/patterns'

interface Session { id: string; user_id: string; user_name: string; user_email: string; organization_id: string; organization_name: string; application_id: string; application_name: string; resource_id: string; resource_name: string; expires_at: string; revoked_at: string | null }
interface AuditEvent { id: string; actor_id: string; actor_label: string; action: string; target_id: string; target_label?: string; created_at: string }

const verbs: Record<string, string> = { POST: 'Created', PUT: 'Set', PATCH: 'Updated', DELETE: 'Deleted' }
const nouns: Record<string, string> = {
  users: 'user', organizations: 'organization', applications: 'application', resources: 'resource', roles: 'role', grants: 'grant',
  'role-assignments': 'role assignment', 'group-role-assignments': 'group role assignment', 'service-accounts': 'service account', 'federation-connections': 'federation connection',
  'oauth-clients': 'OAuth client', 'provisioning-credentials': 'SCIM credential', memberships: 'membership', members: 'member',
  groups: 'group', domains: 'domain', invitations: 'invitation', sessions: 'session', 'login-settings': 'hosted login settings',
  clients: 'client style', 'sign-in': 'sign-in methods', factors: 'second factors', identities: 'linked identity', 'mfa-policy': 'MFA policy',
  verify: 'domain verification', resend: 'invitation', revoke: 'credential', 'logout-deliveries': 'logout delivery', links: 'application link', 'delivery-settings': 'notification settings',
}
const named: Record<string, string> = {
  'federation.jit': 'User signed up through federation', 'federation.email': 'User linked by verified email through federation',
  'federation.profile_updated': 'Profile updated from the identity provider', 'invitation.accept': 'Invitation accepted',
  'mfa.enrolled': 'Second factor enrolled', 'mfa.removed': 'Second factor removed', 'mfa.recovery_regenerated': 'Recovery codes regenerated',
  'mfa.recovery_used': 'Recovery code used', 'mfa.reset': 'Second factors reset', 'mfa.locked': 'Second factor locked after failed attempts',
  'mfa.clone_detected': 'Cloned security key refused',
  'oauth.logout': 'Signed out of an application (OIDC logout)', 'oauth.backchannel_failed': 'Back-channel logout delivery failed', 'oauth.device_approved': 'Approved a device sign-in', 'oauth.token_exchanged': 'Exchanged a token for another resource', 'oauth.impersonated': 'A service account impersonated a user',
  'service_account.authentication': 'Changed how a service account authenticates',
  'service_account.impersonation': 'Changed whether a service account may impersonate users',
  'signing_key.create': 'Created a signing key', 'signing_key.activate': 'Activated a signing key', 'signing_key.retire': 'Retired a signing key',
  'saml_service_provider.create': 'Added a SAML application', 'saml_service_provider.update': 'Updated a SAML application', 'saml_service_provider.delete': 'Deleted a SAML application', 'saml.assertion_issued': 'Signed in to a SAML application',
  'sms.update': 'Updated SMS delivery', 'sms.delete': 'Removed SMS delivery', 'sms.test': 'Sent a test SMS',
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-/i

/** describeAction turns a stored audit action (a named event, or the HTTP
 * method of a management call) and its target path into a short sentence. */
export function describeAction(action: string, target = '') {
  if (named[action]) return named[action]
  if (action.startsWith('federation.')) return 'User linked through federation'
  const verb = verbs[action]
  if (!verb) return action
  const parts = target.split('?')[0].split('/').filter(Boolean)
  const i = parts.findIndex(p => p === 'environments')
  const rest = (i >= 0 ? parts.slice(i + 2) : parts).filter(p => !uuid.test(p))
  const last = rest[rest.length - 1]
  if (!last) return `${verb} environment`
  if (last === 'verify') return 'Verified domain'
  if (last === 'resend') return 'Resent invitation'
  if (last === 'revoke') return 'Revoked credential'
  if (last === 'retry' && rest.includes('logout-deliveries')) return 'Retried a logout delivery'
  if (last === 'reactivate') return 'Reactivated user'
  if (last === 'suspend') return 'Suspended user'
  if (last === 'force-verify') return 'Marked domain verified'
  if (last === 'permanent') return 'Permanently deleted user'
  if (last === 'profile') return 'Updated member profile'
  // Action-style POSTs end in a verb segment (handled above); any other
  // POST creates the item its path names.
  return `${verb} ${nouns[last] ?? last.replace(/-/g, ' ')}`
}

export default function ActivityPage({ audit = false }: { audit?: boolean }) {
  return audit ? <AuditEvents /> : <Sessions />
}

function Sessions() {
  const { project, environment } = useParams()
  const base = `/projects/${project}/environments/${environment}`
  const path = `/environments/${environment}/sessions`
  const list = usePaginatedList<Session>(path)
  const { principal } = useAuth()
  const [target, setTarget] = useState<Session | null>(null)
  const status = (s: Session) => s.revoked_at ? ['Revoked', 'bg-destructive/10 text-destructive'] : Date.parse(s.expires_at) <= Date.now() ? ['Expired', 'bg-muted text-muted-foreground'] : ['Active', 'bg-success/10 text-success']
  return <div className="space-y-6">
    <PageHeader title="Sessions" description="End users signed in to your applications. Revoking a session signs the user out at the next token refresh." />
    <PaginationBar state={list} noun="sessions" />
    <DataTable
      columns={['User', { header: 'Application', hideBelow: 'md' }, { header: 'Organization', hideBelow: 'lg' }, { header: 'Expires', nowrap: true }, 'Status', 'Actions']}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<KeyRound />} title="No sessions yet" description="Sessions appear here when end users sign in to an application in this environment." />}
      rows={list.data.map(s => {
        const [label, tone] = status(s)
        return [
          <EntityRef name={s.user_name || s.user_email} id={s.user_id} secondary={s.user_name ? s.user_email : undefined} />,
          <EntityRef name={s.application_name} id={s.application_id} to={`${base}/applications/${s.application_id}`} secondary={s.resource_name} />,
          <EntityRef name={s.organization_name} id={s.organization_id} />,
          <Time value={s.expires_at} />,
          <Badge variant="secondary" className={tone}>{label}</Badge>,
          principal?.role !== 'viewer' && !s.revoked_at && <RowActions label={`Actions for session of ${s.user_email || s.user_id}`} actions={[{ label: 'Revoke session', icon: <Ban />, destructive: true, onSelect: () => setTarget(s) }]} />,
        ]
      })} />
    {target && <ConfirmDialog title="Revoke this session?" description={`${target.user_email || 'The user'} is signed out of ${target.application_name || 'the application'} and must sign in again.`} confirmLabel="Revoke session" onClose={() => setTarget(null)} confirm={async () => { await api.delete(`${path}/${target.id}`); toast.success('Session revoked'); list.reload() }} />}
  </div>
}

function AuditEvents() {
  const { environment } = useParams()
  const list = usePaginatedList<AuditEvent>(`/environments/${environment}/audit-events`)
  return <div className="space-y-6">
    <PageHeader title="Audit events" description="Who changed what in this environment, newest first." />
    <PaginationBar state={list} noun="events" placeholder="Filter by action (POST, PATCH, mfa.reset…)" />
    <DataTable
      columns={['Event', { header: 'By', hideBelow: 'md' }, { header: 'Target', hideBelow: 'lg' }, { header: 'When', nowrap: true }]}
      loading={list.loading} error={list.error} retry={list.reload}
      empty={<EmptyState icon={<ActivityIcon />} title="No audit events" description="Changes to users, organizations, applications and settings are recorded here." />}
      rows={list.data.map(e => [
        <span className="font-medium">{describeAction(e.action, e.target_id)}</span>,
        e.actor_label ? <span title={e.actor_id}>{e.actor_label}</span> : <CopyText value={e.actor_id} short label="Copy actor ID" />,
        e.target_label ? <span className="block max-w-xs truncate" title={e.target_id}>{e.target_label}</span> : <span className="block max-w-xs truncate font-mono text-xs text-muted-foreground" title={e.target_id}>{e.target_id}</span>,
        <Time value={e.created_at} />,
      ])} />
  </div>
}
