import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { DetailSection, SwitchField, selectClass } from '@/components/library/patterns'
import { message } from '@/lib/utils'
import { t } from '@/lib/i18n'

export interface DomainJoinSettings { domain_join: boolean; domain_join_group_id: string }

/** DomainJoinTransport is where the setting lives: the management API for
 * the console, the organization's /admin routes for the portal. */
export interface DomainJoinTransport {
  groups: (signal: AbortSignal) => Promise<{ id: string; name: string }[]>
  domains: (signal: AbortSignal) => Promise<{ domain: string; verified: boolean }[]>
  save: (body: { domain_join?: boolean; domain_join_group_id?: string }) => Promise<void>
}

/** DomainJoinPanel is the "auto-join by verified domain" setting: users
 * whose verified email is on one of the organization's verified domains
 * become members when they sign in, with the chosen group's roles. */
export function DomainJoinPanel({ transport, settings, canWrite, reload }: { transport: DomainJoinTransport; settings: Partial<DomainJoinSettings>; canWrite: boolean; reload: () => void }) {
  const [groups, setGroups] = useState<{ id: string; name: string }[]>([])
  const [domains, setDomains] = useState<{ domain: string; verified: boolean }[]>([])
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    const ctrl = new AbortController()
    transport.groups(ctrl.signal).then(setGroups).catch(() => {})
    transport.domains(ctrl.signal).then(setDomains).catch(() => {})
    return () => ctrl.abort()
  }, [transport])
  const verified = domains.filter(d => d.verified).map(d => d.domain)
  const enabled = !!settings.domain_join
  const group = settings.domain_join_group_id ?? ''
  async function save(body: { domain_join?: boolean; domain_join_group_id?: string }, done: string) {
    setBusy(true)
    try { await transport.save(body); toast.success(done); reload() } catch (e) { toast.error(message(e)) } finally { setBusy(false) }
  }
  return <DetailSection title={t('Join by verified domain')} description={t('People who sign in with a verified email address on one of this organization\'s verified domains become members automatically. Members who were removed are never added again.')}>
    <div className="space-y-4">
      <SwitchField label={t('Add people with a verified email on our domains')} hint={verified.length ? t('Verified domains: {{domains}}.', { domains: verified.join(', ') }) : t('No verified domain yet: nobody joins until a domain is verified.')}
        checked={enabled} disabled={!canWrite || busy} onCheckedChange={v => save({ domain_join: v }, v ? t('Domain join turned on') : t('Domain join turned off'))} />
      <div className="space-y-1.5">
        <label htmlFor="domain-join-group" className="text-sm font-medium">{t('Group for new members')}</label>
        <select id="domain-join-group" className={selectClass} value={group} disabled={!canWrite || busy} onChange={e => save({ domain_join_group_id: e.target.value }, t('Domain join group saved'))}>
          <option value="">{t('No group (membership only)')}</option>
          {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
        </select>
        <p className="text-xs text-muted-foreground">{t('New members get this group\'s roles. Only groups you manage can be chosen, not directory (SCIM) groups.')}</p>
      </div>
    </div>
  </DetailSection>
}
