import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import { Ban, Link2, Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { RowActions } from '@/components/ui/menu'
import { ConfirmDialog, CopyField, DataTable, EmptyState, FormDialog, Status, Time } from '@/components/library/patterns'
import { message } from '@/lib/utils'
import { rich, t } from '@/lib/i18n'

export interface SetupLink { id: string; intents: string[]; expires_at: string; revoked_at: string | null; created_by: string; created_at: string; last_used_at: string | null }
export interface IssuedSetupLink { id: string; url: string; expires_at: string; intents: string[] }

/** SetupTransport is where setup links live: the management API for the
 * console, the organization's /admin routes for the portal's owners. */
export interface SetupTransport {
  list: (signal: AbortSignal) => Promise<{ items: SetupLink[] }>
  create: (body: { intents: string[]; expires_in: string }) => Promise<IssuedSetupLink>
  revoke: (id: string) => Promise<void>
}

export const setupIntents: { value: string; label: string; hint: string }[] = [
  { value: 'sso', label: t('Single sign-on'), hint: t('Connect an identity provider over SAML, OIDC or LDAP.') },
  { value: 'directory', label: t('Directory (SCIM)'), hint: t('Provision users and groups from the directory.') },
  { value: 'domains', label: t('Domains'), hint: t('Add and verify the company\'s email domains.') },
]
const intentLabel = (value: string) => setupIntents.find(i => i.value === value)?.label ?? value

const lifetimes = [
  { label: t('1 day'), value: '24h' }, { label: t('3 days'), value: '72h' }, { label: t('7 days'), value: '168h' },
  { label: t('14 days'), value: '336h' }, { label: t('30 days'), value: '720h' },
]
const stateOf = (l: SetupLink) => l.revoked_at ? 'revoked' : Date.parse(l.expires_at) <= Date.now() ? 'expired' : 'active'

/** SetupLinksPanel creates, lists and revokes the setup links of one
 * organization. A link's URL carries its secret and is shown once. */
export function SetupLinksPanel({ transport, canWrite, organization }: { transport: SetupTransport; canWrite: boolean; organization?: string }) {
  const [state, setState] = useState<{ items: SetupLink[]; loading: boolean; error: string }>({ items: [], loading: true, error: '' })
  const [version, setVersion] = useState(0)
  const [creating, setCreating] = useState(false)
  const [revoking, setRevoking] = useState<SetupLink | null>(null)
  const [issued, setIssued] = useState<IssuedSetupLink | null>(null)
  const reload = useCallback(() => setVersion(v => v + 1), [])
  useEffect(() => {
    const ctrl = new AbortController()
    transport.list(ctrl.signal).then(r => setState({ items: r.items, loading: false, error: '' })).catch(e => { if (!ctrl.signal.aborted) setState({ items: [], loading: false, error: message(e) }) })
    return () => ctrl.abort()
  }, [transport, version])
  const create = canWrite && <Button onClick={() => setCreating(true)}><Plus /> {t('Create setup link')}</Button>
  return <div className="space-y-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <p className="max-w-2xl text-sm text-muted-foreground">{organization
        ? t('Give {{name}}\'s IT administrator a link to set up single sign-on, directory sync and domains, without creating an account.', { name: organization })
        : t('Give your IT administrator a link to set up single sign-on, directory sync and domains, without creating an account.')}</p>
      {state.items.length > 0 && create}
    </div>
    <DataTable columns={[t('Can set up'), { header: t('Created'), nowrap: true, hideBelow: 'md' }, { header: t('Last used'), nowrap: true, hideBelow: 'lg' }, { header: t('Expires'), nowrap: true }, t('Status'), ...(canWrite ? [t('Actions')] : [])]}
      loading={state.loading} error={state.error} retry={reload}
      empty={<EmptyState icon={<Link2 />} title={t('No setup links')} description={t('A link expires by itself and can be revoked at any time.')} action={create || undefined} />}
      rows={state.items.map(l => {
        const status = stateOf(l)
        const cells: ReactNode[] = [
          <span className="font-medium">{l.intents.map(intentLabel).join(', ')}</span>,
          <Time value={l.created_at} />,
          <Time value={l.last_used_at} />,
          <Time value={l.expires_at} />,
          status === 'active' ? <Status active /> : <Status active={false} label={status === 'revoked' ? t('Revoked') : t('Expired')} />,
        ]
        if (canWrite) cells.push(status === 'active' ? <RowActions label={t('Actions for setup link')} actions={[{ label: t('Revoke link'), icon: <Ban />, destructive: true, onSelect: () => setRevoking(l) }]} /> : null)
        return cells
      })} />
    {creating && <FormDialog title={t('Create a setup link')} description={t('The link opens a restricted page where the recipient configures only what you tick below.')} submitLabel={t('Create link')} success="" onClose={() => setCreating(false)}
      fields={[
        ...setupIntents.map(i => ({ name: `intent_${i.value}`, label: i.label, hint: i.hint, type: 'checkbox' as const, value: true })),
        { name: 'expires_in', label: t('Link expires in'), type: 'dropdown', options: lifetimes, value: '168h' },
      ]}
      submit={async d => {
        const intents = setupIntents.filter(i => d[`intent_${i.value}`] === true).map(i => i.value)
        if (!intents.length) throw new Error(t('Choose at least one thing the link can set up.'))
        setIssued(await transport.create({ intents, expires_in: String(d.expires_in) }))
        reload()
      }} />}
    {revoking && <ConfirmDialog title={t('Revoke this setup link?')} description={t('Anyone using it is signed out of the setup page at once.')} confirmLabel={t('Revoke link')} onClose={() => setRevoking(null)}
      confirm={async () => { await transport.revoke(revoking.id); toast.success(t('Setup link revoked')); reload() }} />}
    {issued && <Dialog open onOpenChange={open => { if (!open) setIssued(null) }}><DialogContent>
      <DialogTitle className="pr-6 text-base font-semibold">{t('Setup link created')}</DialogTitle>
      <DialogDescription className="text-muted-foreground">{t('Copy the link now — it is shown only once. Anyone who has it can configure the organization until it expires or is revoked.')}</DialogDescription>
      <CopyField label={t('Setup link')} value={issued.url} secret hint={rich('Expires {{time}}.', { time: <Time value={issued.expires_at} /> })} />
      <div className="flex justify-end border-t pt-4"><Button onClick={() => setIssued(null)}>{t('I have copied the link')}</Button></div>
    </DialogContent></Dialog>}
  </div>
}
