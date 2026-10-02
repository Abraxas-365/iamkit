import { useCallback, useEffect, useState } from 'react'
import { Building2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { ConfirmDialog, CopyField, ErrorState, Status } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

/** GET/PUT /environments/:environment/org-admin-portal (orgadmin.Portal). */
export interface Portal { enabled: boolean; client_id?: string; application_id?: string; url?: string }

/** OrgAdminPortalCard turns the hosted organization admin portal on or off:
 * a page where organizations' own administrators manage their members,
 * roles, invitations, domains and single sign-on. */
export function OrgAdminPortalCard({ environment, canWrite }: { environment: string; canWrite: boolean }) {
  const path = `/environments/${environment}/org-admin-portal`
  const [portal, setPortal] = useState<Portal | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [disabling, setDisabling] = useState(false)
  const load = useCallback(() => {
    setError('')
    api.get<Portal>(path).then(setPortal).catch(e => setError(message(e)))
  }, [path])
  useEffect(load, [load])

  return <Card className="space-y-4 p-6">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="space-y-1">
        <h2 className="flex items-center gap-2 font-mono font-medium"><Building2 className="size-4" /> {t('Organization admin portal')}</h2>
        <p className="max-w-2xl text-sm text-muted-foreground">{t('A page IAMKit hosts where your customers\' administrators manage their own organization: members, users, roles, invitations, domains, single sign-on and branding. They sign in with the hosted login, and see only what their organization roles allow.')}</p>
      </div>
      {portal && <Status active={portal.enabled} label={portal.enabled ? t('On') : t('Off')} />}
    </div>
    {error && <ErrorState error={error} retry={load} />}
    {!portal && !error && <p role="status" className="text-sm text-muted-foreground">{t('Loading…')}</p>}
    {portal?.enabled && portal.url && <CopyField label={t('Portal link')} value={portal.url} hint={t('Share it with organization administrators, or link to it from your app. Add ?organization_id=… to preselect an organization.')} />}
    {portal && canWrite && <div className="flex gap-2">
      {portal.enabled
        ? <Button variant="outline" disabled={busy} onClick={() => setDisabling(true)}>{t('Turn off')}</Button>
        : <Button disabled={busy} onClick={async () => {
          setBusy(true)
          try { setPortal(await api.put<Portal>(path, {})); toast.success(t('Organization admin portal turned on')) } catch (e) { toast.error(message(e)) } finally { setBusy(false) }
        }}>{busy ? t('Turning on…') : t('Turn on')}</Button>}
    </div>}
    {disabling && <ConfirmDialog title={t('Turn off the organization admin portal?')} description={t('Administrators signed in to it are signed out now. The organization admin API stays available to your own app.')} confirmLabel={t('Turn off')} onClose={() => setDisabling(false)}
      confirm={async () => { await api.delete(path); toast.success(t('Organization admin portal turned off')); load() }} />}
  </Card>
}
