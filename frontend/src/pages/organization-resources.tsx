import { useParams } from 'react-router-dom'
import { Handshake } from 'lucide-react'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { DataTable, EmptyState, EntityRef, Time } from '@/components/library/patterns'
import { useOrganization } from './organization-layout'
import { GrantedRoles, type ResourceGrant } from './resource-detail'
import { t } from '@/lib/i18n'

interface Role { id: string; name: string; resource_id: string }

/** OrganizationResourcesPage lists the resources granted to the
 * organization, and which of their roles it may assign. */
export function OrganizationResourcesPage() {
  const { project, environment, orgId } = useParams()
  const base = `/environments/${environment}`
  const envBase = `/projects/${project}/environments/${environment}`
  const orgName = useOrganization().org.name
  const grants = usePaginatedList<ResourceGrant>(`${base}/resource-grants`, { extraParams: { organization_id: orgId ?? '' } })
  const roles = usePaginatedList<Role>(`${base}/roles`, { limit: 100 })
  return <div className="space-y-4">
    <div>
      <h2 className="text-lg font-semibold">{t('Resources granted to {{orgName}}', { orgName })}</h2>
      <p className="max-w-2xl text-sm text-muted-foreground">{t('Resources other organizations (or the environment) granted to {{orgName}}. Its administrators can assign the granted roles to members; grant resources from each resource\'s page.', { orgName })}</p>
    </div>
    <PaginationBar state={grants} noun="grants" placeholder={t('Search resources…')} />
    <DataTable
      columns={[t('Resource'), t('Roles'), { header: t('Granted'), hideBelow: 'sm', nowrap: true }]}
      loading={grants.loading} error={grants.error} retry={grants.reload}
      empty={<EmptyState icon={<Handshake />} title={t('No resources granted')} description={t('Resources that require a grant are reachable only by their owner and the organizations they are granted to.')} />}
      rows={grants.data.map(g => [
        <EntityRef name={g.resource_name} id={g.resource_id} to={`${envBase}/resources/${g.resource_id}`} />,
        <GrantedRoles grant={g} roles={roles.data} />,
        <Time value={g.created_at} />,
      ])} />
  </div>
}
