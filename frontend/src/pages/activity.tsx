import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { usePaginatedList } from '@/hooks/use-paginated-list'
import { Button } from '@/components/ui/button'
import { PaginationBar } from '@/components/ui/pagination-bar'
import { ConfirmDialog, DataTable, ID, PageHeader } from '@/components/library/patterns'
interface Activity { id: string; user_id: string; application_id: string; resource_id: string; expires_at: string; revoked_at: string | null; actor_id: string; action: string; target_id: string; created_at: string }
export default function ActivityPage({ audit = false }: { audit?: boolean }) {
  const { environment } = useParams()
  const path = `/environments/${environment}/${audit ? 'audit-events' : 'sessions'}`
  const list = usePaginatedList<Activity>(path)
  const { principal } = useAuth()
  const [target, setTarget] = useState<Activity | null>(null)
  return <div className="space-y-6"><PageHeader title={audit ? 'Audit events' : 'End-user sessions'} description={audit ? 'Selected management mutations in this environment.' : 'End-user sessions, not operator console sessions.'} />
    <PaginationBar state={list} noun={audit ? 'events' : 'sessions'} />
    <DataTable columns={audit ? ['Action', 'Actor', 'Target', 'Created'] : ['Session / User', 'Application / Resource', 'Expires', 'Status', 'Actions']} loading={list.loading} error={list.error} retry={list.reload} rows={list.data.map(row => audit ? [row.action, <ID value={row.actor_id} />, <ID value={row.target_id} />, new Date(row.created_at).toLocaleString()] : [<div><ID value={row.id} /><br /><ID value={row.user_id} /></div>, <div><ID value={row.application_id} /><br /><ID value={row.resource_id} /></div>, new Date(row.expires_at).toLocaleString(), row.revoked_at ? 'Revoked' : Date.parse(row.expires_at) <= Date.now() ? 'Expired' : 'Active', principal?.role !== 'viewer' && !row.revoked_at && <Button variant="destructive" size="sm" onClick={() => setTarget(row)}>Revoke</Button>])} />
    {target && <ConfirmDialog title="Revoke session?" description="This immediately revokes this end-user session." onClose={() => setTarget(null)} confirm={async () => { await api.delete(`${path}/${target.id}`); list.reload() }} />}
  </div>
}
