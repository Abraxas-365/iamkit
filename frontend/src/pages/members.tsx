import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, UserMinus } from 'lucide-react'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import { useList } from '@/hooks/use-list'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { ConfirmDialog, DataTable, ID, PageHeader, Status } from '@/components/library/patterns'

interface Member { user_id: string; user_name: string; user_email: string; active: boolean }

export default function MembersPage() {
  const { project, environment, orgId } = useParams()
  const base = `/environments/${environment}`
  const path = `${base}/organizations/${orgId}/members`
  const list = useList<Member>(path)
  const { principal } = useAuth()
  const canWrite = principal?.role !== 'viewer'
  const [search, setSearch] = useState('')
  const [removing, setRemoving] = useState<Member | null>(null)
  const [orgName, setOrgName] = useState<string>('')

  useEffect(() => {
    if (!environment || !orgId) return
    api.get<{ id: string; name: string }>(`${base}/organizations/${orgId}`)
      .then(org => setOrgName(org.name))
      .catch(() => {})
  }, [environment, orgId, base])

  const filtered = list.data.filter(m =>
    [m.user_name, m.user_email, m.user_id].some(v => v?.toLowerCase().includes(search.toLowerCase())),
  )
  const orgsPath = `/projects/${project}/environments/${environment}/organizations`

  return <div className="space-y-6">
    <div className="space-y-3">
      <Link to={orgsPath} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors">
        <ArrowLeft className="size-3.5" />Back to organizations
      </Link>
      <PageHeader
        title={orgName ? `Members of ${orgName}` : 'Members'}
        description={orgId}
        actions={canWrite && <div className="flex flex-wrap gap-2">
          {/* Add-member action stays on the organizations page */}
        </div>}
      />
    </div>

    <div className="flex items-center justify-between gap-3">
      <Input aria-label="Search members" className="max-w-sm" placeholder="Search members…" value={search} onChange={e => setSearch(e.target.value)} />
      <span className="text-xs text-muted-foreground">{filtered.length} of {list.total} members</span>
    </div>

    <DataTable
      columns={['User', 'Email', 'Status', ...(canWrite ? ['Actions'] : [])]}
      loading={list.loading}
      error={list.error}
      retry={list.reload}
      rows={filtered.map(m => {
        const cells: React.ReactNode[] = [
          <div className="space-y-1">
            <p className="font-medium">{m.user_name}</p>
            <ID value={m.user_id} />
          </div>,
          <span className="text-sm">{m.user_email}</span>,
          <Status active={m.active} />,
        ]
        if (canWrite) cells.push(
          m.active
            ? <Button variant="ghost" size="icon" aria-label="Remove member" onClick={() => setRemoving(m)}><UserMinus className="size-4" /></Button>
            : null,
        )
        return cells
      })}
    />

    {removing && (
      <ConfirmDialog
        title="Remove member?"
        description={`${removing.user_name || removing.user_id} will be deactivated in ${orgName || 'this organization'}.`}
        onClose={() => setRemoving(null)}
        confirm={async () => {
          await api.delete(`${base}/organizations/${orgId}/members/${removing.user_id}`)
          list.reload()
        }}
      />
    )}
  </div>
}
