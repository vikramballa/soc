import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Search, Users } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { RiskScore } from '../components/security'
import { toast, toastError } from '../components/toast'
import { Card, EmptyState, ErrorState, Input, PageHeader, SkeletonRows, Switch } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { relTime } from '../lib/format'
import type { Identity, Page } from '../lib/types'
import { useDebounced } from './Incidents'

export default function Identities() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const q = useDebounced(search)
  const query = useQuery({ queryKey: ['identities', q], queryFn: () => api.get<Page<Identity>>('/identities', { q, limit: 500 }) })
  const update = useMutation({
    mutationFn: ({ id, privileged }: { id: string; privileged: boolean }) => api.patch(`/identities/${id}`, { privileged }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['identities'] }); toast('Updated') },
    onError: toastError,
  })
  return (
    <div>
      <PageHeader
        title="Users"
        description="Accounts observed in authentication and process telemetry. Mark administrative accounts as privileged — incidents involving them score higher."
      />
      <Card className="overflow-hidden">
        <div className="border-b border-line bg-bg-elev px-4 py-2.5">
          <Input icon={<Search className="size-4" />} className="w-full max-w-xs" placeholder="Search username or department" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        {query.error ? <ErrorState error={query.error} /> : !query.data ? <SkeletonRows /> : !query.data.items.length ? (
          <EmptyState icon={<Users className="size-5" />} title="No accounts seen yet" />
        ) : (
          <table className="sx-table">
            <thead><tr><th className="w-14">Risk</th><th>Account</th><th className="w-48">Department</th><th className="w-32">Last seen</th><th className="w-28">Privileged</th></tr></thead>
            <tbody>
              {query.data.items.map((u) => (
                <tr key={u.id}>
                  <td><RiskScore score={u.risk_score} size="sm" /></td>
                  <td>
                    <Link to={`/events?user=${encodeURIComponent(u.username)}&hours=168`} className="font-medium hover:text-accent">{u.username}</Link>
                    <div className="text-[12px] text-faint">{u.email ?? ''}</div>
                  </td>
                  <td className="text-muted">{u.department ?? '—'}</td>
                  <td className="text-muted">{relTime(u.last_seen)}</td>
                  <td><Switch label={`Privileged: ${u.username}`} checked={u.privileged} disabled={!can('asset:update')} onChange={(v) => update.mutate({ id: u.id, privileged: v })} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  )
}
