import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Download, FileText } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { SeverityBadge, StatusBadge } from '../components/security'
import { Button, Card, EmptyState, PageHeader, Segmented, SkeletonRows } from '../components/ui'
import { api, apiUrl } from '../lib/api'
import { dateTime } from '../lib/format'
import type { IncidentSummary, Page } from '../lib/types'
import { Pager } from './Incidents'

export default function Reports() {
  const [status, setStatus] = useState('all')
  const [offset, setOffset] = useState(0)
  const q = useQuery({
    queryKey: ['report-incidents', status, offset],
    queryFn: () => api.get<Page<IncidentSummary>>('/incidents', { status: status === 'all' ? undefined : status, sort: 'newest', limit: 50, offset }),
    placeholderData: keepPreviousData,
  })
  return (
    <div>
      <PageHeader
        title="Reports"
        description="Download a self-contained incident report for management, auditors or your insurer. Reports separate observed evidence, automated inference, AI interpretation and analyst conclusions."
        actions={<Segmented value={status} onChange={(v) => { setStatus(v); setOffset(0) }} items={[{ value: 'all', label: 'All' }, { value: 'open', label: 'Open' }, { value: 'closed', label: 'Resolved' }]} />}
      />
      <Card className="overflow-hidden">
        {!q.data ? <SkeletonRows /> : !q.data.items.length ? <EmptyState icon={<FileText className="size-5" />} title="No incidents to report on yet" /> : (
          <table className="sx-table">
            <thead><tr><th>Incident</th><th className="w-28">Severity</th><th className="w-32">Status</th><th className="w-40">Created</th><th className="w-48 text-right">Export</th></tr></thead>
            <tbody>
              {q.data.items.map((i) => (
                <tr key={i.id}>
                  <td className="max-w-0"><Link to={`/incidents/${i.id}`} className="block truncate font-medium hover:text-accent"><span className="font-mono text-[11.5px] text-faint">INC-{i.number}</span> {i.title}</Link></td>
                  <td><SeverityBadge severity={i.severity} size="sm" /></td>
                  <td><StatusBadge status={i.status} /></td>
                  <td className="text-muted">{dateTime(i.created_at)}</td>
                  <td className="text-right">
                    <div className="inline-flex gap-1.5">
                      <a href={apiUrl(`/incidents/${i.id}/report`, { fmt: 'html' })} target="_blank" rel="noreferrer"><Button size="sm" icon={<Download className="size-3.5" />}>HTML</Button></a>
                      <a href={apiUrl(`/incidents/${i.id}/report`, { fmt: 'json' })} target="_blank" rel="noreferrer"><Button size="sm" variant="ghost">JSON</Button></a>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {q.data && <Pager total={q.data.total} offset={offset} limit={50} onChange={setOffset} />}
      </Card>
      <p className="mt-3 text-[12px] text-faint">Tip: open the HTML report and use your browser's “Print → Save as PDF” for a PDF copy. Report generation is recorded in the audit log.</p>
    </div>
  )
}
