import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Boxes, Search } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Drawer } from '../components/overlay'
import { CriticalityDots, RiskScore, SeverityBadge, StatusBadge } from '../components/security'
import { toast, toastError } from '../components/toast'
import { Badge, Button, Card, EmptyState, ErrorState, Input, KeyValue, Label, Mono, PageHeader, SectionTitle, Select, Skeleton, SkeletonRows } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { dateTime, num, relTime } from '../lib/format'
import type { Asset, IncidentSummary, Page } from '../lib/types'
import { useDebounced } from './Incidents'

const CRIT_HELP = ['', 'Low — lab or disposable', 'Normal — typical workstation', 'Important — team or department system', 'High — business-critical server', 'Critical — crown jewels (domain controller, finance, customer data)']

export default function Assets() {
  const [params] = useSearchParams()
  const [search, setSearch] = useState('')
  const q = useDebounced(search)
  const [sort, setSort] = useState('risk')
  const [selected, setSelected] = useState<string | null>(params.get('focus'))
  const query = useQuery({ queryKey: ['assets', q, sort], queryFn: () => api.get<Page<Asset>>('/assets', { q, sort, limit: 500 }) })
  return (
    <div>
      <PageHeader
        title="Assets"
        description="Hosts seen in telemetry. Set how critical each one is — criticality feeds directly into incident risk scores."
      />
      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-line bg-bg-elev px-4 py-2.5">
          <Input icon={<Search className="size-4" />} className="w-full max-w-xs" placeholder="Search hostname, owner, IP" value={search} onChange={(e) => setSearch(e.target.value)} />
          <Select className="ml-auto w-44" value={sort} onChange={(e) => setSort(e.target.value)}>
            <option value="risk">Sort: highest risk</option>
            <option value="name">Sort: name</option>
            <option value="seen">Sort: recently seen</option>
          </Select>
        </div>
        {query.error ? <ErrorState error={query.error} /> : !query.data ? <SkeletonRows /> : !query.data.items.length ? (
          <EmptyState icon={<Boxes className="size-5" />} title="No assets yet">Assets are discovered automatically from Wazuh agents and network telemetry.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="sx-table min-w-[860px]">
              <thead><tr><th className="w-14">Risk</th><th>Host</th><th className="w-44">Criticality</th><th className="w-40">Owner</th><th className="w-40">IP addresses</th><th className="w-28">Last seen</th></tr></thead>
              <tbody>
                {query.data.items.map((a) => (
                  <tr key={a.id} data-clickable="true" onClick={() => setSelected(a.id)}>
                    <td><RiskScore score={a.risk_score} size="sm" /></td>
                    <td>
                      <div className="font-medium">{a.hostname}</div>
                      <div className="text-[12px] text-faint">{[a.os, a.environment].filter(Boolean).join(' · ') || '—'}</div>
                    </td>
                    <td><CriticalityDots value={a.criticality} /></td>
                    <td className="text-muted">{a.owner ?? <span className="text-faint">Unassigned</span>}</td>
                    <td className="max-w-0 truncate"><Mono className="text-muted">{a.ip_addresses.join(', ') || '—'}</Mono></td>
                    <td className="text-muted">{relTime(a.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <AssetDrawer id={selected} onClose={() => setSelected(null)} />
    </div>
  )
}

function AssetDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { can } = useAuth()
  const qc = useQueryClient()
  const q = useQuery({
    queryKey: ['asset', id],
    enabled: !!id,
    queryFn: () => api.get<{ asset: Asset; incidents: IncidentSummary[]; event_counts: Record<string, number> }>(`/assets/${id}`),
  })
  const [form, setForm] = useState({ criticality: 2, owner: '', environment: '', tags: '' })
  useEffect(() => {
    const a = q.data?.asset
    if (a) setForm({ criticality: a.criticality, owner: a.owner ?? '', environment: a.environment ?? '', tags: a.tags.join(', ') })
  }, [q.data])
  const save = useMutation({
    mutationFn: () => api.patch(`/assets/${id}`, { criticality: form.criticality, owner: form.owner || null, environment: form.environment || null, tags: form.tags.split(',').map((t) => t.trim()).filter(Boolean) }),
    onSuccess: () => { toast('Asset updated — new incidents use the new criticality'); qc.invalidateQueries({ queryKey: ['assets'] }); qc.invalidateQueries({ queryKey: ['asset', id] }) },
    onError: toastError,
  })
  const a = q.data?.asset
  return (
    <Drawer open={!!id} onClose={onClose} title={a?.hostname ?? 'Asset'} subtitle={a && [a.os, a.environment].filter(Boolean).join(' · ')}
      footer={can('asset:update') && <div className="flex justify-end"><Button variant="primary" loading={save.isPending} onClick={() => save.mutate()}>Save changes</Button></div>}>
      {!a ? <Skeleton className="h-40" /> : (
        <div className="space-y-6">
          <div className="flex items-center gap-4">
            <RiskScore score={a.risk_score} size="lg" />
            <KeyValue items={[['First seen', dateTime(a.first_seen)], ['Last seen', relTime(a.last_seen)], ['Wazuh agent', a.wazuh_agent_id], ['IP addresses', <Mono key="ip">{a.ip_addresses.join(', ') || '—'}</Mono>]]} />
          </div>
          {can('asset:update') ? (
            <div className="space-y-3">
              <SectionTitle>Business context</SectionTitle>
              <label className="block"><Label hint={CRIT_HELP[form.criticality].split(' — ')[1]}>Criticality</Label>
                <Select value={form.criticality} onChange={(e) => setForm({ ...form, criticality: Number(e.target.value) })}>
                  {[1, 2, 3, 4, 5].map((c) => <option key={c} value={c}>{c} · {CRIT_HELP[c].split(' — ')[0]}</option>)}
                </Select>
              </label>
              <div className="grid grid-cols-2 gap-3">
                <label className="block"><Label>Owner / team</Label><Input value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} /></label>
                <label className="block"><Label>Environment</Label><Input value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })} placeholder="production" /></label>
              </div>
              <label className="block"><Label hint="comma separated">Tags</Label><Input value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} /></label>
            </div>
          ) : (
            <KeyValue items={[['Criticality', <CriticalityDots key="c" value={a.criticality} />], ['Owner', a.owner], ['Tags', a.tags.map((t) => <Badge key={t} className="mr-1">{t}</Badge>)]]} />
          )}
          <div>
            <SectionTitle>Incidents involving this host</SectionTitle>
            {q.data!.incidents.length ? (
              <ul className="space-y-1.5">
                {q.data!.incidents.map((i) => (
                  <li key={i.id}>
                    <Link to={`/incidents/${i.id}`} className="flex items-center gap-2 rounded-lg px-2 py-1.5 text-[13px] hover:bg-surface-2">
                      <SeverityBadge severity={i.severity} size="sm" />
                      <span className="min-w-0 flex-1 truncate">{i.title}</span>
                      <StatusBadge status={i.status} />
                    </Link>
                  </li>
                ))}
              </ul>
            ) : <p className="text-[12.5px] text-faint">None.</p>}
          </div>
          <div>
            <SectionTitle>Telemetry from this host</SectionTitle>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(q.data!.event_counts).map(([t, n]) => (
                <Link key={t} to={`/events?host=${encodeURIComponent(a.hostname)}&event_type=${t}&hours=720`}><Badge tone="outline" className="h-6 hover:text-fg">{t}: {num(n)}</Badge></Link>
              ))}
            </div>
          </div>
        </div>
      )}
    </Drawer>
  )
}
