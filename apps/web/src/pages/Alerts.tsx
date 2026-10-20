import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, Bell, Search } from 'lucide-react'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { EventDrawer } from '../components/EventDrawer'
import { Drawer } from '../components/overlay'
import { SeverityBadge, SourcePills, TechniqueChip } from '../components/security'
import { toastError } from '../components/toast'
import { Badge, Button, Card, EmptyState, ErrorState, Input, KeyValue, Mono, PageHeader, SectionTitle, Select, Skeleton, SkeletonRows } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { clock, dateTime, DETECTION_SOURCE_LABEL, num, relTime, severityFromScore } from '../lib/format'
import type { Alert, Page, SecurityEvent } from '../lib/types'
import { Pager, useDebounced } from './Incidents'

export default function Alerts() {
  const [params, setParams] = useSearchParams()
  const [search, setSearch] = useState(params.get('q') ?? '')
  const q = useDebounced(search)
  const [level, setLevel] = useState(params.get('level') ?? '')
  const [source, setSource] = useState(params.get('source') ?? '')
  const [status, setStatus] = useState(params.get('status') ?? '')
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<Alert | null>(null)
  const query = useQuery({
    queryKey: ['alerts', q, level, source, status, offset, params.get('rule_uid')],
    queryFn: () => api.get<Page<Alert>>('/alerts', { q, level, source, status, offset, limit: 50, rule_uid: params.get('rule_uid') }),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  })
  return (
    <div>
      <PageHeader
        title="Alerts"
        description="Individual detections, already de-duplicated: repeated hits of the same rule on the same host are folded into one alert with an event count. Most alerts belong to an incident."
      />
      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-line bg-bg-elev px-4 py-2.5">
          <Input icon={<Search className="size-4" />} className="w-full max-w-xs" placeholder="Search title, host, user, IP, domain" value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0) }} />
          <Select className="w-36" value={level} onChange={(e) => { setLevel(e.target.value); setOffset(0) }}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </Select>
          <Select className="w-44" value={source} onChange={(e) => { setSource(e.target.value); setOffset(0) }}>
            <option value="">All detection types</option>
            {Object.entries(DETECTION_SOURCE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </Select>
          <Select className="w-36" value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0) }}>
            <option value="">Any status</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="closed">Closed</option>
          </Select>
          {params.get('rule_uid') && <Button size="sm" variant="ghost" onClick={() => setParams({})}>Clear rule filter ✕</Button>}
        </div>
        {query.error ? <ErrorState error={query.error} /> : !query.data ? <SkeletonRows /> : !query.data.items.length ? (
          <EmptyState icon={<Bell className="size-5" />} title="No alerts match">Alerts appear here as detections fire on incoming telemetry.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="sx-table min-w-[960px]">
              <thead>
                <tr>
                  <th className="w-28">Severity</th>
                  <th>Detection</th>
                  <th className="w-40">Host / user</th>
                  <th className="w-36">Type</th>
                  <th className="w-20 text-right">Events</th>
                  <th className="w-28">Incident</th>
                  <th className="w-28">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((a) => (
                  <tr key={a.id} data-clickable="true" onClick={() => setSelected(a)}>
                    <td><SeverityBadge severity={severityFromScore(a.severity)} size="sm" /></td>
                    <td className="max-w-0">
                      <div className="truncate font-medium">{a.title}</div>
                      <div className="truncate text-[12px] text-faint">{[a.src_ip && `from ${a.src_ip}`, a.dest_ip && `to ${a.dest_ip}`, a.domain].filter(Boolean).join(' · ') || a.rule_uid}</div>
                    </td>
                    <td className="text-[12.5px]"><div>{a.hostname ?? <span className="text-faint">—</span>}</div><div className="text-faint">{a.username}</div></td>
                    <td className="text-[12.5px] text-muted">{DETECTION_SOURCE_LABEL[a.source] ?? a.source}</td>
                    <td className="tnum text-right text-muted">{num(a.event_count)}</td>
                    <td>{a.incident_id ? <Link onClick={(e) => e.stopPropagation()} to={`/incidents/${a.incident_id}`} className="text-[12.5px] text-accent hover:text-accent-strong">Open →</Link> : <span className="text-[12px] text-faint">—</span>}</td>
                    <td className="text-muted" title={dateTime(a.last_event_at)}>{relTime(a.last_event_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {query.data && <Pager total={query.data.total} offset={offset} limit={50} onChange={setOffset} />}
      </Card>
      <AlertDrawer alert={selected} onClose={() => setSelected(null)} />
    </div>
  )
}

export function AlertDrawer({ alert, onClose }: { alert: Alert | null; onClose: () => void }) {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [eventId, setEventId] = useState<string | null>(null)
  const events = useQuery({
    queryKey: ['alert-events', alert?.id],
    enabled: !!alert,
    queryFn: () => api.get<SecurityEvent[]>(`/alerts/${alert!.id}/events`, { limit: 100 }),
  })
  const update = useMutation({
    mutationFn: (status: string) => api.patch(`/alerts/${alert!.id}`, { status }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['alerts'] }); onClose() },
    onError: toastError,
  })
  if (!alert) return null
  const obs = (alert.details?.observed ?? {}) as Record<string, unknown[]>
  return (
    <>
      <Drawer
        open={!!alert}
        onClose={onClose}
        title={alert.title}
        subtitle={<span className="flex items-center gap-2"><SeverityBadge severity={severityFromScore(alert.severity)} size="sm" /> {DETECTION_SOURCE_LABEL[alert.source]} · <Badge>{alert.status}</Badge></span>}
        footer={
          <div className="flex items-center justify-between gap-2">
            {alert.incident_id ? <Link to={`/incidents/${alert.incident_id}`}><Button variant="primary">Open incident <ArrowRight className="size-3.5" /></Button></Link> : <span />}
            {can('incident:update') && (
              <div className="flex gap-2">
                {alert.status !== 'acknowledged' && <Button size="sm" onClick={() => update.mutate('acknowledged')}>Acknowledge</Button>}
                {alert.status !== 'closed' && <Button size="sm" variant="ghost" onClick={() => update.mutate('closed')}>Close</Button>}
              </div>
            )}
          </div>
        }
      >
        <div className="space-y-5">
          {alert.description && <p className="text-[13px] text-muted">{alert.description}</p>}
          <KeyValue items={[
            ['First seen', dateTime(alert.first_event_at, { seconds: true })],
            ['Last seen', dateTime(alert.last_event_at, { seconds: true })],
            ['Host', alert.hostname],
            ['User', alert.username],
            ['Source IP', alert.src_ip && <Mono key="s">{alert.src_ip}</Mono>],
            ['Destination', alert.dest_ip && <Mono key="d">{alert.dest_ip}</Mono>],
            ['Domain', alert.domain && <Mono key="dm">{alert.domain}</Mono>],
            ['Telemetry', <SourcePills key="s" sources={alert.source_types} />],
            ['Rule', <Mono key="r" className="text-faint">{alert.rule_uid}</Mono>],
          ]} />
          {alert.mitre_techniques.length > 0 && <div><SectionTitle>ATT&CK</SectionTitle><div className="flex flex-wrap gap-1">{alert.mitre_techniques.map((t) => <TechniqueChip key={t} id={t} />)}</div></div>}
          {Object.keys(obs).length > 0 && (
            <div>
              <SectionTitle>Observed values</SectionTitle>
              <div className="space-y-1.5 text-[12.5px]">
                {Object.entries(obs).map(([k, vals]) => (
                  <div key={k} className="flex gap-2"><span className="w-28 shrink-0 text-faint">{k.replace(/_/g, ' ')}</span><span className="min-w-0 flex-1 break-all font-mono text-[11.5px]">{vals.slice(0, 8).join(', ')}{vals.length > 8 && ` (+${vals.length - 8})`}</span></div>
                ))}
              </div>
            </div>
          )}
          <div>
            <SectionTitle>Source events ({num(alert.event_count)})</SectionTitle>
            {events.isLoading ? <Skeleton className="h-24" /> : (
              <div className="overflow-hidden rounded-lg border border-line">
                <table className="sx-table text-[12.5px]">
                  <tbody>
                    {(events.data ?? []).map((e) => (
                      <tr key={e.id} data-clickable="true" onClick={() => setEventId(e.id)}>
                        <td className="w-24 tnum text-faint">{clock(e.timestamp)}</td>
                        <td className="max-w-0 truncate">{e.summary}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </Drawer>
      <EventDrawer eventId={eventId} onClose={() => setEventId(null)} />
    </>
  )
}
