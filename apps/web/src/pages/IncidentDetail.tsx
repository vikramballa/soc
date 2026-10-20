import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  ArrowLeft,
  Bot,
  Brain,
  ChevronRight,
  Download,
  Eye,
  Globe2,
  ListChecks,
  Monitor,
  Plus,
  Sparkles,
  Square,
  SquareCheck,
  User,
} from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { AiPanel } from '../components/AiPanel'
import { HBar } from '../components/charts'
import { EventDrawer } from '../components/EventDrawer'
import { EvidenceGraph } from '../components/EvidenceGraph'
import { Modal } from '../components/overlay'
import {
  CategoryLabel,
  ConfidenceMeter,
  RiskScore,
  SeverityBadge,
  SourcePills,
  StatusBadge,
  TechniqueChip,
  sevBar,
  sevText,
} from '../components/security'
import { toast, toastError } from '../components/toast'
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  Input,
  KeyValue,
  Label,
  Mono,
  SectionTitle,
  Select,
  Skeleton,
  Tabs,
  Textarea,
} from '../components/ui'
import { api, apiUrl } from '../lib/api'
import { useAuth } from '../lib/auth'
import {
  clock,
  clock24,
  dateTime,
  DETECTION_SOURCE_LABEL,
  num,
  relTime,
  severityFromScore,
  STATUS_LABEL,
  TACTIC_LABEL,
} from '../lib/format'
import type { Alert, IncidentDetail as Incident, SecurityEvent, TimelineEntry } from '../lib/types'

interface Context {
  entities: { kind: string; value: string; alert_count: number }[]
  assets: { hostname: string; os: string | null; criticality: number; owner: string | null; environment: string | null; tags: string[]; ip_addresses: string[]; risk_score: number }[]
  identities: { username: string; email: string | null; department: string | null; privileged: boolean }[]
  threat_intel: { value: string; indicator_type: string; provider: string; verdict: string; confidence: number; tags: string[]; references: string[] }[]
  ml: { host: string; window_start: string; anomaly_score: number; is_anomaly: boolean; top_contributors: { feature: string; value: number; baseline_median: number; z_score: number }[] }[]
  mitre: { id: string; name: string; tactics: string[]; url: string | null; alerts: string[] }[]
  graph: { nodes: any[]; edges: any[] }
}

interface Activity {
  id: string
  kind: string
  actor: string
  message: string
  created_at: string
}

interface ResponseAction {
  id: string
  kind: string
  status: string
  title: string
  payload: Record<string, any>
  requested_by: string
  created_at: string
}

const STATUSES = ['new', 'triaged', 'investigating', 'contained', 'resolved', 'closed']
const DISPOSITIONS = [
  ['true_positive', 'True positive — real malicious activity'],
  ['benign_true_positive', 'Benign — real activity, but authorized'],
  ['false_positive', 'False positive — detection was wrong'],
  ['undetermined', 'Undetermined'],
]

const FEATURE_LABEL: Record<string, string> = {
  auth_failures: 'failed logins', auth_successes: 'successful logins', dns_queries: 'DNS queries',
  distinct_domains: 'distinct domains', connections: 'connections', distinct_dest_ips: 'distinct destinations',
  distinct_dest_ports: 'distinct ports', rare_port_connections: 'unusual-port connections', bytes_out: 'bytes sent',
  powershell: 'PowerShell starts', processes: 'process starts', distinct_processes: 'distinct programs',
  file_changes: 'file changes', events: 'events', distinct_users: 'distinct users',
}

export default function IncidentDetail() {
  const { can } = useAuth()
  const { id = '' } = useParams()
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') ?? 'overview') as 'overview' | 'timeline' | 'graph' | 'ai' | 'activity'
  const setTab = (t: string) => {
    const p = new URLSearchParams(params)
    p.set('tab', t)
    setParams(p, { replace: true })
  }
  const [eventId, setEventId] = useState<string | null>(null)

  const inc = useQuery({ queryKey: ['incident', id], queryFn: () => api.get<Incident>(`/incidents/${id}`), refetchInterval: 20_000 })
  const ctx = useQuery({ queryKey: ['incident-context', id], queryFn: () => api.get<Context>(`/incidents/${id}/context`) })
  const alerts = useQuery({ queryKey: ['incident-alerts', id], queryFn: () => api.get<Alert[]>(`/incidents/${id}/alerts`) })
  const timeline = useQuery({
    queryKey: ['incident-timeline', id],
    queryFn: () => api.get<{ total_events: number; entries: TimelineEntry[]; detections: any[]; milestones: any[] }>(`/incidents/${id}/timeline`),
  })
  const activity = useQuery({ queryKey: ['incident-activity', id], queryFn: () => api.get<Activity[]>(`/incidents/${id}/activity`) })

  if (inc.error) return <ErrorState error={inc.error} retry={() => inc.refetch()} />
  const i = inc.data
  if (!i) return <div className="space-y-4"><Skeleton className="h-24" /><Skeleton className="h-64" /></div>

  if (i.status === 'merged' && i.merged_into) {
    return (
      <EmptyState title={`INC-${i.number} was merged into another incident`} action={<Link to={`/incidents/${i.merged_into}`}><Button variant="primary">Open the combined incident</Button></Link>}>
        SentinelX found that this activity belongs to a larger incident and combined them.
      </EmptyState>
    )
  }

  const hosts = ctx.data?.entities.filter((e) => e.kind === 'host') ?? []
  const users = ctx.data?.entities.filter((e) => e.kind === 'user') ?? []

  return (
    <div>
      <Link to="/incidents" className="mb-3 inline-flex items-center gap-1 text-[12.5px] text-muted hover:text-fg">
        <ArrowLeft className="size-3.5" /> Incidents
      </Link>

      {/* Header */}
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <div className="mb-1.5 flex flex-wrap items-center gap-2">
            <span className="font-mono text-[12px] text-faint">INC-{i.number}</span>
            <SeverityBadge severity={i.severity} size="sm" />
            <StatusBadge status={i.status} />
            <CategoryLabel category={i.category} />
            {!i.promoted && <Badge tone="neutral" title="Below the incident threshold">low-signal group</Badge>}
          </div>
          <h1 className="text-[21px] leading-tight font-semibold tracking-[-0.015em]">{i.title}</h1>
          <p className="mt-1.5 text-[12.5px] text-faint">
            First seen {dateTime(i.first_event_at, { seconds: true })} · last activity {relTime(i.last_event_at)}
            {i.promotion_reason && <> · raised because of {i.promotion_reason}</>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {can('report:generate') && (
            <a href={apiUrl(`/incidents/${i.id}/report`, { fmt: 'html' })} target="_blank" rel="noreferrer">
              <Button icon={<Download className="size-4" />}>Report</Button>
            </a>
          )}
          <Button variant="ai" icon={<Sparkles className="size-4" />} onClick={() => setTab('ai')}>AI analyst</Button>
        </div>
      </div>

      {/* The five questions */}
      <Card className="mb-5">
        <div className="grid divide-y divide-line lg:grid-cols-[1.35fr_0.9fr_1fr] lg:divide-x lg:divide-y-0">
          <div className="p-4">
            <SectionTitle>What happened</SectionTitle>
            <p className="text-[13.5px] leading-relaxed text-fg">{i.description}</p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <SourcePills sources={i.source_types} />
            </div>
          </div>
          <div className="flex gap-4 p-4">
            <RiskScore score={i.risk_score} size="lg" />
            <div className="min-w-0">
              <SectionTitle>How serious</SectionTitle>
              <div className={clsx('text-[15px] font-semibold', sevText(i.severity))}>
                {i.severity === 'informational' ? 'Informational' : i.severity.charAt(0).toUpperCase() + i.severity.slice(1)} risk
              </div>
              <div className="mt-1.5"><ConfidenceMeter value={i.confidence} /></div>
              <button onClick={() => document.getElementById('risk-breakdown')?.scrollIntoView({ behavior: 'smooth' })} className="mt-1.5 text-[12px] text-accent hover:text-accent-strong">
                Why this score? →
              </button>
            </div>
          </div>
          <div className="p-4">
            <SectionTitle>Who & what is affected</SectionTitle>
            <div className="flex flex-wrap gap-1.5">
              {hosts.map((h) => {
                const a = ctx.data?.assets.find((x) => x.hostname === h.value)
                return (
                  <span key={h.value} className="inline-flex h-7 items-center gap-1.5 rounded-lg border border-line bg-surface-2 px-2 text-[12.5px]" title={a ? `Criticality ${a.criticality}/5 · ${a.owner ?? 'no owner'}` : undefined}>
                    <Monitor className="size-3.5 text-accent" />
                    {h.value}
                    {a && a.criticality >= 4 && <Badge tone="warn" className="h-4">critical asset</Badge>}
                  </span>
                )
              })}
              {users.map((u) => {
                const idn = ctx.data?.identities.find((x) => x.username === u.value)
                return (
                  <span key={u.value} className="inline-flex h-7 items-center gap-1.5 rounded-lg border border-line bg-surface-2 px-2 text-[12.5px]">
                    <User className="size-3.5 text-low" />
                    {u.value}
                    {idn?.privileged && <Badge tone="warn" className="h-4">privileged</Badge>}
                  </span>
                )
              })}
              {!hosts.length && !users.length && <span className="text-[12.5px] text-faint">{ctx.isLoading ? 'Loading…' : 'No managed host or account identified'}</span>}
            </div>
            {ctx.data && ctx.data.mitre.length > 0 && (
              <>
                <SectionTitle>ATT&CK techniques</SectionTitle>
                <div className="flex flex-wrap gap-1.5">{ctx.data.mitre.slice(0, 6).map((m) => <TechniqueChip key={m.id} id={m.id} name={m.name} />)}</div>
              </>
            )}
          </div>
        </div>
      </Card>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="min-w-0">
          <Tabs
            value={tab}
            onChange={setTab}
            className="mb-4"
            items={[
              { value: 'overview', label: 'Overview' },
              { value: 'timeline', label: 'Timeline', count: timeline.data?.total_events },
              { value: 'graph', label: 'Evidence graph' },
              { value: 'ai', label: <span className="flex items-center gap-1.5"><Bot className="size-3.5 text-ai" />AI analyst</span> },
              { value: 'activity', label: 'Notes & activity', count: activity.data?.length },
            ]}
          />
          {tab === 'overview' && <Overview i={i} ctx={ctx.data} alerts={alerts.data} />}
          {tab === 'timeline' && <Timeline data={timeline.data} loading={timeline.isLoading} onOpen={setEventId} />}
          {tab === 'graph' && (
            <Card className="p-4">{ctx.data ? <EvidenceGraph nodes={ctx.data.graph.nodes} edges={ctx.data.graph.edges} /> : <Skeleton className="h-80" />}</Card>
          )}
          {tab === 'ai' && <AiPanel incidentId={i.id} onOpenEvent={setEventId} />}
          {tab === 'activity' && <ActivityPanel incidentId={i.id} items={activity.data ?? []} />}
        </div>
        <aside className="space-y-5">
          <Workflow i={i} />
          <ResponsePanel i={i} ctx={ctx.data} />
          <Card className="p-4">
            <SectionTitle>Key facts</SectionTitle>
            <KeyValue
              items={[
                ['Created', dateTime(i.created_at)],
                ['Raised', i.promoted_at ? dateTime(i.promoted_at) : 'Not raised'],
                ['Acknowledged', i.acknowledged_at ? relTime(i.acknowledged_at) : 'Not yet'],
                ['Detections', i.alert_count],
                ['Evidence events', num(i.event_count)],
                ['Disposition', i.disposition?.replace(/_/g, ' ') ?? '—'],
              ]}
            />
            {i.confidence_factors.length > 0 && (
              <div className="mt-4">
                <SectionTitle>Confidence factors</SectionTitle>
                <ul className="space-y-1 text-[12px] text-muted">
                  {i.confidence_factors.map((f) => <li key={f}>{f}</li>)}
                </ul>
              </div>
            )}
          </Card>
        </aside>
      </div>
      <EventDrawer eventId={eventId} incidentId={i.id} onClose={() => setEventId(null)} />
    </div>
  )
}

/* Overview */
function Overview({ i, ctx, alerts }: { i: Incident; ctx?: Context; alerts?: Alert[] }) {
  const [open, setOpen] = useState<string | null>(null)
  const [eventId, setEventId] = useState<string | null>(null)
  const events = useQuery({
    queryKey: ['alert-events', open],
    enabled: !!open,
    queryFn: () => api.get<SecurityEvent[]>(`/alerts/${open}/events`, { limit: 50 }),
  })
  const byTactic = useMemo(() => {
    const m = new Map<string, Context['mitre']>()
    for (const t of ctx?.mitre ?? []) {
      const k = t.tactics[0] ?? 'other'
      m.set(k, [...(m.get(k) ?? []), t])
    }
    return [...m.entries()]
  }, [ctx])
  return (
    <div className="space-y-5">
      <Card id="risk-breakdown">
        <CardHeader title="Why this risk score" subtitle={`${i.risk_score}/100 — the sum of these factors (capped at 100). Weights are SentinelX's documented defaults.`} />
        <div className="space-y-3 px-4 pb-4">
          {i.risk_breakdown.map((c) => (
            <div key={c.key} className="grid grid-cols-[150px_1fr_56px] items-center gap-3 text-[12.5px]">
              <span className={clsx('font-medium', c.value ? 'text-fg' : 'text-faint')}>{c.label}</span>
              <div>
                <HBar value={c.value} max={c.max} tone={c.value / c.max > 0.66 ? 'high' : 'accent'} />
                <div className="mt-1 text-[12px] text-muted">{c.reason}</div>
              </div>
              <span className="tnum text-right text-muted">+{c.value}<span className="text-faint">/{c.max}</span></span>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <CardHeader title="Detections" subtitle="The rules and sensors that contributed. Expand one to see its source events." />
        {!alerts ? <Skeleton className="m-4 h-24" /> : (
          <ul className="divide-y divide-line border-t border-line">
            {alerts.map((a) => (
              <li key={a.id}>
                <button onClick={() => setOpen(open === a.id ? null : a.id)} className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-surface-2">
                  <ChevronRight className={clsx('size-4 shrink-0 text-faint transition-transform duration-150', open === a.id && 'rotate-90')} />
                  <SeverityBadge severity={severityFromScore(a.severity)} size="sm" />
                  <span className="min-w-0 flex-1 truncate text-[13px] font-medium">{a.title}</span>
                  <span className="hidden text-[12px] text-faint sm:inline">{DETECTION_SOURCE_LABEL[a.source] ?? a.source}</span>
                  <span className="tnum w-20 text-right text-[12px] text-muted">{num(a.event_count)} event{a.event_count === 1 ? '' : 's'}</span>
                  <span className="w-20 text-right text-[12px] text-faint">{clock(a.first_event_at)}</span>
                </button>
                {open === a.id && (
                  <div className="animate-in space-y-3 bg-bg-elev px-4 py-3 pl-11">
                    {a.description && <p className="text-[12.5px] text-muted">{a.description}</p>}
                    {a.details?.correlation && (
                      <p className="text-[12.5px] text-muted">
                        Correlation: <b className="text-fg">{a.details.correlation.value}</b> matches ({a.details.correlation.type.replace('_', ' ')}) within{' '}
                        {Math.round(a.details.correlation.timespan_seconds / 60)} minutes, grouped by {Object.entries(a.details.correlation.group_by).map(([k, v]) => `${k}=${v}`).join(', ')}.
                      </p>
                    )}
                    {a.details?.ml && (
                      <p className="text-[12.5px] text-muted">Anomaly score {(a.details.ml.anomaly_score * 100).toFixed(1)} percentile vs. baseline (model v{a.details.ml.model_version}).</p>
                    )}
                    {a.details?.falsepositives?.length > 0 && (
                      <p className="text-[12px] text-faint">Known benign causes: {a.details.falsepositives.join('; ')}</p>
                    )}
                    {a.mitre_techniques.length > 0 && <div className="flex flex-wrap gap-1">{a.mitre_techniques.map((t) => <TechniqueChip key={t} id={t} />)}</div>}
                    <div className="overflow-hidden rounded-lg border border-line">
                      {events.isLoading ? <Skeleton className="h-16" /> : (
                        <table className="sx-table text-[12.5px]">
                          <tbody>
                            {(events.data ?? []).slice(0, 12).map((e) => (
                              <tr key={e.id} data-clickable="true" onClick={() => setEventId(e.id)}>
                                <td className="w-24 text-faint tnum">{clock(e.timestamp)}</td>
                                <td className="max-w-0 truncate">{e.summary}</td>
                                <td className="w-8"><Eye className="size-3.5 text-faint" /></td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                      {(events.data?.length ?? 0) > 12 && <div className="border-t border-line px-3 py-1.5 text-[12px] text-faint">+{(events.data?.length ?? 0) - 12} more in the Timeline tab</div>}
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>

      {byTactic.length > 0 && (
        <Card>
          <CardHeader title="MITRE ATT&CK" subtitle="Techniques backed by detection rules — never guessed by AI." />
          <div className="grid gap-3 px-4 pb-4 md:grid-cols-2">
            {byTactic.map(([tac, techs]) => (
              <div key={tac} className="rounded-lg border border-line bg-bg-elev p-3">
                <div className="mb-2 text-[11.5px] font-medium tracking-wide text-faint uppercase">{TACTIC_LABEL[tac] ?? tac}</div>
                {techs.map((t) => (
                  <div key={t.id} className="mb-1.5 last:mb-0">
                    <a href={t.url ?? '#'} target="_blank" rel="noreferrer" className="text-[13px] hover:text-accent">
                      <span className="font-mono text-[11.5px] text-accent-strong">{t.id}</span> {t.name}
                    </a>
                    <div className="text-[11.5px] text-faint">via {t.alerts.join(', ')}</div>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </Card>
      )}

      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader title="Threat intelligence" icon={<Globe2 className="size-4" />} subtitle="Reputation is context, not proof." />
          <div className="px-4 pb-4">
            {ctx?.threat_intel.length ? (
              <ul className="space-y-2.5">
                {ctx.threat_intel.map((t) => (
                  <li key={t.value + t.provider} className="text-[12.5px]">
                    <div className="flex items-center justify-between gap-2">
                      <Mono className="truncate text-fg">{t.value}</Mono>
                      <Badge tone={t.verdict === 'malicious' ? 'danger' : t.verdict === 'suspicious' ? 'warn' : 'neutral'}>{t.verdict}</Badge>
                    </div>
                    <div className="mt-0.5 text-faint">{t.provider} · confidence {Math.round(t.confidence * 100)}%{t.tags.length ? ` · ${t.tags.join(', ')}` : ''}</div>
                  </li>
                ))}
              </ul>
            ) : <p className="py-4 text-[12.5px] text-faint">No indicator in this incident matched threat intelligence.</p>}
          </div>
        </Card>
        <Card>
          <CardHeader title="Behavioral analysis (ML)" icon={<Brain className="size-4" />} subtitle="How affected hosts compare with their learned baseline." />
          <div className="px-4 pb-4">
            {ctx?.ml.filter((m) => m.is_anomaly).length ? (
              <ul className="space-y-3">
                {ctx.ml.filter((m) => m.is_anomaly).map((m) => (
                  <li key={m.host + m.window_start} className="text-[12.5px]">
                    <div className="flex justify-between"><span className="font-medium">{m.host}</span><span className="text-faint">{dateTime(m.window_start)} · score {(m.anomaly_score * 100).toFixed(1)}</span></div>
                    <ul className="mt-1 space-y-0.5 text-muted">
                      {m.top_contributors.slice(0, 3).map((c) => (
                        <li key={c.feature}>{FEATURE_LABEL[c.feature] ?? c.feature}: <b className="text-fg tnum">{num(Math.round(c.value))}</b> (usually ~{num(Math.round(c.baseline_median))})</li>
                      ))}
                    </ul>
                  </li>
                ))}
              </ul>
            ) : <p className="py-4 text-[12.5px] text-faint">No behavioral anomaly on the affected hosts during this incident.</p>}
          </div>
        </Card>
      </div>
      <EventDrawer eventId={eventId} onClose={() => setEventId(null)} />
    </div>
  )
}

/* Timeline */
function Timeline({ data, loading, onOpen }: { data?: { total_events: number; entries: TimelineEntry[]; milestones: any[] }; loading: boolean; onOpen: (id: string) => void }) {
  if (loading || !data) return <Skeleton className="h-80" />
  if (!data.entries.length) return <Card><EmptyState title="No evidence events" /></Card>
  const dayOf = (ts: string) => new Date(ts).toDateString()
  return (
    <Card className="p-4">
      <p className="mb-4 text-[12.5px] text-muted">
        {num(data.total_events)} evidence events in chronological order. Repeats of the same behaviour are grouped; click any row to open the original event.
      </p>
      <ol className="relative">
        <span className="absolute top-2 bottom-2 left-[83px] w-px bg-line" />
        {data.entries.map((e, idx) => {
          const showDay = idx === 0 || dayOf(e.timestamp) !== dayOf(data.entries[idx - 1].timestamp)
          const sev = severityFromScore(e.severity ?? 0)
          return (
            <li key={e.event_id + idx}>
              {showDay && <div className="mb-1 ml-[100px] pt-1 text-[11.5px] font-medium tracking-wide text-faint uppercase">{new Date(e.timestamp).toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' })}</div>}
              <button onClick={() => onOpen(e.event_ids[0])} className="group relative flex w-full items-start gap-4 rounded-lg py-1.5 pr-2 text-left hover:bg-surface-2">
                <span className="tnum w-[70px] shrink-0 pt-0.5 text-right font-mono text-[11.5px] whitespace-nowrap text-faint">{clock24(e.timestamp)}</span>
                <span className={clsx('relative z-[1] mt-1.5 size-2.5 shrink-0 rounded-full ring-4 ring-[var(--surface)]', e.alert_title ? sevBar(sev) : 'bg-faint')} />
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="min-w-0 text-[13px] break-all text-fg">{e.summary}</span>
                    {e.count > 1 && <Badge tone="accent">×{e.count}</Badge>}
                  </span>
                  <span className="mt-0.5 block truncate text-[12px] text-faint">
                    {e.source_type}
                    {e.alert_title && <> · <span className="text-muted">{e.alert_title}</span></>}
                    {e.count > 1 && <> · until {clock(e.last_timestamp)}</>}
                    {e.process_command_line && e.event_type === 'process' && <> · <Mono>{e.process_command_line.slice(0, 120)}</Mono></>}
                  </span>
                </span>
                <Eye className="mt-1 size-3.5 shrink-0 text-faint opacity-0 transition-opacity group-hover:opacity-100" />
              </button>
            </li>
          )
        })}
        {data.milestones.map((m: any) => (
          <li key={m.timestamp + m.kind} className="flex items-start gap-4 py-1.5">
            <span className="tnum w-[70px] shrink-0 pt-0.5 text-right font-mono text-[11.5px] whitespace-nowrap text-faint">{clock24(m.timestamp)}</span>
            <span className="relative z-[1] mt-1.5 size-2.5 shrink-0 rounded-sm bg-ai ring-4 ring-[var(--surface)]" />
            <span className="text-[13px] text-ai">{m.message}</span>
          </li>
        ))}
      </ol>
    </Card>
  )
}

/* Workflow */
function Workflow({ i }: { i: Incident }) {
  const { can, me } = useAuth()
  const qc = useQueryClient()
  const [closing, setClosing] = useState<string | null>(null)
  const [disp, setDisp] = useState(i.disposition ?? 'true_positive')
  const patch = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.patch<Incident>(`/incidents/${i.id}`, body),
    onSuccess: (d) => {
      qc.setQueryData(['incident', i.id], d)
      qc.invalidateQueries({ queryKey: ['incident-activity', i.id] })
      qc.invalidateQueries({ queryKey: ['incidents'] })
      toast(`Incident ${STATUS_LABEL[d.status].toLowerCase()}`)
      setClosing(null)
    },
    onError: toastError,
  })
  const canEdit = can('incident:update')
  const canClose = can('incident:close')
  const people = useQuery({
    queryKey: ['assignees'],
    queryFn: () => api.get<{ id: string; display_name: string; email: string; role: string }[]>('/incidents/assignees'),
    enabled: canEdit,
    staleTime: 60_000,
  })
  const next: Record<string, { label: string; to: string }> = {
    new: { label: 'Start investigating', to: 'investigating' },
    triaged: { label: 'Start investigating', to: 'investigating' },
    investigating: { label: 'Mark contained', to: 'contained' },
    contained: { label: 'Resolve', to: 'resolved' },
    resolved: { label: 'Close', to: 'closed' },
    closed: { label: 'Reopen', to: 'investigating' },
  }
  const isFinal = (s: string) => s === 'resolved' || s === 'closed'
  const n = next[i.status]
  const canGo = (to: string) => canEdit && (!isFinal(to) || canClose)
  const go = (to: string) => {
    if (isFinal(to) && !i.disposition) setClosing(to)
    else patch.mutate({ status: to })
  }
  const mine = i.assigned_to === me.user.id
  const assignee = people.data?.find((p) => p.id === i.assigned_to)
  return (
    <Card className="p-4">
      <SectionTitle>Workflow</SectionTitle>
      <div className="mb-3 flex items-center gap-1">
        {STATUSES.map((s, idx) => {
          const cur = STATUSES.indexOf(i.status)
          return <span key={s} title={STATUS_LABEL[s]} className={clsx('h-1.5 flex-1 rounded-full', idx <= cur ? 'bg-accent' : 'bg-surface-3')} />
        })}
      </div>
      <div className="mb-3 text-[12.5px] text-muted">
        Status: <b className="text-fg">{STATUS_LABEL[i.status]}</b>
        {i.assigned_to && <> · Owner: <b className="text-fg">{mine ? 'you' : assignee?.display_name ?? 'a teammate'}</b></>}
      </div>
      {canEdit ? (
        <div className="space-y-2">
          {n && canGo(n.to) && <Button variant="primary" className="w-full" loading={patch.isPending} onClick={() => go(n.to)}>{n.label}</Button>}
          {n && !canGo(n.to) && <p className="rounded-lg bg-surface-2 px-3 py-2 text-[12px] text-muted">A security analyst records the verdict and resolves this incident.</p>}
          <label className="block">
            <span className="mb-1 block text-[11.5px] text-faint">Status</span>
            <Select value={i.status} onChange={(e) => go(e.target.value)} aria-label="Set status">
              {STATUSES.filter((s) => canGo(s) || s === i.status).map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
            </Select>
          </label>
          <label className="block">
            <span className="mb-1 block text-[11.5px] text-faint">Owner</span>
            <Select value={i.assigned_to ?? ''} onChange={(e) => patch.mutate({ assigned_to: e.target.value || null })} aria-label="Assign owner">
              <option value="">Unassigned</option>
              {(people.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.id === me.user.id ? `${p.display_name} (you)` : p.display_name}</option>)}
              {i.assigned_to && !assignee && <option value={i.assigned_to}>Current owner</option>}
            </Select>
          </label>
          {!mine && <Button className="w-full" size="sm" variant="ghost" onClick={() => patch.mutate({ assigned_to: me.user.id })}>Assign to me</Button>}
        </div>
      ) : (
        <p className="text-[12px] text-faint">You have read-only access to this incident.</p>
      )}
      <Modal
        open={!!closing}
        onClose={() => setClosing(null)}
        title="What was the outcome?"
        description="Recording a verdict keeps your false-positive rate honest and helps tune detections."
        footer={<>
          <Button variant="ghost" onClick={() => setClosing(null)}>Cancel</Button>
          <Button variant="primary" loading={patch.isPending} onClick={() => patch.mutate({ status: closing, disposition: disp })}>Save and {closing === 'closed' ? 'close' : 'resolve'}</Button>
        </>}
      >
        <div className="space-y-2">
          {DISPOSITIONS.map(([v, label]) => (
            <label key={v} className={clsx('flex cursor-pointer items-center gap-2.5 rounded-lg border px-3 py-2 text-[13px]', disp === v ? 'border-accent/50 bg-accent-soft' : 'border-line hover:border-line-strong')}>
              <input type="radio" name="disp" checked={disp === v} onChange={() => setDisp(v)} className="accent-[var(--accent)]" />
              {label}
            </label>
          ))}
        </div>
      </Modal>
    </Card>
  )
}

/* Response */
function ResponsePanel({ i, ctx }: { i: Incident; ctx?: Context }) {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [mode, setMode] = useState<'task' | 'ioc' | null>(null)
  const [text, setText] = useState('')
  const list = useQuery({ queryKey: ['responses', i.id], queryFn: () => api.get<ResponseAction[]>(`/incidents/${i.id}/responses`) })
  const create = useMutation({
    mutationFn: (body: unknown) => api.post(`/incidents/${i.id}/responses`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['responses', i.id] })
      qc.invalidateQueries({ queryKey: ['incident-activity', i.id] })
      toast(mode === 'ioc' ? 'Indicator added to the watchlist' : 'Task added')
      setMode(null)
      setText('')
    },
    onError: toastError,
  })
  const toggle = useMutation({
    mutationFn: (id: string) => api.patch(`/incidents/${i.id}/responses/${id}`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['responses', i.id] }),
  })
  const suggestions = (ctx?.entities ?? []).filter((e) => ['ip', 'domain', 'hash'].includes(e.kind)).slice(0, 4)
  const submit = () => {
    if (!text.trim()) return
    if (mode === 'task') create.mutate({ kind: 'task', title: text.trim(), payload: {} })
    else create.mutate({ kind: 'watchlist_ioc', title: `Watch ${text.trim()}`, payload: { value: text.trim() } })
  }
  return (
    <Card className="p-4">
      <SectionTitle>Response</SectionTitle>
      <p className="mb-3 text-[12px] text-faint">Safe, audited actions only. SentinelX never runs commands on your systems.</p>
      <ul className="mb-3 space-y-1.5">
        {(list.data ?? []).map((a) => (
          <li key={a.id} className="flex items-start gap-2 text-[12.5px]">
            {a.kind === 'task' ? (
              <button onClick={() => toggle.mutate(a.id)} disabled={!can('incident:update')} className="mt-0.5 text-muted enabled:hover:text-fg disabled:cursor-not-allowed" aria-label="Toggle task">
                {a.status === 'completed' ? <SquareCheck className="size-4 text-ok" /> : <Square className="size-4" />}
              </button>
            ) : <ListChecks className="mt-0.5 size-4 text-accent" />}
            <span className={clsx('flex-1', a.status === 'completed' && a.kind === 'task' && 'text-faint line-through')}>{a.title}</span>
          </li>
        ))}
        {!list.data?.length && <li className="text-[12.5px] text-faint">No actions yet.</li>}
      </ul>
      {can('response:execute') && (mode ? (
        <div className="space-y-2">
          <Input autoFocus value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && submit()}
            placeholder={mode === 'task' ? 'e.g. Reset jdoe password and revoke sessions' : 'IP, domain, hash or URL'} />
          {mode === 'ioc' && suggestions.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {suggestions.map((s) => <button key={s.value} onClick={() => setText(s.value)} className="rounded-md border border-line px-1.5 py-0.5 font-mono text-[11px] text-muted hover:text-fg">{s.value}</button>)}
            </div>
          )}
          <div className="flex justify-end gap-2">
            <Button size="sm" variant="ghost" onClick={() => setMode(null)}>Cancel</Button>
            <Button size="sm" variant="primary" loading={create.isPending} onClick={submit}>Add</Button>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-2">
          <Button size="sm" icon={<Plus className="size-3.5" />} onClick={() => setMode('task')}>Task</Button>
          <Button size="sm" icon={<Globe2 className="size-3.5" />} onClick={() => setMode('ioc')}>Watch IOC</Button>
        </div>
      ))}
    </Card>
  )
}

/* Activity */
function ActivityPanel({ incidentId, items }: { incidentId: string; items: Activity[] }) {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [body, setBody] = useState('')
  const add = useMutation({
    mutationFn: () => api.post(`/incidents/${incidentId}/notes`, { body }),
    onSuccess: () => {
      setBody('')
      qc.invalidateQueries({ queryKey: ['incident-activity', incidentId] })
    },
    onError: toastError,
  })
  return (
    <div className="space-y-4">
      {can('incident:update') && (
        <Card className="p-3">
          <Label>Add a note</Label>
          <Textarea value={body} onChange={(e) => setBody(e.target.value)} placeholder="What did you find? What did you do? Notes become part of the incident report." />
          <div className="mt-2 flex justify-end"><Button variant="primary" size="sm" disabled={!body.trim()} loading={add.isPending} onClick={() => add.mutate()}>Add note</Button></div>
        </Card>
      )}
      <Card>
        <ul className="divide-y divide-line">
          {items.map((a) => (
            <li key={a.id} className="flex gap-3 px-4 py-3">
              <span className={clsx('mt-1.5 size-2 shrink-0 rounded-full', a.kind === 'note' ? 'bg-accent' : a.kind === 'ai' ? 'bg-ai' : a.kind === 'promoted' ? 'bg-high' : 'bg-faint')} />
              <div className="min-w-0 flex-1">
                <div className={clsx('text-[13px]', a.kind === 'note' ? 'whitespace-pre-wrap text-fg' : 'text-muted')}>{a.message}</div>
                <div className="mt-0.5 text-[11.5px] text-faint">{a.actor} · {relTime(a.created_at)}</div>
              </div>
            </li>
          ))}
          {!items.length && <li className="px-4 py-8 text-center text-[13px] text-faint">No activity yet.</li>}
        </ul>
      </Card>
    </div>
  )
}

