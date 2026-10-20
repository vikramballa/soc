import { useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import { ArrowRight, CheckCircle2, Clock, FlaskConical, Plug, Sparkles, Timer } from 'lucide-react'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { AreaChart, BarChart, HBar } from '../components/charts'
import { CategoryLabel, RiskScore, SeverityBadge, SourcePills, StatusBadge, sevText } from '../components/security'
import { toast, toastError } from '../components/toast'
import { Button, Card, CardHeader, EmptyState, ErrorState, Segmented, Skeleton } from '../components/ui'
import { api, setTenantOverride } from '../lib/api'
import { useAuth } from '../lib/auth'
import { compact, duration, num, pct, relTime, TACTIC_LABEL } from '../lib/format'
import type { IncidentSummary, Severity } from '../lib/types'

interface Summary {
  window_hours: number
  funnel: {
    raw_events: number
    security_events: number
    alerts: number
    correlated_groups: number
    incidents: number
    critical: number
    high: number
    reduction_pct: number | null
  }
  open_by_severity: Record<Severity, number>
  open_total: number
  attention: IncidentSummary[]
  trend: {
    incidents_per_day: { day: string; count: number }[]
    events_per_hour: { t: string; count: number }[]
  }
  top_assets: { id: string; hostname: string; risk_score: number; criticality: number }[]
  top_users: { id: string; username: string; risk_score: number; privileged: boolean }[]
  top_techniques: { id: string; incidents: number; name: string; tactic: string | null }[]
  threat_intel_matches: number
  ingestion: { source: string; events_total: number; failures: number; last_ingest_at: string | null; status: string }[]
  metrics: { mtta_seconds: number | null; mttr_seconds: number | null; false_positive_rate: number | null; dispositioned: number }
  system: { worker: { running: boolean; queued_jobs: number }; ai: { available: boolean; model: string; reason?: string } }
}

const WINDOWS = [
  { value: '24', label: '24h' },
  { value: '168', label: '7d' },
  { value: '720', label: '30d' },
]

function greeting() {
  const h = new Date().getHours()
  return h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening'
}

function DemoButton() {
  const { me, can } = useAuth()
  const [busy, setBusy] = useState(false)
  const qc = useQueryClient()
  const nav = useNavigate()
  if (!can('platform:manage')) return null
  const existing = me.tenants.find((t) => t.demo && t.demo_loaded_at)
  if (existing && me.tenant?.id !== existing.id) {
    return (
      <Button
        variant="secondary"
        icon={<FlaskConical className="size-4" />}
        onClick={() => {
          setTenantOverride(existing.id)
          qc.clear()
          nav('/')
        }}
      >
        Open demo lab
      </Button>
    )
  }
  const run = async () => {
    setBusy(true)
    try {
      const before = me.tenants.find((t) => t.demo)?.demo_loaded_at ?? null
      await api.post('/admin/demo')
      toast('Building the Demo Lab with synthetic attack scenarios…', 'info')
      const started = Date.now()
      let demoId: string | null = null
      while (!demoId) {
        await new Promise((r) => setTimeout(r, 2000))
        const m = await api.get<typeof me>('/auth/me')
        const demo = m.tenants.find((t) => t.demo && t.demo_loaded_at && t.demo_loaded_at !== before)
        if (demo) demoId = demo.id
        else if (Date.now() - started > 180_000)
          throw new Error('The demo is taking longer than expected — check that the background worker is running.')
      }
      setTenantOverride(demoId)
      qc.clear()
      nav('/')
      toast('Demo Lab ready — you are now viewing synthetic data.')
    } catch (e) {
      toastError(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Button variant="secondary" icon={<FlaskConical className="size-4" />} loading={busy} onClick={run}>
      {me.tenants.some((t) => t.demo) ? 'Rebuild demo lab' : 'Explore demo lab'}
    </Button>
  )
}

function Stat({ label, value, sub, icon }: { label: string; value: string; sub?: string; icon: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-line bg-bg-elev px-3 py-2.5">
      <div className="mt-0.5 text-faint [&>svg]:size-4">{icon}</div>
      <div className="min-w-0">
        <div className="text-[11.5px] text-faint">{label}</div>
        <div className="tnum text-[16px] font-semibold tracking-[-0.01em]">{value}</div>
        {sub && <div className="text-[11.5px] text-faint">{sub}</div>}
      </div>
    </div>
  )
}

function AttentionList({ items }: { items: IncidentSummary[] }) {
  const nav = useNavigate()
  if (!items.length)
    return (
      <EmptyState icon={<CheckCircle2 className="size-5 text-ok" />} title="Nothing needs your attention right now">
        No open incidents. SentinelX keeps correlating new telemetry in the background.
      </EmptyState>
    )
  return (
    <ul className="divide-y divide-line">
      {items.map((inc, i) => (
        <li key={inc.id} className="animate-in" style={{ animationDelay: `${i * 40}ms` }}>
          <button
            onClick={() => nav(`/incidents/${inc.id}`)}
            className="group flex w-full items-center gap-3.5 px-4 py-3 text-left transition-colors duration-150 hover:bg-surface-2"
          >
            <RiskScore score={inc.risk_score} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="font-mono text-[11.5px] text-faint">INC-{inc.number}</span>
                <SeverityBadge severity={inc.severity} size="sm" />
                <StatusBadge status={inc.status} />
              </div>
              <div className="mt-1 truncate text-[13.5px] font-medium">{inc.title}</div>
              <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[12px] text-faint">
                <CategoryLabel category={inc.category} />
                <span>·</span>
                <span>{inc.alert_count} detections · {num(inc.event_count)} events</span>
                <span>·</span>
                <span>last activity {relTime(inc.last_event_at)}</span>
              </div>
            </div>
            <div className="hidden xl:block"><SourcePills sources={inc.source_types} /></div>
            <ArrowRight className="size-4 text-faint transition-transform duration-150 group-hover:translate-x-0.5" />
          </button>
        </li>
      ))}
    </ul>
  )
}

function Funnel({ f }: { f: Summary['funnel'] }) {
  const steps = [
    { label: 'Raw events', value: f.raw_events, hint: 'All telemetry received' },
    { label: 'Security-relevant events', value: f.security_events, hint: 'Matched at least one detection' },
    { label: 'Alerts', value: f.alerts, hint: 'After de-duplication' },
    { label: 'Correlated groups', value: f.correlated_groups, hint: 'Related alerts joined together' },
    { label: 'Incidents', value: f.incidents, hint: 'Raised for a human to review' },
  ]
  // log scale so 12,000 and 7 are both visible; the numbers carry the exact values
  const lmax = Math.log10(Math.max(10, f.raw_events) + 1)
  return (
    <div className="space-y-3 px-4 pb-4">
      {steps.map((s) => (
        <div key={s.label}>
          <div className="mb-1 flex items-baseline justify-between gap-2">
            <span className="text-[12.5px] text-muted" title={s.hint}>{s.label}</span>
            <span className="tnum text-[13px] font-semibold">{num(s.value)}</span>
          </div>
          <HBar value={Math.log10(s.value + 1)} max={lmax} tone={s.label === 'Incidents' ? 'high' : 'accent'} />
        </div>
      ))}
      <p className="pt-1 text-[11.5px] text-faint">Bar lengths use a log scale; numbers are exact.</p>
    </div>
  )
}

export default function Dashboard() {
  const { me } = useAuth()
  const [win, setWin] = useState('24')
  const q = useQuery({
    queryKey: ['dashboard', win],
    queryFn: () => api.get<Summary>('/dashboard/summary', { hours: win }),
    refetchInterval: 30_000,
  })
  const d = q.data

  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />

  const noData = d && d.funnel.raw_events === 0 && d.open_total === 0 && !d.ingestion.length
  return (
    <div>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-[20px] font-semibold tracking-[-0.015em]">
            {greeting()}, {me.user.display_name.split(' ')[0]}
          </h1>
          <p className="mt-1 text-[13px] text-muted">
            {d ? (
              d.open_total ? (
                <>
                  <b className="text-fg">{d.open_total} open incident{d.open_total > 1 ? 's' : ''}</b>
                  {d.open_by_severity.critical + d.open_by_severity.high > 0 && (
                    <> — {d.open_by_severity.critical + d.open_by_severity.high} high or critical. Start with the top of the list.</>
                  )}
                </>
              ) : (
                'All clear — no open incidents.'
              )
            ) : (
              'Loading your security overview…'
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <DemoButton />
          <Segmented value={win} onChange={setWin} items={WINDOWS} />
        </div>
      </div>

      {noData && (
        <Card className="mb-5">
          <EmptyState
            icon={<Plug className="size-5" />}
            title="No telemetry yet"
            action={
              <div className="flex gap-2">
                <Link to="/integrations"><Button variant="primary">Connect a data source</Button></Link>
                <DemoButton />
              </div>
            }
          >
            Connect Wazuh, Suricata or Zeek to start detecting threats — or explore the Demo Lab, which replays three
            synthetic attack scenarios end to end.
          </EmptyState>
        </Card>
      )}

      <div className="grid gap-5 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader
            title="Needs your attention"
            subtitle="Open incidents ranked by explainable risk"
            action={<Link to="/incidents" className="text-[12.5px] text-accent hover:text-accent-strong">All incidents →</Link>}
          />
          {d ? <AttentionList items={d.attention} /> : <div className="space-y-2 p-4">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-14" />)}</div>}
        </Card>

        <div className="space-y-5">
          <Card>
            <CardHeader title="Open incidents" subtitle="By severity" />
            <div className="space-y-1 px-2 pb-3">
              {(['critical', 'high', 'medium', 'low', 'informational'] as Severity[]).map((s) => (
                <Link
                  key={s}
                  to={`/incidents?status=open&severity=${s}`}
                  className="flex items-center justify-between rounded-lg px-2 py-1.5 transition-colors duration-150 hover:bg-surface-2"
                >
                  <SeverityBadge severity={s} size="sm" />
                  <span className={clsx('tnum text-[14px] font-semibold', d?.open_by_severity[s] ? sevText(s) : 'text-faint')}>
                    {d ? d.open_by_severity[s] : '–'}
                  </span>
                </Link>
              ))}
            </div>
          </Card>
          <div className="grid grid-cols-2 gap-3">
            <Stat icon={<Clock />} label="Mean time to acknowledge" value={duration(d?.metrics.mtta_seconds)} sub="last 30 days" />
            <Stat icon={<Timer />} label="Mean time to resolve" value={duration(d?.metrics.mttr_seconds)} sub="last 30 days" />
            <Stat icon={<CheckCircle2 />} label="False-positive rate" value={pct(d?.metrics.false_positive_rate)} sub={`${d?.metrics.dispositioned ?? 0} closed with a verdict`} />
            <Stat icon={<Sparkles />} label="Threat-intel matches" value={num(d?.threat_intel_matches)} sub="in this window" />
          </div>
        </div>

        <Card>
          <CardHeader
            title="Noise reduction"
            subtitle={d?.funnel.reduction_pct != null ? <>Alerts reduced to incidents by <b className="text-fg">{d.funnel.reduction_pct}%</b></> : 'From raw telemetry to incidents'}
          />
          {d ? <Funnel f={d.funnel} /> : <Skeleton className="m-4 h-40" />}
        </Card>

        <Card>
          <CardHeader title="Event volume" subtitle="Events per hour, last 24 hours" />
          <div className="px-4 pb-4">
            {d ? (
              <AreaChart
                unit="events"
                height={190}
                data={d.trend.events_per_hour.map((p) => ({
                  label: new Date(p.t).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' }),
                  value: p.count,
                }))}
              />
            ) : (
              <Skeleton className="h-28" />
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="New incidents" subtitle="Per day, last 14 days" />
          <div className="px-4 pb-4">
            {d ? (
              <BarChart
                unit="incidents"
                height={190}
                data={d.trend.incidents_per_day.map((p) => ({
                  label: new Date(p.day).toLocaleDateString([], { month: 'short', day: 'numeric' }),
                  value: p.count,
                }))}
              />
            ) : (
              <Skeleton className="h-28" />
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Most at risk" subtitle="Hosts and accounts in open incidents" />
          <div className="px-4 pb-4">
            {d && (d.top_assets.length || d.top_users.length) ? (
              <ul className="space-y-3">
                {d.top_assets.map((a) => (
                  <li key={a.id}>
                    <div className="mb-1 flex justify-between text-[12.5px]">
                      <Link to={`/assets?focus=${a.id}`} className="font-medium hover:text-accent">{a.hostname}</Link>
                      <span className="tnum text-muted">{a.risk_score}</span>
                    </div>
                    <HBar value={a.risk_score} max={100} tone={a.risk_score > 75 ? 'high' : 'accent'} />
                  </li>
                ))}
                {d.top_users.map((u) => (
                  <li key={u.id}>
                    <div className="mb-1 flex justify-between text-[12.5px]">
                      <Link to={`/events?user=${encodeURIComponent(u.username)}&hours=168`} className="font-medium hover:text-accent">
                        {u.username}
                        <span className="ml-1.5 text-[11.5px] font-normal text-faint">{u.privileged ? 'privileged account' : 'account'}</span>
                      </Link>
                      <span className="tnum text-muted">{u.risk_score}</span>
                    </div>
                    <HBar value={u.risk_score} max={100} tone={u.risk_score > 75 ? 'high' : 'accent'} />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="py-6 text-center text-[12.5px] text-faint">No hosts or accounts involved in open incidents.</p>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Top ATT&CK techniques" subtitle="Seen in incidents in this window" action={<Link to="/mitre" className="text-[12.5px] text-accent">Matrix →</Link>} />
          <div className="px-4 pb-4">
            {d?.top_techniques.length ? (
              <TechniqueList items={d.top_techniques} />
            ) : (
              <p className="py-6 text-center text-[12.5px] text-faint">No techniques observed.</p>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Telemetry sources" subtitle="Ingestion health" action={<Link to="/integrations" className="text-[12.5px] text-accent">Manage →</Link>} />
          <div className="px-4 pb-4">
            {d?.ingestion.length ? (
              <ul className="divide-y divide-line">
                {d.ingestion.map((s) => (
                  <li key={s.source} className="flex items-center justify-between py-2 text-[12.5px]">
                    <span className="flex items-center gap-2">
                      <span className={clsx('size-1.5 rounded-full', s.status === 'healthy' ? 'bg-ok' : 'bg-faint')} />
                      <span className="font-medium capitalize">{s.source}</span>
                      <span className="text-faint">{s.status === 'healthy' ? 'receiving' : `idle · last ${relTime(s.last_ingest_at)}`}</span>
                    </span>
                    <span className="tnum text-muted">{compact(s.events_total)} events{s.failures ? ` · ${s.failures} rejected` : ''}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="py-6 text-center text-[12.5px] text-faint">No sources have sent data yet.</p>
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}

function TechniqueList({ items }: { items: Summary['top_techniques'] }) {
  const max = Math.max(...items.map((i) => i.incidents))
  return (
    <ul className="space-y-3">
      {items.map((t) => (
        <li key={t.id}>
          <div className="mb-1 flex items-baseline justify-between gap-2 text-[12.5px]">
            <span className="min-w-0 truncate">
              <span className="font-mono text-[11px] text-accent-strong">{t.id}</span>{' '}
              <span className="font-medium">{t.name}</span>
              {t.tactic && <span className="text-faint"> · {TACTIC_LABEL[t.tactic] ?? t.tactic}</span>}
            </span>
            <span className="tnum shrink-0 text-muted">{t.incidents}</span>
          </div>
          <HBar value={t.incidents} max={max} />
        </li>
      ))}
    </ul>
  )
}
