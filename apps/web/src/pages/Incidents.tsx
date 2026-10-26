import { keepPreviousData, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Search, ShieldCheck } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { CategoryLabel, RiskScore, SeverityBadge, SourcePills, StatusBadge } from '../components/security'
import { Button, Card, EmptyState, ErrorState, Input, PageHeader, Select, SkeletonRows, Tabs } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { num, relTime, SEVERITY_LABEL } from '../lib/format'
import type { IncidentSummary, Page, Severity } from '../lib/types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'informational']
const PAGE = 50

export function Pager({ total, offset, limit, onChange }: { total: number; offset: number; limit: number; onChange: (o: number) => void }) {
  if (total <= limit) return null
  return (
    <div className="flex items-center justify-between border-t border-line px-4 py-2.5 text-[12.5px] text-muted">
      <span className="tnum">
        {num(offset + 1)}–{num(Math.min(total, offset + limit))} of {num(total)}
      </span>
      <div className="flex gap-1.5">
        <Button size="sm" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Previous</Button>
        <Button size="sm" disabled={offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</Button>
      </div>
    </div>
  )
}

export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}

export default function Incidents() {
  const [params, setParams] = useSearchParams()
  const nav = useNavigate()
  const status = params.get('status') ?? 'open'
  const severity = params.get('severity') ?? ''
  const sort = params.get('sort') ?? 'priority'
  const offset = Number(params.get('offset') ?? 0)
  const groups = params.get('groups') === '1'
  const assignee = params.get('assignee') ?? ''
  const { me } = useAuth()
  const [search, setSearch] = useState(params.get('q') ?? '')
  const q = useDebounced(search)
  const [active, setActive] = useState(0)

  const set = (k: string, v: string | null) => {
    const p = new URLSearchParams(params)
    if (v) p.set(k, v)
    else p.delete(k)
    if (k !== 'offset') p.delete('offset')
    setParams(p, { replace: true })
  }
  useEffect(() => {
    if ((params.get('q') ?? '') !== q) set('q', q || null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q])

  const query = useQuery({
    queryKey: ['incidents', status, severity, sort, q, offset, groups, assignee],
    queryFn: () =>
      api.get<Page<IncidentSummary>>('/incidents', {
        status: status === 'all' ? undefined : status,
        severity: severity || undefined,
        sort,
        q: q || undefined,
        offset,
        limit: PAGE,
        include_groups: groups,
        assignee: assignee || undefined,
      }),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  })
  const items = useMemo(() => query.data?.items ?? [], [query.data])

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).closest('input,textarea,select')) return
      if (e.key === 'j') setActive((a) => Math.min(items.length - 1, a + 1))
      if (e.key === 'k') setActive((a) => Math.max(0, a - 1))
      if (e.key === 'Enter' && items[active]) nav(`/incidents/${items[active].id}`)
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [items, active, nav])

  return (
    <div>
      <PageHeader
        title="Incidents"
        description="Each incident groups related detections across endpoints and the network. Ranked by an explainable risk score — open one to see what happened, why it matters and what to do next."
      />
      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-3 px-4 pt-2">
          <Tabs
            value={status}
            onChange={(v) => set('status', v)}
            items={[
              { value: 'open', label: 'Open' },
              { value: 'new', label: 'New' },
              { value: 'investigating', label: 'Investigating' },
              { value: 'closed', label: 'Resolved & closed' },
              { value: 'all', label: 'All' },
            ]}
            className="flex-1 border-b-0"
          />
        </div>
        <div className="flex flex-wrap items-center gap-2 border-y border-line bg-bg-elev px-4 py-2.5">
          <Input
            icon={<Search className="size-4" />}
            className="w-full max-w-xs"
            placeholder="Search title or INC number"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <div className="flex flex-wrap gap-1">
            {SEVERITIES.slice(0, 4).map((s) => {
              const on = severity.split(',').includes(s)
              return (
                <button
                  key={s}
                  onClick={() => {
                    const cur = new Set(severity.split(',').filter(Boolean))
                    if (on) cur.delete(s)
                    else cur.add(s)
                    set('severity', [...cur].join(',') || null)
                  }}
                  className={clsx(
                    'press h-7 rounded-lg border px-2 text-[12px] transition-colors',
                    on ? 'border-accent/40 bg-accent-soft text-fg' : 'border-line text-muted hover:text-fg',
                  )}
                  aria-pressed={on}
                >
                  {SEVERITY_LABEL[s]}
                </button>
              )
            })}
          </div>
          <Select value={assignee} onChange={(e) => set('assignee', e.target.value || null)} className="w-full max-w-44" aria-label="Filter by owner">
            <option value="">Owner: anyone</option>
            <option value="me">Assigned to me</option>
            <option value="unassigned">Unassigned</option>
          </Select>
          <div className="ml-auto flex items-center gap-2">
            <label className="flex items-center gap-1.5 text-[12px] whitespace-nowrap text-muted" title="Correlation groups that did not meet the incident threshold (noise SentinelX kept aside)">
              <input type="checkbox" checked={groups} onChange={(e) => set('groups', e.target.checked ? '1' : null)} className="accent-[var(--accent)]" />
              Show low-signal groups
            </label>
            <Select value={sort} onChange={(e) => set('sort', e.target.value)} className="w-40">
              <option value="priority">Sort: priority</option>
              <option value="newest">Sort: newest</option>
              <option value="updated">Sort: recently updated</option>
              <option value="risk">Sort: risk score</option>
            </Select>
          </div>
        </div>

        {query.error ? (
          <ErrorState error={query.error} retry={() => query.refetch()} />
        ) : !query.data ? (
          <SkeletonRows />
        ) : !items.length ? (
          <EmptyState icon={<ShieldCheck className="size-5 text-ok" />} title={assignee === 'me' ? 'Nothing assigned to you' : status === 'open' ? 'No open incidents' : 'No incidents match'}>
            {assignee === 'me' ? 'Incidents you own will show up here. Open an incident and choose “Assign to me” to take it.' : status === 'open' ? 'Nothing needs investigation right now.' : 'Try a different filter.'}
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="sx-table min-w-[900px]">
              <thead>
                <tr>
                  <th className="w-14">Risk</th>
                  <th>Incident</th>
                  <th className="w-28">Severity</th>
                  <th className="w-32">Status</th>
                  <th className="w-56">Telemetry</th>
                  <th className="w-24 text-right">Evidence</th>
                  <th className="w-32">Last activity</th>
                </tr>
              </thead>
              <tbody>
                {items.map((inc, i) => (
                  <tr
                    key={inc.id}
                    data-clickable="true"
                    data-active={i === active}
                    onClick={() => nav(`/incidents/${inc.id}`)}
                    onMouseEnter={() => setActive(i)}
                  >
                    <td><RiskScore score={inc.risk_score} size="sm" /></td>
                    <td className="max-w-0">
                      <div className="flex items-center gap-2">
                        <span className="shrink-0 font-mono text-[11.5px] text-faint">INC-{inc.number}</span>
                        <span className="truncate font-medium">{inc.title}</span>
                        {inc.assigned_to === me.user.id && <span className="shrink-0 rounded bg-accent-soft px-1 text-[11px] text-accent-strong" title="You own this incident">yours</span>}
                        {!inc.promoted && <span className="shrink-0 rounded bg-surface-3 px-1 text-[11px] text-faint">low signal</span>}
                      </div>
                      <div className="mt-0.5 flex items-center gap-2 text-[12px] text-faint">
                        <CategoryLabel category={inc.category} />
                        {inc.mitre_techniques.length > 0 && <span>· {inc.mitre_techniques.length} ATT&CK techniques</span>}
                      </div>
                    </td>
                    <td><SeverityBadge severity={inc.severity} size="sm" /></td>
                    <td><StatusBadge status={inc.status} /></td>
                    <td><SourcePills sources={inc.source_types} /></td>
                    <td className="tnum text-right text-muted">{inc.alert_count} · {num(inc.event_count)}</td>
                    <td className="text-muted" title={new Date(inc.last_event_at).toLocaleString()}>{relTime(inc.last_event_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {query.data && <Pager total={query.data.total} offset={offset} limit={PAGE} onChange={(o) => set('offset', String(o))} />}
      </Card>
      <p className="mt-3 text-[12px] text-faint">
        Tip: use <b>j</b> / <b>k</b> to move through the list and <b>Enter</b> to open. Evidence column: detections · events.
      </p>
    </div>
  )
}
