import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Activity, Search, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { BarChart } from '../components/charts'
import { EventDrawer } from '../components/EventDrawer'
import { SourcePills } from '../components/security'
import { Badge, Button, Card, EmptyState, ErrorState, Input, Mono, PageHeader, Segmented, Select, SkeletonRows } from '../components/ui'
import { api } from '../lib/api'
import { dateTime, num } from '../lib/format'
import type { SecurityEvent } from '../lib/types'
import { useDebounced } from './Incidents'

interface SearchResult {
  items: SecurityEvent[]
  total: number
  total_capped: boolean
  next_cursor: string | null
}

const FILTER_KEYS = ['host', 'user', 'ip', 'source', 'event_type', 'outcome'] as const

export default function Events() {
  const [params, setParams] = useSearchParams()
  const [text, setText] = useState(params.get('q') ?? '')
  const q = useDebounced(text, 350)
  const hours = params.get('hours') ?? '24'
  const [eventId, setEventId] = useState<string | null>(null)
  const filters = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ''])) as Record<(typeof FILTER_KEYS)[number], string>

  const set = (k: string, v: string | null) => {
    const p = new URLSearchParams(params)
    if (v) p.set(k, v)
    else p.delete(k)
    setParams(p, { replace: true })
  }
  useEffect(() => {
    if ((params.get('q') ?? '') !== q) set('q', q || null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q])

  const query = useInfiniteQuery({
    queryKey: ['events', q, hours, filters],
    queryFn: ({ pageParam }) => api.get<SearchResult>('/events', { q, hours, ...filters, cursor: pageParam ?? undefined, limit: 100 }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  })
  const histo = useQuery({
    queryKey: ['events-histo', hours, filters.host],
    queryFn: () => api.get<{ bucket: string; points: { t: string; source: string; count: number }[] }>('/events/histogram', { hours, host: filters.host || undefined }),
  })
  const buckets = (() => {
    const m = new Map<string, number>()
    for (const p of histo.data?.points ?? []) m.set(p.t, (m.get(p.t) ?? 0) + p.count)
    return [...m.entries()].map(([t, count]) => ({
      label: new Date(t).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: histo.data?.bucket === 'minute' ? '2-digit' : undefined }),
      value: count,
    }))
  })()
  const rows = query.data?.pages.flatMap((p) => p.items) ?? []
  const first = query.data?.pages[0]
  const active = FILTER_KEYS.filter((k) => filters[k])

  return (
    <div>
      <PageHeader
        title="Events"
        description="Search normalized telemetry from Wazuh, Suricata and Zeek. Every event keeps its original raw record."
        actions={<Segmented value={hours} onChange={(v) => set('hours', v)} items={[{ value: '1', label: '1h' }, { value: '24', label: '24h' }, { value: '168', label: '7d' }, { value: '720', label: '30d' }]} />}
      />
      <Card className="mb-4 p-4">
        <div className="mb-3 flex items-baseline justify-between">
          <span className="text-[12.5px] text-muted">Events over time</span>
          {first && <span className="tnum text-[12.5px] text-muted">{num(first.total)}{first.total_capped && '+'} matching events</span>}
        </div>
        <BarChart data={buckets} unit="events" height={96} />
      </Card>
      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-line bg-bg-elev px-4 py-2.5">
          <Input icon={<Search className="size-4" />} className="w-full max-w-md" placeholder="Search summaries, command lines, domains, URLs…" value={text} onChange={(e) => setText(e.target.value)} />
          <Select className="w-36" value={filters.source} onChange={(e) => set('source', e.target.value)}>
            <option value="">All sources</option>
            <option value="wazuh">Wazuh</option>
            <option value="suricata">Suricata</option>
            <option value="zeek">Zeek</option>
            <option value="sentinelx">SentinelX</option>
          </Select>
          <Select className="w-40" value={filters.event_type} onChange={(e) => set('event_type', e.target.value)}>
            <option value="">All event types</option>
            {['authentication', 'process', 'network', 'dns', 'http', 'tls', 'file', 'iam', 'ssh', 'alert', 'other'].map((t) => <option key={t} value={t}>{t}</option>)}
          </Select>
          {active.filter((k) => !['source', 'event_type'].includes(k)).map((k) => (
            <Badge key={k} tone="accent" className="h-7 gap-1.5 px-2">
              {k}: {filters[k]}
              <button onClick={() => set(k, null)} aria-label={`Remove ${k} filter`}><X className="size-3" /></button>
            </Badge>
          ))}
        </div>
        {query.error ? <ErrorState error={query.error} /> : !query.data ? <SkeletonRows rows={10} /> : !rows.length ? (
          <EmptyState icon={<Activity className="size-5" />} title="No events in this range">Widen the time range or remove a filter.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="sx-table min-w-[980px] text-[12.5px]">
              <thead>
                <tr>
                  <th className="w-40">Time</th>
                  <th className="w-28">Source</th>
                  <th className="w-28">Type</th>
                  <th>Summary</th>
                  <th className="w-36">Host</th>
                  <th className="w-36">Source IP</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id} data-clickable="true" onClick={() => setEventId(e.id)}>
                    <td className="tnum text-muted">{dateTime(e.timestamp, { seconds: true })}</td>
                    <td><SourcePills sources={[e.source_type]} /></td>
                    <td className={clsx('text-muted', e.outcome === 'failure' && 'text-warn')}>{e.event_type}{e.outcome === 'failure' && ' ✕'}</td>
                    <td className="max-w-0 truncate">{e.summary}</td>
                    <td>{e.hostname ? <button className="hover:text-accent" onClick={(ev) => { ev.stopPropagation(); set('host', e.hostname) }}>{e.hostname}</button> : <span className="text-faint">—</span>}</td>
                    <td>{e.src_ip ? <button className="hover:text-accent" onClick={(ev) => { ev.stopPropagation(); set('ip', e.src_ip) }}><Mono>{e.src_ip}</Mono></button> : <span className="text-faint">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {query.hasNextPage && (
          <div className="flex justify-center border-t border-line p-3">
            <Button loading={query.isFetchingNextPage} onClick={() => query.fetchNextPage()}>Load more</Button>
          </div>
        )}
      </Card>
      <p className="mt-3 text-[12px] text-faint">Click a host or IP to filter by it. Search is bounded to the selected time range for speed.</p>
      <EventDrawer eventId={eventId} onClose={() => setEventId(null)} />
    </div>
  )
}
