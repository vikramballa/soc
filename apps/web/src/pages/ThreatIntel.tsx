import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import { Globe2, Plus, Search, ShieldAlert, ShieldCheck, ShieldQuestion, Trash2, Upload } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Modal } from '../components/overlay'
import { toast, toastError } from '../components/toast'
import { Badge, Button, Card, CardHeader, EmptyState, ErrorState, Input, Label, Mono, PageHeader, Select, SkeletonRows, Tabs, Textarea } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { dateTime, num, relTime } from '../lib/format'
import type { Page } from '../lib/types'

interface Indicator {
  id: string
  type: string
  value: string
  source: string
  confidence: number
  verdict: string
  tags: string[]
  description: string | null
  expires_at: string | null
  created_at: string
}

interface Lookup {
  indicator: string
  type: string
  overall: string
  results: { provider: string; verdict: string; confidence: number; tags: string[]; references: string[]; looked_up_at: string; details: Record<string, any> }[]
  sightings: { events_30d: number; first_seen: string | null; last_seen: string | null; hosts: string[] }
  providers: string[]
}

const VERDICT_UI: Record<string, { icon: React.ReactNode; label: string; cls: string }> = {
  malicious: { icon: <ShieldAlert className="size-5" />, label: 'Known malicious', cls: 'text-critical bg-critical/10 border-critical/25' },
  suspicious: { icon: <ShieldQuestion className="size-5" />, label: 'Suspicious', cls: 'text-medium bg-medium/10 border-medium/25' },
  no_match: { icon: <ShieldCheck className="size-5" />, label: 'No threat-intel match', cls: 'text-muted bg-surface-2 border-line' },
  benign: { icon: <ShieldCheck className="size-5" />, label: 'Known benign', cls: 'text-ok bg-ok/10 border-ok/25' },
}

function LookupBox() {
  const [params, setParams] = useSearchParams()
  const [value, setValue] = useState(params.get('q') ?? '')
  const [target, setTarget] = useState(params.get('q') ?? '')
  const q = useQuery({ queryKey: ['ti-lookup', target], enabled: !!target, queryFn: () => api.get<Lookup>(`/threat-intel/lookup/${encodeURIComponent(target)}`), retry: false })
  useEffect(() => {
    const p = params.get('q')
    if (p && p !== target) { setValue(p); setTarget(p) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params])
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTarget(value.trim())
    setParams(value.trim() ? { q: value.trim() } : {}, { replace: true })
  }
  const r = q.data
  const v = r ? VERDICT_UI[r.overall] ?? VERDICT_UI.no_match : null
  return (
    <Card className="mb-5 p-5">
      <form onSubmit={submit} className="flex gap-2">
        <Input icon={<Search className="size-4" />} className="flex-1" value={value} onChange={(e) => setValue(e.target.value)} placeholder="Look up an IP address, domain, URL or file hash…" />
        <Button type="submit" variant="primary" loading={q.isFetching}>Look up</Button>
      </form>
      {q.error && <p className="mt-3 text-[13px] text-danger">{(q.error as Error).message}</p>}
      {r && v && (
        <div className="animate-in mt-4 grid gap-4 lg:grid-cols-[1fr_1fr]">
          <div className={clsx('flex items-start gap-3 rounded-xl border p-4', v.cls)}>
            {v.icon}
            <div className="min-w-0">
              <div className="text-[15px] font-semibold">{v.label}</div>
              <Mono className="break-all text-fg">{r.indicator}</Mono> <Badge className="ml-1">{r.type}</Badge>
              <div className="mt-2 space-y-1.5">
                {r.results.filter((x) => x.verdict !== 'unknown').map((x) => (
                  <div key={x.provider} className="text-[12.5px] text-muted">
                    <b className="text-fg">{x.provider}</b>: {x.verdict}, confidence {Math.round(x.confidence * 100)}%{x.tags.length ? ` · ${x.tags.join(', ')}` : ''}
                    {x.details?.description && <div className="text-faint">{x.details.description}</div>}
                  </div>
                ))}
                <div className="text-[11.5px] text-faint">Checked: {r.providers.join(', ')}. Reputation alone is not proof of compromise.</div>
              </div>
            </div>
          </div>
          <div className="rounded-xl border border-line bg-bg-elev p-4">
            <div className="text-[12.5px] text-muted">Seen in your telemetry (30 days)</div>
            <div className="tnum mt-0.5 text-[22px] font-semibold">{num(r.sightings.events_30d)} <span className="text-[13px] font-normal text-muted">events</span></div>
            {r.sightings.events_30d > 0 && (
              <div className="mt-1 text-[12.5px] text-muted">
                {dateTime(r.sightings.first_seen)} → {dateTime(r.sightings.last_seen)}
                {r.sightings.hosts.length > 0 && <> · hosts: {r.sightings.hosts.slice(0, 5).join(', ')}</>}
                <div className="mt-2"><Link to={`/events?${r.type === 'ip' ? 'ip' : 'q'}=${encodeURIComponent(r.indicator)}&hours=720`} className="text-accent hover:text-accent-strong">View events →</Link></div>
              </div>
            )}
          </div>
        </div>
      )}
    </Card>
  )
}

function AddIndicator({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const [f, setF] = useState({ value: '', verdict: 'malicious', confidence: '0.8', description: '', expires_days: '' })
  const add = useMutation({
    mutationFn: () => api.post('/threat-intel/indicators', { value: f.value.trim(), verdict: f.verdict, confidence: Number(f.confidence), description: f.description || null, expires_days: f.expires_days ? Number(f.expires_days) : null }),
    onSuccess: () => { toast('Added to watchlist — new telemetry is matched immediately'); qc.invalidateQueries({ queryKey: ['indicators'] }); onClose() },
    onError: toastError,
  })
  return (
    <Modal open={open} onClose={onClose} title="Add to watchlist" description="Any future event containing this indicator raises an alert."
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!f.value.trim()} loading={add.isPending} onClick={() => add.mutate()}>Add indicator</Button></>}>
      <div className="space-y-3">
        <label className="block"><Label>IP, domain, URL or hash</Label><Input autoFocus value={f.value} onChange={(e) => setF({ ...f, value: e.target.value })} /></label>
        <div className="grid grid-cols-3 gap-3">
          <label className="block"><Label>Verdict</Label><Select value={f.verdict} onChange={(e) => setF({ ...f, verdict: e.target.value })}><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="benign">Benign</option></Select></label>
          <label className="block"><Label>Confidence</Label><Select value={f.confidence} onChange={(e) => setF({ ...f, confidence: e.target.value })}><option value="0.95">Very high</option><option value="0.8">High</option><option value="0.6">Medium</option><option value="0.4">Low</option></Select></label>
          <label className="block"><Label>Expires</Label><Select value={f.expires_days} onChange={(e) => setF({ ...f, expires_days: e.target.value })}><option value="">Never</option><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option></Select></label>
        </div>
        <label className="block"><Label>Note</Label><Input value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} placeholder="Why is this on the watchlist?" /></label>
      </div>
    </Modal>
  )
}

function ImportFeed() {
  const qc = useQueryClient()
  const [content, setContent] = useState('')
  const [format, setFormat] = useState('txt')
  const [source, setSource] = useState('')
  const imp = useMutation({
    mutationFn: () => api.post<{ imported: number }>('/threat-intel/feeds/import', { content, format, source: source || 'imported-feed' }),
    onSuccess: (r) => { toast(`Imported ${num(r.imported)} indicators`); setContent(''); qc.invalidateQueries({ queryKey: ['indicators'] }); qc.invalidateQueries({ queryKey: ['ti-sources'] }) },
    onError: toastError,
  })
  const onFile = async (file: File) => {
    const text = await file.text()
    setContent(text)
    setFormat(file.name.endsWith('.csv') ? 'csv' : file.name.endsWith('.json') ? 'json' : 'txt')
    if (!source) setSource(file.name.replace(/\.[^.]+$/, ''))
  }
  return (
    <div className="space-y-3 p-4">
      <p className="text-[13px] text-muted">
        Import indicators from any feed you are licensed to use (for example abuse.ch exports, MISP CSV exports or STIX 2.1 bundles).
        Plain text = one indicator per line. CSV needs a <Mono>value</Mono> column (optional: type, confidence, verdict, tags, description).
      </p>
      <div className="grid gap-3 sm:grid-cols-3">
        <label className="block"><Label>Feed name</Label><Input value={source} onChange={(e) => setSource(e.target.value)} placeholder="e.g. urlhaus-2026-10" /></label>
        <label className="block"><Label>Format</Label><Select value={format} onChange={(e) => setFormat(e.target.value)}><option value="txt">Plain text (one per line)</option><option value="csv">CSV</option><option value="json">JSON / STIX 2.1 bundle</option></Select></label>
        <label className="block"><Label>Or choose a file</Label>
          <span className="flex h-8.5 cursor-pointer items-center gap-2 rounded-lg border border-dashed border-line-strong px-3 text-[13px] text-muted hover:text-fg">
            <Upload className="size-4" /> Choose file…
            <input type="file" accept=".txt,.csv,.json" className="hidden" onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])} />
          </span>
        </label>
      </div>
      <Textarea className="min-h-40 font-mono text-[12px]" value={content} onChange={(e) => setContent(e.target.value)} placeholder={'198.51.100.23\nbad-domain.example\n# comments are ignored'} />
      <div className="flex justify-end"><Button variant="primary" disabled={!content.trim()} loading={imp.isPending} onClick={() => imp.mutate()}>Import indicators</Button></div>
    </div>
  )
}

export default function ThreatIntel() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [tab, setTab] = useState<'indicators' | 'import'>('indicators')
  const [source, setSource] = useState('')
  const [add, setAdd] = useState(false)
  const [filter, setFilter] = useState('')
  const sources = useQuery({ queryKey: ['ti-sources'], queryFn: () => api.get<{ source: string; indicators: number; updated: string }[]>('/threat-intel/sources') })
  const inds = useQuery({ queryKey: ['indicators', source, filter], queryFn: () => api.get<Page<Indicator>>('/threat-intel/indicators', { source, q: filter, limit: 200 }) })
  const del = useMutation({
    mutationFn: (id: string) => api.del(`/threat-intel/indicators/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['indicators'] }); toast('Indicator removed') },
    onError: toastError,
  })
  return (
    <div>
      <PageHeader
        title="Threat Intelligence"
        description="Indicators from your feeds, MISP (if configured) and your own watchlist. SentinelX checks every incoming event against them."
        actions={can('threatintel:manage') && <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setAdd(true)}>Add indicator</Button>}
      />
      <LookupBox />
      <div className="grid gap-5 xl:grid-cols-[260px_1fr]">
        <Card>
          <CardHeader title="Sources" icon={<Globe2 className="size-4" />} />
          <ul className="px-2 pb-3">
            <li><button onClick={() => setSource('')} className={clsx('flex w-full justify-between rounded-lg px-2 py-1.5 text-[13px]', !source ? 'bg-surface-2 font-medium' : 'text-muted hover:bg-surface-2')}>All sources</button></li>
            {(sources.data ?? []).map((s) => (
              <li key={s.source}>
                <button onClick={() => setSource(s.source)} className={clsx('flex w-full items-center justify-between gap-2 rounded-lg px-2 py-1.5 text-left text-[13px]', source === s.source ? 'bg-surface-2 font-medium' : 'text-muted hover:bg-surface-2')}>
                  <span className="truncate">{s.source}</span><span className="tnum text-[12px] text-faint">{num(s.indicators)}</span>
                </button>
              </li>
            ))}
          </ul>
        </Card>
        <Card className="overflow-hidden">
          <div className="px-4 pt-1">
            <Tabs value={tab} onChange={setTab} className="border-b-0" items={[{ value: 'indicators', label: 'Indicators', count: inds.data?.total }, ...(can('threatintel:manage') ? [{ value: 'import' as const, label: 'Import feed' }] : [])]} />
          </div>
          {tab === 'import' ? <div className="border-t border-line"><ImportFeed /></div> : (
            <>
              <div className="border-y border-line bg-bg-elev px-4 py-2.5"><Input icon={<Search className="size-4" />} className="max-w-xs" placeholder="Filter indicators" value={filter} onChange={(e) => setFilter(e.target.value)} /></div>
              {inds.error ? <ErrorState error={inds.error} /> : !inds.data ? <SkeletonRows /> : !inds.data.items.length ? (
                <EmptyState icon={<Globe2 className="size-5" />} title="No indicators yet">Import a feed or add indicators to your watchlist.</EmptyState>
              ) : (
                <div className="overflow-x-auto">
                  <table className="sx-table min-w-[720px] text-[12.5px]">
                    <thead><tr><th>Indicator</th><th className="w-20">Type</th><th className="w-28">Verdict</th><th className="w-24">Confidence</th><th className="w-36">Source</th><th className="w-28">Added</th><th className="w-10" /></tr></thead>
                    <tbody>
                      {inds.data.items.map((i) => (
                        <tr key={i.id}>
                          <td className="max-w-0"><Mono className="block truncate text-fg">{i.value}</Mono>{i.description && <div className="truncate text-[12px] text-faint">{i.description}</div>}</td>
                          <td className="text-muted">{i.type}</td>
                          <td><Badge tone={i.verdict === 'malicious' ? 'danger' : i.verdict === 'suspicious' ? 'warn' : 'ok'}>{i.verdict}</Badge></td>
                          <td className="tnum text-muted">{Math.round(i.confidence * 100)}%</td>
                          <td className="truncate text-muted">{i.source}</td>
                          <td className="text-muted">{relTime(i.created_at)}</td>
                          <td>{can('threatintel:manage') && <button onClick={() => del.mutate(i.id)} className="text-faint hover:text-danger" aria-label="Delete indicator"><Trash2 className="size-3.5" /></button>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </Card>
      </div>
      <AddIndicator open={add} onClose={() => setAdd(false)} />
    </div>
  )
}
