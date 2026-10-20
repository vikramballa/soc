import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import { BrainCircuit, RefreshCw } from 'lucide-react'
import { useMemo, useState } from 'react'
import { HBar } from '../components/charts'
import { toast, toastError } from '../components/toast'
import { Badge, Button, Card, CardHeader, EmptyState, ErrorState, KeyValue, PageHeader, Segmented, Skeleton } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { dateTime, num, relTime } from '../lib/format'

interface Pred {
  host: string
  window_start: string
  anomaly_score: number
  is_anomaly: boolean
  top_contributors: { feature: string; value: number; baseline_median: number; z_score: number }[]
}
interface Data {
  model: null | {
    version: number
    trained_at: string
    metrics: { training_windows: number; excluded_windows: number; hosts: number; train_start: string; train_end: string }
    params: Record<string, any>
    features: { key: string; label: string }[]
  }
  history: { version: number; trained_at: string; status: string }[]
  predictions: Pred[]
}

export default function MlAnalytics() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [hours, setHours] = useState('72')
  const [onlyAnom, setOnlyAnom] = useState<'all' | 'anomalies'>('anomalies')
  const q = useQuery({ queryKey: ['ml', hours], queryFn: () => api.get<Data>('/analytics/anomalies', { hours }) })
  const train = useMutation({
    mutationFn: () => api.post('/analytics/ml/train'),
    onSuccess: () => {
      toast('Retraining queued — results appear in a few seconds', 'info')
      setTimeout(() => qc.invalidateQueries({ queryKey: ['ml'] }), 5000)
    },
    onError: toastError,
  })
  const labels = useMemo(() => Object.fromEntries((q.data?.model?.features ?? []).map((f) => [f.key, f.label])), [q.data])
  const hosts = useMemo(() => {
    const m = new Map<string, Pred[]>()
    for (const p of q.data?.predictions ?? []) m.set(p.host, [...(m.get(p.host) ?? []), p])
    return [...m.entries()].map(([host, ps]) => ({ host, ps: ps.sort((a, b) => a.window_start.localeCompare(b.window_start)), max: Math.max(...ps.map((p) => p.anomaly_score)), anomalies: ps.filter((p) => p.is_anomaly).length }))
      .sort((a, b) => b.anomalies - a.anomalies || b.max - a.max)
  }, [q.data])
  const rows = (q.data?.predictions ?? []).filter((p) => onlyAnom === 'all' || p.is_anomaly)

  return (
    <div>
      <PageHeader
        title="ML Analytics"
        description="An Isolation Forest learns what normal hourly activity looks like for your hosts. Unusual hours raise incident risk and are explained feature by feature. ML never creates a serious incident on its own."
        actions={<>
          <Segmented value={hours} onChange={setHours} items={[{ value: '24', label: '24h' }, { value: '72', label: '3d' }, { value: '168', label: '7d' }]} />
          {can('rule:manage') && <Button icon={<RefreshCw className="size-4" />} loading={train.isPending} onClick={() => train.mutate()}>Retrain now</Button>}
        </>}
      />
      {q.error && <ErrorState error={q.error} />}
      {!q.data ? <Skeleton className="h-80" /> : !q.data.model ? (
        <Card><EmptyState icon={<BrainCircuit className="size-5" />} title="No baseline yet">
          The model needs at least 24 host-hours of normal activity. It trains automatically once a day; you can also retrain manually.
        </EmptyState></Card>
      ) : (
        <div className="grid gap-5 xl:grid-cols-[320px_1fr]">
          <div className="space-y-5">
            <Card className="p-4">
              <div className="mb-3 flex items-center justify-between"><span className="text-[13.5px] font-semibold">Active model</span><Badge tone="ok">v{q.data.model.version}</Badge></div>
              <KeyValue items={[
                ['Algorithm', 'Isolation Forest (200 trees)'],
                ['Trained', relTime(q.data.model.trained_at)],
                ['Baseline', `${num(q.data.model.metrics.training_windows)} host-hours`],
                ['Hosts', q.data.model.metrics.hosts],
                ['Excluded', <span key="e" title="Hours touched by incidents are left out so attacks cannot become 'normal'">{q.data.model.metrics.excluded_windows} incident hours</span>],
                ['Flag rule', `score ≥ ${(q.data.model.params.threshold ?? 0.8).toFixed(2)} (isolation rarity + deviation) and a feature ≥ ${q.data.model.params.min_top_z ?? 4} robust σ above normal`],
              ]} />
            </Card>
            <Card>
              <CardHeader title="Hosts" subtitle="Highest anomaly score in the window" />
              <ul className="space-y-3 px-4 pb-4">
                {hosts.map((h) => (
                  <li key={h.host}>
                    <div className="mb-1 flex justify-between text-[12.5px]"><span className="font-medium">{h.host}</span><span className="tnum text-muted">{h.anomalies ? <b className="text-high">{h.anomalies} flagged</b> : 'normal'}</span></div>
                    <HBar value={h.max} max={1} tone={h.anomalies ? 'high' : 'accent'} />
                  </li>
                ))}
              </ul>
            </Card>
          </div>
          <Card className="overflow-hidden">
            <CardHeader title="Scored host-hours" subtitle="Why each hour was unusual — compared with that population's normal" action={<Segmented value={onlyAnom} onChange={setOnlyAnom} items={[{ value: 'anomalies', label: 'Flagged' }, { value: 'all', label: 'All' }]} />} />
            {!rows.length ? <EmptyState title="No flagged hours in this window">Behaviour is within the learned baseline.</EmptyState> : (
              <ul className="divide-y divide-line border-t border-line">
                {rows.slice(0, 150).map((p) => (
                  <li key={p.host + p.window_start} className="grid gap-3 px-4 py-3 md:grid-cols-[200px_1fr]">
                    <div>
                      <div className="flex items-center gap-2"><span className="font-medium">{p.host}</span>{p.is_anomaly && <Badge tone="warn">anomaly</Badge>}</div>
                      <div className="text-[12px] text-faint">{dateTime(p.window_start)}</div>
                      <div className="tnum mt-1 text-[12px] text-muted">score {(p.anomaly_score * 100).toFixed(1)}</div>
                    </div>
                    <div className="space-y-1.5">
                      {p.top_contributors.length ? p.top_contributors.map((c) => (
                        <div key={c.feature} className="grid grid-cols-[150px_1fr_110px] items-center gap-3 text-[12.5px]">
                          <span className="text-muted">{labels[c.feature] ?? c.feature}</span>
                          <HBar value={Math.min(c.z_score, 12)} max={12} tone={c.z_score >= 4 ? 'high' : 'accent'} />
                          <span className={clsx('tnum text-right', c.z_score >= 4 ? 'text-fg' : 'text-muted')}>{num(Math.round(c.value))} <span className="text-faint">vs ~{num(Math.round(c.baseline_median))}</span></span>
                        </div>
                      )) : <span className="text-[12.5px] text-faint">No feature above its usual range.</span>}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>
      )}
    </div>
  )
}
