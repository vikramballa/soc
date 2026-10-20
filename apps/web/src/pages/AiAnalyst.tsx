import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import { Bot, CheckCircle2, Cpu, ShieldCheck, XCircle } from 'lucide-react'
import { Link } from 'react-router-dom'
import { RiskScore, SeverityBadge } from '../components/security'
import { toast, toastError } from '../components/toast'
import { Badge, Card, CardHeader, EmptyState, PageHeader, Select, Skeleton } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { bytes, num, pct } from '../lib/format'
import type { IncidentSummary, Page } from '../lib/types'

interface Status {
  enabled: boolean
  available: boolean
  reason: string | null
  model: string
  ollama_url: string
  local_models: { name: string; size: number; parameter_size: string | null; family: string | null }[]
  quality: { investigations: Record<string, number>; invalid_output_rate: number | null; feedback: Record<string, number> }
}

const GUARDS = [
  'Only sees the incident\'s evidence — never the whole database, and secrets are redacted first',
  'Telemetry is wrapped as untrusted data; instructions hidden in logs are ignored and flagged',
  'Every claim must cite an event; invented events, indicators or ATT&CK IDs fail validation',
  'Cannot take actions, change risk scores or close incidents',
  'Runs on local Ollama models only — cloud models are refused',
]

export default function AiAnalyst() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const st = useQuery({ queryKey: ['ai-status-full'], queryFn: () => api.get<Status>('/ai/status'), refetchInterval: 30_000 })
  const incs = useQuery({ queryKey: ['incidents', 'ai-candidates'], queryFn: () => api.get<Page<IncidentSummary>>('/incidents', { status: 'open', limit: 8 }) })
  const setModel = useMutation({
    mutationFn: (model: string) => api.put('/ai/model', { model }),
    onSuccess: () => { toast('Model updated'); qc.invalidateQueries({ queryKey: ['ai-status-full'] }); qc.invalidateQueries({ queryKey: ['ai-status'] }) },
    onError: toastError,
  })
  const s = st.data
  const inv = s?.quality.investigations ?? {}
  return (
    <div>
      <PageHeader
        title="AI Analyst"
        description="A private assistant that explains incidents in plain language using only the evidence SentinelX collected. Detection, correlation and risk scoring never depend on it."
      />
      <div className="grid gap-5 lg:grid-cols-3">
        <Card className="p-4 lg:col-span-2">
          {!s ? <Skeleton className="h-32" /> : (
            <div className="flex flex-wrap items-start gap-4">
              <div className={clsx('flex size-11 items-center justify-center rounded-xl', s.available ? 'bg-ai-soft text-ai' : 'bg-surface-3 text-faint')}><Bot className="size-6" /></div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 text-[15px] font-semibold">
                  {s.available ? <><CheckCircle2 className="size-4 text-ok" /> Ready</> : <><XCircle className="size-4 text-warn" /> Unavailable</>}
                </div>
                <p className="mt-0.5 text-[13px] text-muted">
                  {s.available ? <>Using <span className="font-mono text-[12.5px] text-fg">{s.model}</span> through Ollama at {s.ollama_url}.</> : <>{s.reason}. Start Ollama (<span className="font-mono">ollama serve</span>) and pull the model — everything else keeps working meanwhile.</>}
                </p>
                {can('admin:manage') && s.local_models.length > 0 && (
                  <div className="mt-3 flex items-center gap-2">
                    <span className="text-[12.5px] text-muted">Model</span>
                    <Select className="max-w-xs" value={s.model} onChange={(e) => setModel.mutate(e.target.value)}>
                      {s.local_models.map((m) => <option key={m.name} value={m.name}>{m.name}{m.parameter_size ? ` · ${m.parameter_size}` : ''}{m.size ? ` · ${bytes(m.size)}` : ''}</option>)}
                    </Select>
                  </div>
                )}
                <p className="mt-2 text-[12px] text-faint">Smaller models (3–4B) answer in ~1 minute on a laptop; larger ones are slower but more articulate. Every answer is validated either way.</p>
              </div>
            </div>
          )}
        </Card>
        <Card className="p-4">
          <div className="mb-3 text-[13.5px] font-semibold">Output quality</div>
          <div className="grid grid-cols-2 gap-3 text-[12.5px]">
            <div><div className="text-faint">Completed</div><div className="tnum text-[18px] font-semibold">{num(inv.completed ?? 0)}</div></div>
            <div><div className="text-faint">Rejected by validator</div><div className="tnum text-[18px] font-semibold">{num(inv.rejected ?? 0)}</div></div>
            <div><div className="text-faint">Invalid-output rate</div><div className="tnum text-[18px] font-semibold">{pct(s?.quality.invalid_output_rate)}</div></div>
            <div><div className="text-faint">Rated helpful</div><div className="tnum text-[18px] font-semibold">{num(s?.quality.feedback.helpful ?? 0)}<span className="text-[12px] font-normal text-faint"> / {num((s?.quality.feedback.helpful ?? 0) + (s?.quality.feedback.not_helpful ?? 0))}</span></div></div>
          </div>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader title="Investigate an open incident" subtitle="Open an incident and use the AI analyst tab" />
          {!incs.data ? <Skeleton className="m-4 h-32" /> : !incs.data.items.length ? <EmptyState title="No open incidents" /> : (
            <ul className="divide-y divide-line border-t border-line">
              {incs.data.items.map((i) => (
                <li key={i.id}>
                  <Link to={`/incidents/${i.id}?tab=ai`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-surface-2">
                    <RiskScore score={i.risk_score} size="sm" />
                    <span className="font-mono text-[11.5px] text-faint">INC-{i.number}</span>
                    <span className="min-w-0 flex-1 truncate text-[13px] font-medium">{i.title}</span>
                    <SeverityBadge severity={i.severity} size="sm" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card className="p-4">
          <div className="mb-3 flex items-center gap-2 text-[13.5px] font-semibold"><ShieldCheck className="size-4 text-ok" /> Safety guarantees</div>
          <ul className="space-y-2 text-[12.5px] text-muted">
            {GUARDS.map((g) => <li key={g} className="flex gap-2"><Cpu className="mt-0.5 size-3.5 shrink-0 text-faint" />{g}</li>)}
          </ul>
          <Badge tone="ai" className="mt-3">AI output is always labelled</Badge>
        </Card>
      </div>
    </div>
  )
}
