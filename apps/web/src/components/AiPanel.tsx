import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import { AlertTriangle, Bot, CheckCircle2, Copy, Info, ShieldQuestion, Sparkles, ThumbsDown, ThumbsUp, XCircle } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { relTime } from '../lib/format'
import type { AiInvestigation } from '../lib/types'
import { TechniqueChip } from './security'
import { toast, toastError } from './toast'
import { Badge, Button, Card, EmptyState, SectionTitle } from './ui'

const VERDICT: Record<string, { label: string; tone: 'danger' | 'warn' | 'ok' | 'neutral'; hint: string }> = {
  likely_malicious: { label: 'Possible compromise', tone: 'danger', hint: 'The evidence is consistent with malicious activity' },
  suspicious: { label: 'Suspicious activity', tone: 'warn', hint: 'Unusual enough to investigate' },
  likely_benign: { label: 'Likely benign', tone: 'ok', hint: 'The evidence fits a legitimate explanation' },
  insufficient_evidence: { label: 'Insufficient evidence', tone: 'neutral', hint: 'Not enough evidence to judge' },
}

function Elapsed({ since }: { since: string }) {
  const [, tick] = useState(0)
  useEffect(() => {
    const t = setInterval(() => tick((x) => x + 1), 1000)
    return () => clearInterval(t)
  }, [])
  const s = Math.max(0, Math.round((Date.now() - new Date(since).getTime()) / 1000))
  return <span className="tnum">{Math.floor(s / 60)}:{String(s % 60).padStart(2, '0')}</span>
}

export function AiPanel({ incidentId, onOpenEvent }: { incidentId: string; onOpenEvent: (id: string) => void }) {
  const { can } = useAuth()
  const qc = useQueryClient()
  const status = useQuery({ queryKey: ['ai-status'], queryFn: () => api.get<{ available: boolean; model: string; reason?: string }>('/ai/status'), staleTime: 20_000 })
  const list = useQuery({
    queryKey: ['investigations', incidentId],
    queryFn: () => api.get<AiInvestigation[]>(`/incidents/${incidentId}/investigations`),
    refetchInterval: (q) => (q.state.data?.some((i) => i.status === 'queued' || i.status === 'running') ? 2500 : false),
  })
  const start = useMutation({
    mutationFn: () => api.post<AiInvestigation>(`/incidents/${incidentId}/investigate`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['investigations', incidentId] }),
    onError: toastError,
  })
  const feedback = useMutation({
    mutationFn: ({ id, fb }: { id: string; fb: string }) => api.post(`/ai/investigations/${id}/feedback`, { feedback: fb }),
    onSuccess: () => {
      toast('Thanks — feedback recorded')
      qc.invalidateQueries({ queryKey: ['investigations', incidentId] })
    },
  })

  const latest = list.data?.[0]
  const running = latest && (latest.status === 'queued' || latest.status === 'running')
  const lastGood = list.data?.find((i) => i.status === 'completed')
  const shown = latest?.status === 'completed' ? latest : lastGood

  const runButton = can('ai:investigate') && (
    <Button variant="ai" icon={<Sparkles className="size-4" />} loading={start.isPending} disabled={!!running || !status.data?.available} onClick={() => start.mutate()}>
      {shown ? 'Run again' : 'Investigate with AI'}
    </Button>
  )

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3 rounded-xl border border-ai/20 bg-ai-soft px-4 py-3">
        <div className="flex gap-3">
          <Bot className="mt-0.5 size-5 shrink-0 text-ai" />
          <div className="text-[13px]">
            <div className="font-medium text-fg">Local AI analyst</div>
            <div className="text-muted">
              Explains this incident using only the evidence SentinelX collected. Runs on your own machine
              {status.data?.model && <> with <span className="font-mono text-[12px]">{status.data.model}</span></>}. Every claim is checked against
              the evidence before it is shown — it cannot take actions or change the risk score.
            </div>
            {status.data && !status.data.available && (
              <div className="mt-1.5 flex items-center gap-1.5 text-warn"><AlertTriangle className="size-3.5" /> AI analyst unavailable: {status.data.reason}. Core detection is unaffected.</div>
            )}
          </div>
        </div>
        {runButton}
      </div>

      {running && latest && (
        <Card className="px-4 py-5">
          <div className="flex items-center gap-3">
            <div className="relative flex size-9 items-center justify-center">
              <span className="absolute inset-0 rounded-full border-2 border-ai/20" />
              <span className="spin absolute inset-0 rounded-full border-2 border-transparent border-t-ai" />
              <Sparkles className="size-4 text-ai" />
            </div>
            <div className="text-[13px]">
              <div className="font-medium">{latest.status === 'queued' ? 'Waiting for the AI worker…' : 'Reading the evidence and writing an analysis…'}</div>
              <div className="text-muted">
                Elapsed <Elapsed since={latest.created_at} /> · local models typically take 1–2 minutes. You can keep working; this updates automatically.
              </div>
            </div>
          </div>
        </Card>
      )}

      {latest?.status === 'rejected' && (
        <Card className="border-warn/30 px-4 py-4">
          <div className="flex gap-3">
            <ShieldQuestion className="mt-0.5 size-5 shrink-0 text-warn" />
            <div className="text-[13px]">
              <div className="font-medium">The AI's answer was rejected because it was not fully supported by evidence</div>
              <p className="mt-0.5 text-muted">SentinelX never shows unsupported claims. You can run it again, or rely on the deterministic analysis on the Overview tab.</p>
              <ul className="mt-2 list-disc space-y-0.5 pl-4 text-[12.5px] text-faint">
                {latest.validation_errors.slice(0, 5).map((e, i) => <li key={i}>{e}</li>)}
              </ul>
            </div>
          </div>
        </Card>
      )}
      {latest?.status === 'failed' && (
        <Card className="px-4 py-4">
          <div className="flex gap-3 text-[13px]">
            <XCircle className="mt-0.5 size-5 shrink-0 text-danger" />
            <div><div className="font-medium">The AI analyst could not run</div><p className="text-muted">{latest.error}</p></div>
          </div>
        </Card>
      )}

      {!latest && !list.isLoading && (
        <Card>
          <EmptyState icon={<Bot className="size-5" />} title="No AI investigation yet" action={runButton}>
            Ask the local AI analyst for a plain-language explanation, possible benign explanations and suggested next steps.
          </EmptyState>
        </Card>
      )}

      {shown?.result && <AiResult inv={shown} onOpenEvent={onOpenEvent} onFeedback={(fb) => feedback.mutate({ id: shown.id, fb })} />}
    </div>
  )
}

function AiResult({ inv, onOpenEvent, onFeedback }: { inv: AiInvestigation; onOpenEvent: (id: string) => void; onFeedback: (fb: string) => void }) {
  const r = inv.result!
  const v = VERDICT[r.verdict] ?? VERDICT.insufficient_evidence
  const supported = r.mitre_assessment.filter((m) => m.status === 'supported')
  const hypotheses = r.mitre_assessment.filter((m) => m.status === 'hypothesis')
  return (
    <Card className="animate-in overflow-hidden border-ai/25">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-ai-soft px-4 py-2.5">
        <div className="flex items-center gap-2 text-[12.5px]">
          <Badge tone="ai"><Sparkles className="size-3" /> AI-generated</Badge>
          <span className="text-muted">{inv.model} · {relTime(inv.completed_at)} · verified against {inv.context_stats.evidence_events ?? '?'} evidence events</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="mr-1 text-[12px] text-faint">Was this useful?</span>
          <button onClick={() => onFeedback('helpful')} className={clsx('press rounded-md p-1.5 hover:bg-surface-2', inv.feedback === 'helpful' ? 'text-ok' : 'text-faint')} aria-label="Helpful"><ThumbsUp className="size-3.5" /></button>
          <button onClick={() => onFeedback('not_helpful')} className={clsx('press rounded-md p-1.5 hover:bg-surface-2', inv.feedback === 'not_helpful' ? 'text-danger' : 'text-faint')} aria-label="Not helpful"><ThumbsDown className="size-3.5" /></button>
        </div>
      </div>
      <div className="space-y-6 px-4 py-4">
        <div>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <Badge tone={v.tone} title={v.hint}>{v.label}</Badge>
            <span className="text-[12px] text-faint">AI confidence {Math.round(r.confidence * 100)}% — an opinion, not a measurement</span>
          </div>
          <p className="text-[14px] leading-relaxed text-fg">{r.summary}</p>
          <p className="mt-2 text-[13px] text-muted"><b className="font-medium text-fg">Why it matters: </b>{r.severity_assessment}</p>
        </div>

        {inv.injection_flags.length > 0 && (
          <div className="flex gap-2 rounded-lg border border-warn/30 bg-warn/8 px-3 py-2 text-[12.5px] text-warn">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>
              {inv.injection_flags.length} telemetry field(s) contained text that looks like instructions to an AI (possible prompt injection).
              That text was withheld from the AI and the analysis is based on the remaining evidence.{' '}
              {(() => {
                const refs = [...new Set(inv.injection_flags.map((f) => f.ref).filter((r) => /^E\d+$/.test(r)))]
                return refs.length ? <>Affected events: {refs.join(', ')}.</> : null
              })()}
            </span>
          </div>
        )}

        <div>
          <SectionTitle>Evidence behind this analysis</SectionTitle>
          <ul className="space-y-1.5">
            {r.evidence.map((e, i) => (
              <li key={i} className="flex items-start gap-2.5 text-[13px]">
                <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-ok" />
                <span className="flex-1">{e.claim}</span>
                <span className="flex shrink-0 flex-wrap justify-end gap-1">
                  {(e.event_ids ?? [e.event_id]).slice(0, 4).map((id, j) => (
                    <button key={id} onClick={() => onOpenEvent(id)} className="press rounded-md border border-line px-1.5 py-0.5 font-mono text-[11px] text-accent hover:border-accent/50" title="Open the source event">
                      {(e.refs ?? [e.ref])[j] ?? 'event'}
                    </button>
                  ))}
                </span>
              </li>
            ))}
          </ul>
        </div>

        {r.mitre_assessment.length > 0 && (
          <div>
            <SectionTitle>ATT&CK assessment</SectionTitle>
            <div className="space-y-2">
              {[...supported, ...hypotheses].map((m) => (
                <div key={m.technique_id} className="flex flex-wrap items-start gap-2 text-[13px]">
                  <TechniqueChip id={m.technique_id} name={m.technique_name ?? undefined} />
                  <Badge tone={m.status === 'supported' ? 'ok' : 'warn'} title={m.status === 'supported' ? 'Backed by a detection rule' : 'Model hypothesis — not confirmed by a rule'}>
                    {m.status === 'supported' ? 'rule-supported' : 'hypothesis'}
                  </Badge>
                  <span className="min-w-[200px] flex-1 text-muted">{m.reason}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="grid gap-5 md:grid-cols-2">
          <div>
            <SectionTitle>Suggested next steps</SectionTitle>
            <ol className="space-y-2">
              {r.recommended_investigation_steps.map((s, i) => (
                <li key={i} className="flex gap-2.5 text-[13px]">
                  <span className="tnum flex size-5 shrink-0 items-center justify-center rounded-full bg-surface-3 text-[11px] text-muted">{i + 1}</span>
                  <span>{s}</span>
                </li>
              ))}
            </ol>
          </div>
          <div>
            <SectionTitle>Possible benign explanations</SectionTitle>
            <ul className="space-y-2">
              {r.possible_benign_explanations.map((s, i) => (
                <li key={i} className="flex gap-2.5 text-[13px] text-muted"><Info className="mt-0.5 size-4 shrink-0 text-faint" />{s}</li>
              ))}
              {!r.possible_benign_explanations.length && <li className="text-[13px] text-faint">None suggested.</li>}
            </ul>
          </div>
        </div>

        {r.indicators_to_search.length > 0 && (
          <div>
            <SectionTitle>Indicators to search elsewhere</SectionTitle>
            <div className="flex flex-wrap gap-1.5">
              {r.indicators_to_search.map((x) => (
                <button key={x} onClick={() => { navigator.clipboard?.writeText(x); toast(`Copied ${x}`) }}
                  className="press inline-flex items-center gap-1.5 rounded-md border border-line bg-surface-2 px-2 py-1 font-mono text-[12px] hover:border-line-strong">
                  {x} <Copy className="size-3 text-faint" />
                </button>
              ))}
            </div>
          </div>
        )}
        <p className="border-t border-line pt-3 text-[11.5px] text-faint">
          Prompt {inv.prompt_version} · context {inv.context_sha256?.slice(0, 12)} · {inv.attempts} attempt{inv.attempts > 1 ? 's' : ''} · {Math.round((inv.duration_ms ?? 0) / 1000)}s.
          AI output can be wrong — verify against the evidence before acting.
        </p>
      </div>
    </Card>
  )
}
