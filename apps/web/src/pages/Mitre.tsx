import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { ExternalLink } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Drawer } from '../components/overlay'
import { SeverityBadge, StatusBadge } from '../components/security'
import { Badge, Card, ErrorState, PageHeader, SectionTitle, Segmented, Skeleton } from '../components/ui'
import { api } from '../lib/api'
import { num, relTime } from '../lib/format'
import type { Severity } from '../lib/types'

interface Tech {
  id: string
  name: string
  observed: boolean
  incidents: number
  evidence: number
  last_observed: string | null
  covered: boolean
  observed_subtechniques: string[]
}
interface Matrix {
  attack_version: string
  observed_total: number
  covered_total: number
  tactics: { id: string; shortname: string; name: string; techniques: Tech[] }[]
}
interface TechDetail {
  technique: { id: string; name: string; tactics: string[]; description: string; detection: string; url: string; platforms: string[] }
  incidents: { id: string; number: number; title: string; severity: Severity; status: string; last_event_at: string }[]
  rules: { rule_uid: string; title: string; enabled: boolean }[]
}

export default function Mitre() {
  const [show, setShow] = useState<'relevant' | 'all'>('relevant')
  const [days, setDays] = useState('30')
  const [sel, setSel] = useState<string | null>(null)
  const q = useQuery({ queryKey: ['mitre', days], queryFn: () => api.get<Matrix>('/mitre/matrix', { days }) })
  const detail = useQuery({ queryKey: ['mitre-tech', sel], enabled: !!sel, queryFn: () => api.get<TechDetail>(`/mitre/techniques/${sel}`) })

  return (
    <div>
      <PageHeader
        title="MITRE ATT&CK"
        description="Techniques observed in your incidents, and which ones your detection rules cover. Techniques only appear as observed when a rule or sensor provided evidence — never because an AI guessed."
        actions={
          <>
            <Segmented value={days} onChange={setDays} items={[{ value: '7', label: '7d' }, { value: '30', label: '30d' }, { value: '90', label: '90d' }]} />
            <Segmented value={show} onChange={setShow} items={[{ value: 'relevant', label: 'Observed & covered' }, { value: 'all', label: 'Full matrix' }]} />
          </>
        }
      />
      {q.error && <ErrorState error={q.error} />}
      {!q.data ? <Skeleton className="h-96" /> : (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-4 text-[12.5px] text-muted">
            <span className="flex items-center gap-1.5"><span className="size-3 rounded bg-high/80" /> Observed in incidents ({q.data.observed_total})</span>
            <span className="flex items-center gap-1.5"><span className="size-3 rounded border border-accent/60 bg-accent-soft" /> Covered by an enabled rule ({q.data.covered_total})</span>
            <span className="flex items-center gap-1.5"><span className="size-3 rounded border border-line bg-surface-2" /> Not covered</span>
            <span className="ml-auto text-faint">ATT&CK v{q.data.attack_version}</span>
          </div>
          <Card className="overflow-x-auto p-3">
            <div className="flex min-w-max gap-2">
              {q.data.tactics.map((tac) => {
                const techs = show === 'all' ? tac.techniques : tac.techniques.filter((t) => t.observed || t.covered)
                const obs = tac.techniques.filter((t) => t.observed).length
                return (
                  <div key={tac.id} className="w-[168px] shrink-0">
                    <div className="mb-2 rounded-lg bg-surface-2 px-2 py-1.5">
                      <div className="text-[12px] leading-tight font-semibold">{tac.name}</div>
                      <div className="text-[11px] text-faint">{obs ? `${obs} observed · ` : ''}{tac.techniques.length} techniques</div>
                    </div>
                    <div className="space-y-1">
                      {techs.map((t) => (
                        <button
                          key={t.id}
                          onClick={() => setSel(t.id)}
                          title={`${t.id} ${t.name}`}
                          className={clsx(
                            'press block w-full rounded-md border px-2 py-1.5 text-left text-[11.5px] leading-snug',
                            t.observed ? 'border-high/50 bg-high/15 text-fg hover:bg-high/25'
                              : t.covered ? 'border-accent/35 bg-accent-soft text-fg hover:border-accent/60'
                              : 'border-line bg-bg-elev text-faint hover:text-muted',
                          )}
                        >
                          <span className="block truncate">{t.name}</span>
                          <span className="flex items-center justify-between font-mono text-[10.5px] opacity-70">
                            {t.id}
                            {t.observed && <span className="tnum font-sans">{t.incidents} inc</span>}
                          </span>
                        </button>
                      ))}
                      {!techs.length && <div className="px-2 py-3 text-[11px] text-faint">Nothing observed or covered</div>}
                    </div>
                  </div>
                )
              })}
            </div>
          </Card>
        </>
      )}
      <Drawer open={!!sel} onClose={() => setSel(null)} title={detail.data ? `${detail.data.technique.id} ${detail.data.technique.name}` : sel ?? ''}
        subtitle={detail.data?.technique.tactics.join(', ')}>
        {!detail.data ? <Skeleton className="h-40" /> : (
          <div className="space-y-5 text-[13px]">
            <p className="text-muted">{detail.data.technique.description}</p>
            <a href={detail.data.technique.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent hover:text-accent-strong">
              Read on attack.mitre.org <ExternalLink className="size-3.5" />
            </a>
            <div>
              <SectionTitle>Incidents with this technique</SectionTitle>
              {detail.data.incidents.length ? (
                <ul className="space-y-1">
                  {detail.data.incidents.map((i) => (
                    <li key={i.id}>
                      <Link to={`/incidents/${i.id}`} className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-surface-2">
                        <SeverityBadge severity={i.severity} size="sm" />
                        <span className="min-w-0 flex-1 truncate">INC-{i.number} {i.title}</span>
                        <StatusBadge status={i.status} />
                        <span className="text-[12px] text-faint">{relTime(i.last_event_at)}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              ) : <p className="text-faint">None in this organization.</p>}
            </div>
            <div>
              <SectionTitle>Detection rules mapped to it</SectionTitle>
              {detail.data.rules.length ? (
                <ul className="space-y-1">
                  {detail.data.rules.map((r) => (
                    <li key={r.rule_uid} className="flex items-center justify-between gap-2">
                      <Link to={`/rules?rule=${r.rule_uid}`} className="hover:text-accent">{r.title}</Link>
                      <Badge tone={r.enabled ? 'ok' : 'neutral'}>{r.enabled ? 'enabled' : 'disabled'}</Badge>
                    </li>
                  ))}
                </ul>
              ) : <p className="text-faint">No SentinelX rule covers this technique yet — a gap to consider.</p>}
            </div>
            {detail.data.technique.detection && (
              <div><SectionTitle>MITRE detection guidance</SectionTitle><p className="text-muted">{detail.data.technique.detection}</p></div>
            )}
            <p className="text-[11.5px] text-faint">Platforms: {detail.data.technique.platforms.join(', ') || '—'} · {num(detail.data.incidents.length)} incidents</p>
          </div>
        )}
      </Drawer>
    </div>
  )
}
