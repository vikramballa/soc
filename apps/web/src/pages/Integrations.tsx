import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { CheckCircle2, CircleDashed, Copy, Database, Plug } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { toast } from '../components/toast'
import { Badge, Card, CardHeader, ErrorState, PageHeader, Skeleton } from '../components/ui'
import { useAuth } from '../lib/auth'
import { api } from '../lib/api'
import { num, relTime } from '../lib/format'

interface Data {
  telemetry: { name: string; configured: boolean; how: string; events_total: number; failures: number; last_ingest_at: string | null; last_error: string | null }[]
  services: { name: string; status?: string; running?: boolean; detail?: string; workers?: number; queued_jobs?: number }[]
  quarantined_events: number
}

const SOURCE_INFO: Record<string, { title: string; blurb: string }> = {
  wazuh: { title: 'Wazuh', blurb: 'Endpoint telemetry: logins, processes (Sysmon), file integrity, account changes.' },
  suricata: { title: 'Suricata', blurb: 'Network IDS alerts plus DNS, HTTP, TLS, flow and file records (EVE JSON).' },
  zeek: { title: 'Zeek', blurb: 'Rich network logs: conn, dns, http, ssl, ssh, files and notices.' },
  sentinelx: { title: 'Custom / other', blurb: 'Any tool that can send JSON in the SentinelX canonical event format.' },
}

function Snippet({ code }: { code: string }) {
  return (
    <div className="relative">
      <button onClick={() => { navigator.clipboard?.writeText(code); toast('Copied') }} className="press absolute top-2 right-2 rounded-md border border-line bg-surface p-1 text-faint hover:text-fg" aria-label="Copy">
        <Copy className="size-3.5" />
      </button>
      <pre className="sx-code overflow-x-auto rounded-lg border border-line bg-bg-elev p-3 pr-10 whitespace-pre">{code}</pre>
    </div>
  )
}

function Guide({ source }: { source: string }) {
  const origin = window.location.origin
  const guides: Record<string, { label: string; code: string }[]> = {
    wazuh: [
      { label: 'Same machine (lab): tail alerts.json', code: 'WAZUH_ALERTS_PATH=/var/ossec/logs/alerts/alerts.json\nFILE_INGEST_TENANT=default' },
      { label: 'Poll the Wazuh indexer', code: 'WAZUH_INDEXER_URL=https://wazuh-indexer:9200\nWAZUH_INDEXER_USERNAME=sentinelx_reader\nWAZUH_INDEXER_PASSWORD=…' },
      { label: 'Push with any shipper', code: `curl -X POST ${origin}/api/v1/ingest/wazuh \\\n  -H "Authorization: Bearer sxi_YOUR_TOKEN" \\\n  --data-binary @alerts.json` },
    ],
    suricata: [
      { label: 'Same machine: tail eve.json', code: 'SURICATA_EVE_PATH=/var/log/suricata/eve.json' },
      { label: 'Fluent Bit output', code: `[OUTPUT]\n    Name   http\n    Match  suricata.*\n    Host   sentinelx.internal\n    Port   8000\n    URI    /api/v1/ingest/suricata\n    Format json_lines\n    Header Authorization Bearer sxi_YOUR_TOKEN` },
    ],
    zeek: [
      { label: 'Same machine: tail the log directory (JSON or TSV)', code: 'ZEEK_LOG_DIR=/opt/zeek/logs/current' },
      { label: 'Push one log type', code: `curl -X POST "${origin}/api/v1/ingest/zeek?log_type=conn" \\\n  -H "Authorization: Bearer sxi_YOUR_TOKEN" \\\n  --data-binary @conn.log` },
    ],
    sentinelx: [
      { label: 'Canonical events (NDJSON)', code: `curl -X POST ${origin}/api/v1/ingest/sentinelx \\\n  -H "Authorization: Bearer sxi_YOUR_TOKEN" \\\n  -d '{"timestamp":"2026-10-06T10:00:00Z","event_type":"authentication","event_action":"logon","outcome":"failure","hostname":"web-01","username":"alice","src_ip":"203.0.113.5"}'` },
    ],
  }
  return (
    <div className="space-y-3">
      {(guides[source] ?? []).map((g) => (
        <div key={g.label}>
          <div className="mb-1 text-[12.5px] font-medium text-muted">{g.label}</div>
          <Snippet code={g.code} />
        </div>
      ))}
      <p className="text-[12px] text-faint">
        File-tailing settings go in <span className="font-mono">.env</span> (restart afterwards). Ingest tokens are created under <Link to="/admin?tab=tokens" className="text-accent">Administration → Ingest tokens</Link>.
      </p>
    </div>
  )
}

export default function Integrations() {
  const { can } = useAuth()
  const [src, setSrc] = useState('wazuh')
  const q = useQuery({ queryKey: ['integrations'], queryFn: () => api.get<Data>('/admin/integrations'), refetchInterval: 20_000 })
  const quarantine = useQuery({ queryKey: ['quarantine'], enabled: can('admin:manage') && (q.data?.quarantined_events ?? 0) > 0, queryFn: () => api.get<{ id: string; source: string; error: string; payload: string; received_at: string }[]>('/admin/quarantine') })
  if (q.error) return <ErrorState error={q.error} />
  return (
    <div>
      <PageHeader title="Integrations" description="Connect telemetry sources and check the health of the services SentinelX uses." />
      {!q.data ? <Skeleton className="h-80" /> : (
        <div className="space-y-5">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {q.data.telemetry.map((t) => {
              const info = SOURCE_INFO[t.name]
              // measured against when the data was fetched, which keeps rendering pure
              const live = t.last_ingest_at && q.dataUpdatedAt - new Date(t.last_ingest_at).getTime() < 15 * 60_000
              return (
                <button key={t.name} onClick={() => setSrc(t.name)} className={clsx('press rounded-xl border bg-surface p-4 text-left shadow-[var(--shadow)]', src === t.name ? 'border-accent/50 ring-2 ring-accent/15' : 'border-line hover:border-line-strong')}>
                  <div className="flex items-center justify-between">
                    <span className="text-[14px] font-semibold">{info.title}</span>
                    {t.events_total ? <Badge tone={live ? 'ok' : 'neutral'}>{live ? 'receiving' : 'idle'}</Badge> : <Badge tone="outline">not connected</Badge>}
                  </div>
                  <p className="mt-1 text-[12.5px] text-muted">{info.blurb}</p>
                  <div className="mt-3 text-[12px] text-faint">
                    {t.events_total ? <>{num(t.events_total)} events · last {relTime(t.last_ingest_at)}{t.failures ? ` · ${t.failures} rejected` : ''}</> : 'No data received yet'}
                  </div>
                </button>
              )
            })}
          </div>
          <div className="grid gap-5 xl:grid-cols-[1.4fr_1fr]">
            <Card>
              <CardHeader title={`Connect ${SOURCE_INFO[src].title}`} icon={<Plug className="size-4" />} subtitle="Pick whichever option fits your setup" />
              <div className="px-4 pb-4"><Guide source={src} /></div>
            </Card>
            <Card>
              <CardHeader title="Services" icon={<Database className="size-4" />} />
              <ul className="divide-y divide-line border-t border-line">
                {q.data.services.map((s) => {
                  const ok = s.running ?? ['connected', 'available', 'configured'].includes(s.status ?? '')
                  return (
                    <li key={s.name} className="flex items-start gap-3 px-4 py-3">
                      {ok ? <CheckCircle2 className="mt-0.5 size-4 text-ok" /> : <CircleDashed className="mt-0.5 size-4 text-faint" />}
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2 text-[13px]"><span className="font-medium">{s.name}</span><span className="text-[12px] text-muted">{s.status ?? (s.running ? `running (${s.workers})` : 'not running')}</span></div>
                        <div className="truncate text-[12px] text-faint">{s.detail ?? (s.queued_jobs != null ? `${s.queued_jobs} queued jobs` : '')}</div>
                      </div>
                    </li>
                  )
                })}
              </ul>
            </Card>
          </div>
          {q.data.quarantined_events > 0 && can('admin:manage') && (
            <Card>
              <CardHeader title={`Quarantined events (${num(q.data.quarantined_events)})`} subtitle="Records that could not be parsed or validated. They are kept for 14 days for troubleshooting." />
              <ul className="divide-y divide-line border-t border-line">
                {(quarantine.data ?? []).slice(0, 20).map((x) => (
                  <li key={x.id} className="px-4 py-2.5 text-[12.5px]">
                    <div className="flex justify-between"><span><Badge>{x.source}</Badge> <span className="text-danger">{x.error}</span></span><span className="text-faint">{relTime(x.received_at)}</span></div>
                    <div className="mt-1 truncate font-mono text-[11.5px] text-faint">{x.payload}</div>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}
