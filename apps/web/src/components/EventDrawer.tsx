import { useQuery } from '@tanstack/react-query'
import { Copy } from 'lucide-react'
import { useState } from 'react'
import { api } from '../lib/api'
import { bytes, dateTime } from '../lib/format'
import { Drawer } from './overlay'
import { SourcePills } from './security'
import { toast } from './toast'
import { Badge, Button, ErrorState, KeyValue, Mono, SectionTitle, Segmented, Spinner } from './ui'

function colorize(json: string) {
  // tiny, safe highlighter: works on escaped text only
  const esc = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  return esc.replace(
    /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)/gi,
    (m, str, colon, bool, n) => {
      if (str) return colon ? `<span class="k">${str}</span>${colon}` : `<span class="s">${str}</span>`
      if (bool) return `<span class="b">${m}</span>`
      if (n) return `<span class="n">${m}</span>`
      return m
    },
  )
}

function JsonView({ value, maxHeight = 420 }: { value: unknown; maxHeight?: number }) {
  const text = JSON.stringify(value, null, 2)
  return (
    <div className="relative">
      <button
        onClick={() => {
          navigator.clipboard?.writeText(text)
          toast('Copied to clipboard')
        }}
        className="press absolute top-2 right-2 rounded-md border border-line bg-surface px-1.5 py-1 text-faint hover:text-fg"
        aria-label="Copy JSON"
      >
        <Copy className="size-3.5" />
      </button>
      <pre
        className="sx-code overflow-auto rounded-lg border border-line bg-bg-elev p-3"
        style={{ maxHeight }}
        dangerouslySetInnerHTML={{ __html: colorize(text) }}
      />
    </div>
  )
}

type Snap = Record<string, any>

function fields(s: Snap): [string, React.ReactNode][] {
  const rows: [string, React.ReactNode][] = [
    ['Time', dateTime(s.timestamp, { seconds: true })],
    ['Source', <SourcePills key="s" sources={[s.source_type]} />],
    ['Type', [s.event_type, s.event_action].filter(Boolean).join(' · ')],
    ['Outcome', s.outcome],
    ['Host', s.hostname],
    ['User', s.username],
    ['Source IP', s.src_ip && <Mono key="sip">{s.src_ip}{s.src_port ? `:${s.src_port}` : ''}</Mono>],
    ['Destination', s.dest_ip && <Mono key="dip">{s.dest_ip}{s.dest_port ? `:${s.dest_port}` : ''}</Mono>],
    ['Protocol', s.protocol],
    ['Bytes out', s.bytes_out != null ? bytes(s.bytes_out) : null],
    ['Process', s.process_name],
    ['Parent process', s.parent_process_name],
    ['Command line', s.process_command_line && <Mono key="f1" className="break-all">{s.process_command_line}</Mono>],
    ['Domain', s.domain && <Mono key="dom">{s.domain}</Mono>],
    ['URL', s.url && <Mono key="f2" className="break-all">{s.url}</Mono>],
    ['File', s.file_path && <Mono key="f3" className="break-all">{s.file_path}</Mono>],
    ['File hash', s.file_hash && <Mono key="f4" className="break-all">{s.file_hash}</Mono>],
    ['Sensor rule', s.rule_name && <span key="rule">{s.rule_name}{s.rule_id && <span className="text-faint"> ({s.rule_id})</span>}</span>],
  ]
  return rows.filter(([, v]) => v !== null && v !== undefined && v !== '')
}

/** Shows one source event. Inside an incident it reads the preserved evidence snapshot, so evidence stays
 * viewable even after raw telemetry ages out of retention. */
export function EventDrawer({
  eventId,
  incidentId,
  onClose,
}: {
  eventId: string | null
  incidentId?: string
  onClose: () => void
}) {
  const [view, setView] = useState<'fields' | 'raw'>('fields')
  const q = useQuery({
    queryKey: ['event', incidentId, eventId],
    enabled: !!eventId,
    queryFn: async () => {
      if (incidentId) {
        const r = await api.get<{ snapshot: Snap }>(`/incidents/${incidentId}/evidence/${eventId}`)
        return r.snapshot
      }
      const r = await api.get<Snap>(`/events/${eventId}`)
      return r
    },
  })
  const s = q.data
  return (
    <Drawer
      open={!!eventId}
      onClose={onClose}
      title={s?.summary || 'Event'}
      subtitle={<Mono className="text-faint">{eventId}</Mono>}
      footer={
        <div className="flex items-center justify-between">
          <span className="text-[12px] text-faint">{incidentId ? 'Preserved evidence snapshot' : 'Stored telemetry'}</span>
          <Button size="sm" onClick={() => { navigator.clipboard?.writeText(eventId ?? ''); toast('Event ID copied') }}>Copy event ID</Button>
        </div>
      }
    >
      {q.isLoading && <div className="flex justify-center py-10"><Spinner /></div>}
      {q.error && <ErrorState error={q.error} />}
      {s && (
        <div className="space-y-5">
          <div className="flex items-center justify-between">
            <Segmented value={view} onChange={setView} items={[{ value: 'fields', label: 'Normalized' }, { value: 'raw', label: 'Original event' }]} />
            {s.mitre_techniques?.length > 0 && (
              <div className="flex gap-1">{s.mitre_techniques.map((t: string) => <Badge key={t} tone="accent">{t}</Badge>)}</div>
            )}
          </div>
          {view === 'fields' ? (
            <>
              <KeyValue items={fields(s)} />
              {s.metadata && Object.keys(s.metadata).length > 0 && (
                <div>
                  <SectionTitle>Additional fields</SectionTitle>
                  <JsonView value={s.metadata} maxHeight={220} />
                </div>
              )}
            </>
          ) : (
            <div>
              <p className="mb-2 text-[12.5px] text-muted">Exactly as received from {s.source_type}. Attacker-controlled fields are shown as data only.</p>
              <JsonView value={s.raw_event ?? {}} />
            </div>
          )}
        </div>
      )}
    </Drawer>
  )
}
