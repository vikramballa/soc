import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BellOff, CircleCheck, CircleDashed, CircleOff, Hourglass, Radar, Trash2 } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Modal } from '../components/overlay'
import { toast, toastError } from '../components/toast'
import { Badge, Button, Card, EmptyState, ErrorState, Input, Label, PageHeader, Select, SkeletonRows } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { num, relTime } from '../lib/format'

type Status = 'healthy' | 'overdue' | 'silent' | 'muted' | 'learning'

interface Sender {
  id: string
  source_type: string
  sender: string
  status: Status
  last_seen: string
  events: number
  usual_gap_seconds: number | null
  alert_after_minutes: number
  quiet_minutes: number
  silent_since: string | null
  muted_until: string | null
  mute_reason: string | null
}

// Status is always shown as icon + word, never by color alone.
const STATUS: Record<Status, { label: string; tone: 'ok' | 'warn' | 'danger' | 'neutral' | 'outline'; icon: ReactNode; help: string }> = {
  healthy: { label: 'Sending', tone: 'ok', icon: <CircleCheck className="size-3" />, help: 'Arriving at its usual pace' },
  overdue: { label: 'Overdue', tone: 'warn', icon: <Hourglass className="size-3" />, help: 'Quieter than usual; an alert follows if it stays quiet' },
  silent: { label: 'Stopped', tone: 'danger', icon: <CircleOff className="size-3" />, help: 'Went quiet - an alert was raised' },
  muted: { label: 'Muted', tone: 'neutral', icon: <BellOff className="size-3" />, help: 'Planned maintenance: no silence alert until the mute ends' },
  learning: { label: 'Learning', tone: 'outline', icon: <CircleDashed className="size-3" />, help: 'Not enough history yet to know its normal pace' },
}

function gap(seconds: number | null) {
  if (seconds === null) return '—'
  if (seconds < 1) return '< 1 s'
  if (seconds < 90) return `${Math.round(seconds)} s`
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`
  return `${(seconds / 3600).toFixed(1)} h`
}

export default function Telemetry() {
  const { can } = useAuth()
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['telemetry'], queryFn: () => api.get<{ items: Sender[]; counts: Partial<Record<Status, number>> }>('/telemetry/sources'), refetchInterval: 30_000 })
  const [muting, setMuting] = useState<Sender | null>(null)
  const [minutes, setMinutes] = useState('120')
  const [reason, setReason] = useState('')
  const refresh = () => qc.invalidateQueries({ queryKey: ['telemetry'] })
  const mute = useMutation({
    mutationFn: () => api.post(`/telemetry/sources/${muting?.id}/mute`, { minutes: Number(minutes), reason }),
    onSuccess: () => { toast('Muted for planned work'); setMuting(null); setReason(''); refresh() },
    onError: toastError,
  })
  const unmute = useMutation({ mutationFn: (id: string) => api.del(`/telemetry/sources/${id}/mute`), onSuccess: refresh, onError: toastError })
  const forget = useMutation({ mutationFn: (id: string) => api.del(`/telemetry/sources/${id}`), onSuccess: () => { toast('Removed from monitoring'); refresh() }, onError: toastError })
  const manage = can('rule:manage')

  return (
    <div>
      <PageHeader
        title="Telemetry Health"
        description="Every agent and sensor that sends to SentinelX, and whether it is still sending. Attackers often stop or blind security agents before they act, so a sender that goes quiet raises an alert - a high one when the silence follows a detection on the same host."
      />
      {q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : !q.data ? <SkeletonRows rows={8} /> : !q.data.items.length ? (
        <EmptyState icon={<Radar className="size-5" />} title="No telemetry received yet">Senders appear here automatically as soon as they send events.</EmptyState>
      ) : (
        <>
          <div className="mb-4 flex flex-wrap gap-2">
            {(Object.keys(STATUS) as Status[]).map((s) => (
              <Badge key={s} tone={STATUS[s].tone} title={STATUS[s].help}>{STATUS[s].icon} {STATUS[s].label}: {q.data.counts[s] ?? 0}</Badge>
            ))}
          </div>
          <Card className="overflow-x-auto">
            <table className="sx-table min-w-[820px]">
              <thead>
                <tr><th>Sender</th><th className="w-28">Source</th><th className="w-32">Status</th><th className="w-36">Last received</th><th className="w-28">Usual gap</th><th className="w-28">Alert after</th><th className="w-24 text-right">Events</th><th className="w-40" /></tr>
              </thead>
              <tbody>
                {q.data.items.map((s) => (
                  <tr key={s.id}>
                    <td className="font-medium">{s.sender}{s.mute_reason && s.status === 'muted' && <div className="text-[11.5px] font-normal text-faint">{s.mute_reason}</div>}</td>
                    <td className="text-muted">{s.source_type}</td>
                    <td><Badge tone={STATUS[s.status].tone} title={STATUS[s.status].help}>{STATUS[s.status].icon} {STATUS[s.status].label}</Badge></td>
                    <td className="text-muted">{relTime(s.last_seen)}</td>
                    <td className="text-muted">{gap(s.usual_gap_seconds)}</td>
                    <td className="text-muted">{s.alert_after_minutes} min quiet</td>
                    <td className="tnum text-right text-muted">{num(s.events)}</td>
                    <td className="text-right">
                      {manage && (
                        <span className="inline-flex gap-1">
                          {s.status === 'muted' ? (
                            <Button size="sm" variant="ghost" onClick={() => unmute.mutate(s.id)}>Unmute</Button>
                          ) : (
                            <Button size="sm" variant="ghost" icon={<BellOff className="size-3.5" />} onClick={() => setMuting(s)}>Mute</Button>
                          )}
                          <Button size="sm" variant="ghost" aria-label={`Stop monitoring ${s.sender}`} title="Decommissioned? Stop monitoring it (it reappears if it sends again)" onClick={() => forget.mutate(s.id)}>
                            <Trash2 className="size-3.5" />
                          </Button>
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>
      )}
      <Modal
        open={!!muting}
        onClose={() => setMuting(null)}
        title={`Mute ${muting?.sender ?? ''}`}
        description="For planned maintenance only. The mute is recorded in the audit log and raises a low-severity platform alert, because muting is also what an intruder would do before stopping an agent."
        footer={<><Button variant="ghost" onClick={() => setMuting(null)}>Cancel</Button><Button variant="primary" disabled={reason.trim().length < 3} loading={mute.isPending} onClick={() => mute.mutate()}>Mute</Button></>}
      >
        <div className="space-y-3">
          <label className="block"><Label>For how long</Label>
            <Select value={minutes} onChange={(e) => setMinutes(e.target.value)}>
              <option value="30">30 minutes</option>
              <option value="120">2 hours</option>
              <option value="480">8 hours</option>
              <option value="1440">1 day</option>
              <option value="10080">7 days</option>
            </Select>
          </label>
          <label className="block"><Label>Reason</Label><Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. CHG-1234 agent upgrade" autoFocus /></label>
        </div>
      </Modal>
    </div>
  )
}
