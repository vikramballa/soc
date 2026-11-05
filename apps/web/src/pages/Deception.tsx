import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Fingerprint, Plus, Siren, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { Modal } from '../components/overlay'
import { toast, toastError } from '../components/toast'
import { Badge, Button, Card, EmptyState, ErrorState, Input, Label, Mono, PageHeader, Select, SkeletonRows, Switch, Textarea } from '../components/ui'
import { api } from '../lib/api'
import { relTime } from '../lib/format'

interface Honeytoken {
  id: string
  kind: string
  value: string
  description: string
  enabled: boolean
  created_by: string
  created_at: string
  last_triggered_at: string | null
  trigger_count: number
}

const KIND_LABEL: Record<string, string> = {
  account: 'Decoy account',
  host: 'Decoy host',
  ip: 'Decoy address',
  domain: 'Decoy DNS name',
  file: 'Decoy file',
  credential: 'Fake credential',
  url: 'Decoy URL',
}

const PLACEHOLDER: Record<string, string> = {
  account: 'svc_backup_legacy',
  host: 'fin-db-archive02',
  ip: '10.20.30.250',
  domain: 'vault-admin.corp.example',
  file: '\\\\fileserver\\finance\\passwords_2026.xlsx',
  credential: 'AKIAXXXXDECOY000EXAMPLE',
  url: 'https://intranet.corp.example/admin-backup',
}

export default function Deception() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['honeytokens'], queryFn: () => api.get<{ items: Honeytoken[]; kinds: Record<string, string> }>('/deception/honeytokens') })
  const [open, setOpen] = useState(false)
  const [f, setF] = useState({ kind: 'account', value: '', description: '' })
  const refresh = () => qc.invalidateQueries({ queryKey: ['honeytokens'] })
  const create = useMutation({
    mutationFn: () => api.post('/deception/honeytokens', f),
    onSuccess: () => { toast('Decoy added - it is watched from now on'); setOpen(false); setF({ kind: f.kind, value: '', description: '' }); refresh() },
    onError: toastError,
  })
  const toggle = useMutation({ mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.patch(`/deception/honeytokens/${id}`, { enabled }), onSuccess: refresh, onError: toastError })
  const remove = useMutation({ mutationFn: (id: string) => api.del(`/deception/honeytokens/${id}`), onSuccess: () => { toast('Decoy removed'); refresh() }, onError: toastError })

  return (
    <div>
      <PageHeader
        title="Deception"
        description="Decoys (honeytokens) are accounts, hosts, addresses, files or credentials that nothing legitimate ever uses. Plant them where an intruder looks - directories, file shares, scripts, wikis - and any touch becomes a critical incident with almost no false alarms. Only administrators can see this list; keep it that way."
        actions={<Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setOpen(true)}>Add decoy</Button>}
      />
      {q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : !q.data ? <SkeletonRows /> : !q.data.items.length ? (
        <EmptyState icon={<Fingerprint className="size-5" />} title="No decoys yet" action={<Button variant="primary" onClick={() => setOpen(true)}>Add your first decoy</Button>}>
          A good first decoy: a disabled-looking service account with a tempting description, created in your directory but used by nothing.
        </EmptyState>
      ) : (
        <Card className="overflow-x-auto">
          <table className="sx-table min-w-[760px]">
            <thead><tr><th className="w-40">Type</th><th>Decoy</th><th className="w-40">Last touched</th><th className="w-24">Watching</th><th className="w-14" /></tr></thead>
            <tbody>
              {q.data.items.map((t) => (
                <tr key={t.id}>
                  <td className="text-muted">{KIND_LABEL[t.kind] ?? t.kind}</td>
                  <td>
                    <Mono className="text-fg">{t.value}</Mono>
                    {t.description && <div className="text-[12px] text-faint">{t.description}</div>}
                  </td>
                  <td>
                    {t.trigger_count ? (
                      <Badge tone="danger"><Siren className="size-3" /> {relTime(t.last_triggered_at)} · {t.trigger_count}×</Badge>
                    ) : (
                      <span className="text-[12.5px] text-faint">Never</span>
                    )}
                  </td>
                  <td><Switch label={`Watch ${t.value}`} checked={t.enabled} onChange={(v) => toggle.mutate({ id: t.id, enabled: v })} /></td>
                  <td className="text-right">
                    <Button size="sm" variant="ghost" aria-label={`Delete decoy ${t.value}`} onClick={() => remove.mutate(t.id)}><Trash2 className="size-3.5" /></Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
      <p className="mt-4 text-[12.5px] text-faint">
        Also running Thinkst Canarytokens? Point its webhook at <Mono>/api/v1/ingest/canarytokens?token=…</Mono> with an ingest token limited to the <Mono>canarytokens</Mono> source.
      </p>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Add decoy"
        description={q.data?.kinds[f.kind]}
        footer={<><Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" disabled={f.value.trim().length < 2} loading={create.isPending} onClick={() => create.mutate()}>Add decoy</Button></>}
      >
        <div className="space-y-3">
          <label className="block"><Label>Type</Label>
            <Select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>
              {Object.entries(KIND_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </Select>
          </label>
          <label className="block"><Label>Value</Label><Input className="font-mono" autoFocus value={f.value} onChange={(e) => setF({ ...f, value: e.target.value })} placeholder={PLACEHOLDER[f.kind]} /></label>
          <label className="block"><Label hint="optional">Where you planted it</Label><Textarea rows={2} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} placeholder="e.g. created in AD, description 'old backup service - password in vault'" /></label>
        </div>
      </Modal>
    </div>
  )
}
