import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BookOpenCheck, FlaskConical, Pencil, Plus, RefreshCw, Search, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Drawer, Modal } from '../components/overlay'
import { SeverityBadge, TechniqueChip } from '../components/security'
import { toast, toastError } from '../components/toast'
import { Badge, Button, Card, EmptyState, ErrorState, Input, KeyValue, PageHeader, SectionTitle, Segmented, Skeleton, SkeletonRows, Switch, Textarea } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { dateTime, num, relTime } from '../lib/format'
import type { Severity } from '../lib/types'

interface Rule {
  rule_uid: string
  name: string | null
  title: string
  description: string
  kind: string
  status: string
  level: Severity
  severity: number
  tags: string[]
  mitre_techniques: string[]
  version: number
  enabled: boolean
  globally_enabled: boolean
  generates_alerts: boolean
  falsepositives: string[]
  updated_at: string
  alerts_7d: number
}

const KIND_LABEL: Record<string, string> = {
  sigma: 'Sigma rule',
  correlation: 'Correlation',
  builtin: 'Behavioral',
  source: 'Sensor pass-through',
  ml: 'Machine learning',
}

const template = () => `title: My custom detection
id: ${crypto.randomUUID()}
status: experimental
description: What this rule detects and why it matters.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains|all:
      - '-urlcache'
      - 'http'
  condition: selection
falsepositives:
  - Describe legitimate causes
level: medium
tags:
  - attack.command_and_control
  - attack.t1105
`

function RuleEditor({ open, onClose, initial, uid }: { open: boolean; onClose: () => void; initial?: string; uid?: string }) {
  const qc = useQueryClient()
  const [content, setContent] = useState(initial ?? template())
  const [error, setError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => (uid ? api.put(`/detections/${uid}`, { content }) : api.post('/detections', { content })),
    onSuccess: () => {
      toast(uid ? 'Rule updated — new version saved' : 'Rule added and active')
      qc.invalidateQueries({ queryKey: ['rules'] })
      qc.invalidateQueries({ queryKey: ['rule', uid] })
      onClose()
    },
    onError: (e: Error) => setError(e.message),
  })
  return (
    <Modal open={open} onClose={onClose} size="lg" title={uid ? 'Edit custom rule' : 'New detection rule'}
      description={<>Standard <a className="text-accent" href="https://sigmahq.io/sigma-specification/" target="_blank" rel="noreferrer">Sigma</a> YAML. SentinelX compiles it before saving, so a broken rule can never be activated.</>}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" loading={save.isPending} onClick={() => { setError(null); save.mutate() }}>Validate &amp; save</Button></>}>
      <Textarea value={content} onChange={(e) => setContent(e.target.value)} spellCheck={false} className="min-h-[360px] font-mono text-[12px] leading-relaxed" />
      {error && <p role="alert" className="mt-2 rounded-lg border border-danger/25 bg-danger/8 px-3 py-2 text-[12.5px] text-danger">{error}</p>}
      <p className="mt-2 text-[12px] text-faint">Fields: Image, CommandLine, ParentImage, User, DestinationIp, DestinationPort, QueryName, TargetFilename, or canonical names such as event_action, outcome, hostname. See docs/operations/sigma-rules.md.</p>
    </Modal>
  )
}

export default function Rules() {
  const { can } = useAuth()
  const isPlatform = can('platform:manage')
  const qc = useQueryClient()
  const [params, setParams] = useSearchParams()
  const [search, setSearch] = useState('')
  const [kind, setKind] = useState('all')
  const [creating, setCreating] = useState(false)
  const sel = params.get('rule')
  const q = useQuery({ queryKey: ['rules'], queryFn: () => api.get<{ items: Rule[]; rejected: { path: string; error: string }[] }>('/detections') })
  const toggle = useMutation({
    mutationFn: ({ uid, enabled }: { uid: string; enabled: boolean }) => api.patch(`/detections/${uid}`, { enabled }),
    onSuccess: (_, v) => { qc.invalidateQueries({ queryKey: ['rules'] }); toast(v.enabled ? 'Rule enabled for this organization' : 'Rule disabled for this organization') },
    onError: toastError,
  })
  const sync = useMutation({
    mutationFn: () => api.post<{ created: number; updated: number; total: number; rejected: number }>('/detections/sync'),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ['rules'] }); toast(`Rules reloaded: ${r.created} new, ${r.updated} updated, ${r.rejected} rejected`) },
    onError: toastError,
  })
  const items = useMemo(() => {
    const s = search.toLowerCase()
    return (q.data?.items ?? []).filter((r) =>
      (kind === 'all' || r.kind === kind) &&
      (!s || r.title.toLowerCase().includes(s) || r.description.toLowerCase().includes(s) || r.mitre_techniques.some((t) => t.toLowerCase().includes(s))))
  }, [q.data, search, kind])

  return (
    <div>
      <PageHeader
        title="Detection Rules"
        description="Portable Sigma rules (stored in security/sigma-rules, versioned), Sigma correlation rules, behavioral evaluators and sensor pass-through. Switching a rule off affects only this organization."
        actions={isPlatform && <>
          <Button icon={<RefreshCw className="size-4" />} loading={sync.isPending} onClick={() => sync.mutate()}>Reload from repository</Button>
          <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setCreating(true)}>New rule</Button>
        </>}
      />
      {q.data?.rejected.length ? (
        <Card className="mb-4 border-warn/30 p-3 text-[12.5px] text-warn">
          {q.data.rejected.length} rule file(s) were rejected and are not running: {q.data.rejected.map((r) => r.error).join('; ')}
        </Card>
      ) : null}
      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-line bg-bg-elev px-4 py-2.5">
          <Input icon={<Search className="size-4" />} className="w-full max-w-xs" placeholder="Search rules or technique IDs" value={search} onChange={(e) => setSearch(e.target.value)} />
          <Segmented value={kind} onChange={setKind} items={[{ value: 'all', label: 'All' }, { value: 'sigma', label: 'Sigma' }, { value: 'correlation', label: 'Correlation' }, { value: 'builtin', label: 'Behavioral' }, { value: 'source', label: 'Sensors' }]} />
        </div>
        {q.error ? <ErrorState error={q.error} /> : !q.data ? <SkeletonRows /> : !items.length ? <EmptyState icon={<BookOpenCheck className="size-5" />} title="No rules match" /> : (
          <div className="overflow-x-auto">
            <table className="sx-table min-w-[900px]">
              <thead><tr><th className="w-24">Level</th><th>Rule</th><th className="w-36">Type</th><th className="w-52">ATT&CK</th><th className="w-24 text-right">Alerts 7d</th><th className="w-20">Active</th></tr></thead>
              <tbody>
                {items.map((r) => (
                  <tr key={r.rule_uid} data-clickable="true" onClick={() => setParams({ rule: r.rule_uid })}>
                    <td><SeverityBadge severity={r.level === 'informational' ? 'informational' : r.level} size="sm" /></td>
                    <td className="max-w-0">
                      <div className="truncate font-medium">{r.title}</div>
                      <div className="truncate text-[12px] text-faint">{!r.generates_alerts ? 'Building block — feeds correlation rules, never alerts on its own' : r.description}</div>
                    </td>
                    <td className="text-[12.5px] text-muted">{KIND_LABEL[r.kind] ?? r.kind}{(r as Rule & { custom?: boolean }).custom && <Badge tone="accent" className="ml-1.5">custom</Badge>}</td>
                    <td><div className="flex flex-wrap gap-1">{r.mitre_techniques.slice(0, 2).map((t) => <TechniqueChip key={t} id={t} />)}{r.mitre_techniques.length > 2 && <Badge>+{r.mitre_techniques.length - 2}</Badge>}</div></td>
                    <td className="tnum text-right text-muted">{num(r.alerts_7d)}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <Switch label={`Enable ${r.title}`} checked={r.enabled} disabled={!can('rule:manage') || !r.globally_enabled} onChange={(v) => toggle.mutate({ uid: r.rule_uid, enabled: v })} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <RuleDrawer uid={sel} onClose={() => setParams({})} />
      {creating && <RuleEditor open onClose={() => setCreating(false)} />}
    </div>
  )
}

function RuleDrawer({ uid, onClose }: { uid: string | null; onClose: () => void }) {
  const { can } = useAuth()
  const isPlatform = can('platform:manage')
  const qc = useQueryClient()
  const [editing, setEditing] = useState(false)
  const del = useMutation({
    mutationFn: () => api.del(`/detections/${uid}`),
    onSuccess: () => { toast('Rule deleted'); qc.invalidateQueries({ queryKey: ['rules'] }); onClose() },
    onError: toastError,
  })
  const [dry, setDry] = useState<{ evaluated: number; matched: number; by_host: Record<string, number>; samples: { id: string; timestamp: string; summary: string }[] } | null>(null)
  const q = useQuery({
    queryKey: ['rule', uid],
    enabled: !!uid,
    queryFn: () => api.get<{ rule: Rule & { content: string; source_path: string | null }; versions: { version: number; created_at: string; created_by: string; sha256: string }[]; recent_alerts: { id: string; title: string; hostname: string | null; last_event_at: string; incident_id: string | null }[] }>(`/detections/${uid}`),
  })
  const test = useMutation({
    mutationFn: () => api.post<typeof dry>(`/detections/${uid}/test`, {}, { hours: 24 }),
    onSuccess: (r) => setDry(r),
    onError: toastError,
  })
  const r = q.data?.rule
  return (
    <Drawer open={!!uid} onClose={() => { setDry(null); onClose() }} title={r?.title ?? 'Rule'} width={680}
      subtitle={r && <span className="flex items-center gap-2">{KIND_LABEL[r.kind]} · v{r.version} · <Badge tone={r.enabled ? 'ok' : 'neutral'}>{r.enabled ? 'active' : 'off'}</Badge></span>}>
      {!r ? <Skeleton className="h-60" /> : (
        <div className="space-y-5">
          <p className="text-[13px] text-muted">{r.description}</p>
          {isPlatform && !r.source_path && (r.kind === 'sigma' || r.kind === 'correlation') && (
            <div className="flex gap-2">
              <Button size="sm" icon={<Pencil className="size-3.5" />} onClick={() => setEditing(true)}>Edit</Button>
              <Button size="sm" variant="danger" icon={<Trash2 className="size-3.5" />} loading={del.isPending} onClick={() => { if (window.confirm('Delete this custom rule? Existing alerts are kept.')) del.mutate() }}>Delete</Button>
            </div>
          )}
          {editing && <RuleEditor open initial={r.content} uid={r.rule_uid} onClose={() => setEditing(false)} />}
          <KeyValue items={[
            ['Level', <SeverityBadge key="l" severity={r.level} size="sm" />],
            ['Rule ID', <span key="id" className="font-mono text-[12px]">{r.rule_uid}</span>],
            ['Status', r.status],
            ['Updated', dateTime(r.updated_at)],
            ['File', r.source_path ? <span key="f" className="font-mono text-[11.5px] break-all text-faint">{r.source_path.split('security/')[1] ?? r.source_path}</span> : <Badge key="f" tone="accent">custom rule (stored in database)</Badge>],
          ]} />
          {r.mitre_techniques.length > 0 && <div className="flex flex-wrap gap-1">{r.mitre_techniques.map((t) => <TechniqueChip key={t} id={t} />)}</div>}
          {r.falsepositives.length > 0 && <div><SectionTitle>Known false positives</SectionTitle><ul className="list-disc pl-5 text-[13px] text-muted">{r.falsepositives.map((f) => <li key={f}>{f}</li>)}</ul></div>}
          {r.kind === 'sigma' && (
            <div>
              <SectionTitle action={<Button size="sm" icon={<FlaskConical className="size-3.5" />} loading={test.isPending} onClick={() => test.mutate()}>Dry-run on last 24h</Button>}>Tune</SectionTitle>
              {dry && (
                <div className="animate-in rounded-lg border border-line bg-bg-elev p-3 text-[12.5px]">
                  <div><b className="tnum">{num(dry.matched)}</b> of {num(dry.evaluated)} recent events match.</div>
                  {Object.keys(dry.by_host).length > 0 && <div className="mt-1 text-muted">By host: {Object.entries(dry.by_host).map(([h, n]) => `${h} (${n})`).join(', ')}</div>}
                  <ul className="mt-2 space-y-0.5 text-faint">{dry.samples.map((s) => <li key={s.id} className="truncate">{s.summary}</li>)}</ul>
                </div>
              )}
            </div>
          )}
          <div>
            <SectionTitle>Rule definition</SectionTitle>
            <pre className="sx-code max-h-80 overflow-auto rounded-lg border border-line bg-bg-elev p-3 whitespace-pre-wrap">{r.content}</pre>
          </div>
          <div>
            <SectionTitle>Recent alerts</SectionTitle>
            {q.data!.recent_alerts.length ? (
              <ul className="space-y-1 text-[13px]">
                {q.data!.recent_alerts.map((a) => (
                  <li key={a.id} className="flex justify-between gap-2">
                    {a.incident_id ? <Link to={`/incidents/${a.incident_id}`} className="truncate hover:text-accent">{a.hostname ?? a.title}</Link> : <span className="truncate">{a.hostname ?? a.title}</span>}
                    <span className="shrink-0 text-faint">{relTime(a.last_event_at)}</span>
                  </li>
                ))}
              </ul>
            ) : <p className="text-[12.5px] text-faint">This rule has not fired in this organization.</p>}
          </div>
          <div>
            <SectionTitle>Version history</SectionTitle>
            <ul className="space-y-1 text-[12.5px] text-muted">
              {q.data!.versions.map((v) => <li key={v.version}>v{v.version} · {dateTime(v.created_at)} · {v.created_by} · <span className="font-mono text-faint">{v.sha256.slice(0, 10)}</span></li>)}
            </ul>
          </div>
        </div>
      )}
    </Drawer>
  )
}
