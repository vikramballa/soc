import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, KeyRound, Lock, Plus, ShieldCheck, UserPlus } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Modal } from '../components/overlay'
import { toast, toastError } from '../components/toast'
import { Badge, Button, Card, CardHeader, EmptyState, Input, Label, Mono, PageHeader, Segmented, Select, SkeletonRows, Switch, Tabs, Textarea } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { dateTime, relTime, ROLE_LABEL } from '../lib/format'
import type { Page } from '../lib/types'
import { Pager } from './Incidents'

type Tab = 'users' | 'settings' | 'tokens' | 'audit' | 'orgs'

interface UserRow { id: string; email: string; display_name: string; role: string; auth_provider: string; is_active: boolean; locked_until: string | null; last_login_at: string | null; created_at: string }
interface RoleInfo { role: string; description: string; permissions: string[] }

const ROLE_ORDER = ['VIEWER', 'IT_OPERATOR', 'SECURITY_ANALYST', 'TENANT_ADMIN', 'SUPER_ADMIN']
/** Mirrors the server rule: a super admin can grant/manage any role, everyone else only roles below their own. */
const assignable = (mine: string) =>
  ROLE_ORDER.filter((r) => mine === 'SUPER_ADMIN' || ROLE_ORDER.indexOf(r) < ROLE_ORDER.indexOf(mine))

const PW_ALPHABET = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
/** 14 random characters from an unambiguous alphabet, always with a letter and a digit. */
const generatePassword = () => Array.from(crypto.getRandomValues(new Uint8Array(12))).map((b) => PW_ALPHABET[b % PW_ALPHABET.length]).join('') + '7a'

const isLocked = (u: UserRow, now: number) => !!u.locked_until && new Date(u.locked_until).getTime() > now

function ResetPasswordModal({ user, onClose }: { user: UserRow | null; onClose: () => void }) {
  const qc = useQueryClient()
  const [pw, setPw] = useState('')
  const reset = useMutation({
    mutationFn: () => api.post(`/admin/users/${user?.id}/reset-password`, { password: pw }),
    onSuccess: () => {
      toast(`Password reset for ${user?.email}. They were signed out everywhere.`)
      qc.invalidateQueries({ queryKey: ['admin-users'] })
      close()
    },
    onError: toastError,
  })
  const close = () => { setPw(''); onClose() }
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(pw)
      toast('Password copied')
    } catch {
      toast('Copy failed — select the password and copy it by hand', 'error')
    }
  }
  return (
    <Modal open={!!user} onClose={close} title={`Reset password for ${user?.display_name ?? ''}`}
      description="Give the new password to the person through a trusted channel. They can change it from My account after signing in. This also unlocks the account and signs them out of every session."
      footer={<><Button variant="ghost" onClick={close}>Cancel</Button><Button variant="primary" loading={reset.isPending} disabled={pw.length < 12} onClick={() => reset.mutate()}>Reset password</Button></>}>
      <label className="block"><Label hint={<button type="button" onClick={() => setPw(generatePassword())} className="text-accent">Generate</button>}>New password (min. 12 characters)</Label>
        <div className="flex gap-2">
          <Input autoFocus value={pw} onChange={(e) => setPw(e.target.value)} className="font-mono" autoComplete="new-password" />
          <Button icon={<Copy className="size-4" />} disabled={!pw} onClick={copy} aria-label="Copy password" />
        </div>
      </label>
    </Modal>
  )
}

function UsersTab() {
  const { me } = useAuth()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [f, setF] = useState({ email: '', display_name: '', role: 'SECURITY_ANALYST', password: '' })
  const grantable = assignable(me.user.role)
  const canManage = (u: UserRow) => u.id !== me.user.id && grantable.includes(u.role)
  const users = useQuery({ queryKey: ['admin-users'], queryFn: () => api.get<UserRow[]>('/admin/users') })
  const roles = useQuery({ queryKey: ['roles'], queryFn: () => api.get<RoleInfo[]>('/admin/roles') })
  const create = useMutation({
    mutationFn: () => api.post('/admin/users', f),
    onSuccess: () => { toast(`User ${f.email} created`); setOpen(false); setF({ email: '', display_name: '', role: 'SECURITY_ANALYST', password: '' }); qc.invalidateQueries({ queryKey: ['admin-users'] }) },
    onError: toastError,
  })
  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) => api.patch(`/admin/users/${id}`, body),
    onSuccess: () => { toast('User updated'); qc.invalidateQueries({ queryKey: ['admin-users'] }) },
    onError: toastError,
  })
  const genPw = () => setF({ ...f, password: generatePassword() })
  const [resetFor, setResetFor] = useState<UserRow | null>(null)
  // captured when the list loads, so rendering stays pure
  const now = users.dataUpdatedAt
  const unlock = useMutation({
    mutationFn: (id: string) => api.post(`/admin/users/${id}/unlock`),
    onSuccess: () => { toast('Account unlocked'); qc.invalidateQueries({ queryKey: ['admin-users'] }) },
    onError: toastError,
  })
  return (
    <Card className="overflow-hidden">
      <CardHeader title="Users" subtitle="People who can sign in to this organization" action={<Button variant="primary" icon={<UserPlus className="size-4" />} onClick={() => setOpen(true)}>Add user</Button>} />
      {!users.data ? <SkeletonRows /> : (
        <table className="sx-table border-t border-line">
          <thead><tr><th>User</th><th className="w-48">Role</th><th className="w-36">Last sign-in</th><th className="w-24">Active</th><th className="w-52 text-right">Sign-in help</th></tr></thead>
          <tbody>
            {users.data.map((u) => (
              <tr key={u.id}>
                <td><div className="font-medium">{u.display_name}{u.id === me.user.id && <Badge tone="accent" className="ml-2">you</Badge>}{isLocked(u, now) && <Badge tone="warn" className="ml-2" title={`Too many failed sign-ins. Locked until ${dateTime(u.locked_until)}`}><Lock className="size-3" /> locked</Badge>}{!u.is_active && <Badge className="ml-2">deactivated</Badge>}</div><div className="text-[12px] text-faint">{u.email}{u.auth_provider !== 'local' && ' · SSO'}</div></td>
                <td>
                  {canManage(u) && u.auth_provider === 'local' ? (
                    <Select value={u.role} onChange={(e) => update.mutate({ id: u.id, body: { role: e.target.value } })}>
                      {grantable.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
                    </Select>
                  ) : (
                    <span className="text-[13px] text-muted" title={u.auth_provider !== 'local' ? 'Role comes from single sign-on' : u.id === me.user.id ? 'You cannot change your own role' : 'Only a super admin can manage this user'}>
                      {ROLE_LABEL[u.role] ?? u.role}{u.auth_provider !== 'local' && ' · SSO'}
                    </span>
                  )}
                </td>
                <td className="text-muted">{relTime(u.last_login_at)}</td>
                <td><Switch label={`Active: ${u.email}`} checked={u.is_active} disabled={!canManage(u)} onChange={(v) => update.mutate({ id: u.id, body: { is_active: v } })} /></td>
                <td><div className="flex items-center justify-end gap-1">
                  {canManage(u) && isLocked(u, now) && <Button size="sm" variant="ghost" loading={unlock.isPending && unlock.variables === u.id} onClick={() => unlock.mutate(u.id)}>Unlock</Button>}
                  {canManage(u) && u.auth_provider === 'local' && <Button size="sm" variant="ghost" icon={<KeyRound className="size-3.5" />} onClick={() => setResetFor(u)}>Reset password</Button>}
                </div></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="border-t border-line px-4 py-3">
        <div className="mb-2 text-[12px] font-medium tracking-wide text-faint uppercase">What each role can do</div>
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-5">
          {(roles.data ?? []).map((r) => (
            <div key={r.role} className="rounded-lg border border-line bg-bg-elev p-2.5 text-[12px]">
              <div className="font-medium text-fg">{ROLE_LABEL[r.role]}</div>
              <div className="mt-0.5 text-muted">{r.description}</div>
            </div>
          ))}
        </div>
      </div>
      <ResetPasswordModal user={resetFor} onClose={() => setResetFor(null)} />
      <Modal open={open} onClose={() => setOpen(false)} title="Add user" description="They can change their password after signing in."
        footer={<><Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button><Button variant="primary" loading={create.isPending} disabled={!f.email || !f.display_name || f.password.length < 12} onClick={() => create.mutate()}>Create user</Button></>}>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <label className="block"><Label>Name</Label><Input autoFocus value={f.display_name} onChange={(e) => setF({ ...f, display_name: e.target.value })} /></label>
            <label className="block"><Label>Email</Label><Input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
          </div>
          <label className="block"><Label>Role</Label>
            <Select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
              {grantable.map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
            </Select>
          </label>
          <label className="block"><Label hint={<button type="button" onClick={genPw} className="text-accent">Generate</button>}>Initial password (min. 12 characters)</Label>
            <Input value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} className="font-mono" />
          </label>
        </div>
      </Modal>
    </Card>
  )
}

function SettingsTab() {
  const qc = useQueryClient()
  const s = useQuery({ queryKey: ['tenant-settings'], queryFn: () => api.get<{ name: string; slug: string; correlation_window_minutes: number; correlation_ignore: string[]; event_retention_days: number; defaults: Record<string, unknown> }>('/admin/settings') })
  const [f, setF] = useState({ name: '', window: 60, ignore: '', retention: 30 })
  useEffect(() => {
    if (s.data) setF({ name: s.data.name, window: s.data.correlation_window_minutes, ignore: s.data.correlation_ignore.join('\n'), retention: s.data.event_retention_days })
  }, [s.data])
  const save = useMutation({
    mutationFn: () => api.put('/admin/settings', { name: f.name, correlation_window_minutes: f.window, correlation_ignore: f.ignore.split(/\n|,/).map((x) => x.trim()).filter(Boolean), event_retention_days: f.retention }),
    onSuccess: () => { toast('Settings saved'); qc.invalidateQueries({ queryKey: ['tenant-settings'] }); qc.invalidateQueries({ queryKey: ['me'] }) },
    onError: toastError,
  })
  if (!s.data) return <SkeletonRows />
  return (
    <Card className="max-w-2xl p-5">
      <div className="space-y-5">
        <label className="block"><Label>Organization name</Label><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></label>
        <label className="block"><Label hint="5–1440 minutes">Correlation window</Label>
          <Select value={f.window} onChange={(e) => setF({ ...f, window: Number(e.target.value) })}>
            {[5, 15, 30, 60, 120, 240, 1440].map((m) => <option key={m} value={m}>{m < 60 ? `${m} minutes` : m === 1440 ? '24 hours (slow campaigns)' : `${m / 60} hour${m > 60 ? 's' : ''}`}</option>)}
          </Select>
          <span className="mt-1 block text-[12px] text-faint">Alerts sharing a host, user, IP or domain within this window are joined into one incident.</span>
        </label>
        <label className="block"><Label hint="one per line">Never correlate on</Label>
          <Textarea className="font-mono text-[12px]" value={f.ignore} onChange={(e) => setF({ ...f, ignore: e.target.value })} placeholder={'ip:10.0.0.2\nuser:svc_scanner'} />
          <span className="mt-1 block text-[12px] text-faint">Shared infrastructure (DNS servers, proxies, scanners) that would otherwise glue unrelated activity together. Format kind:value — kinds: host, user, ip, domain, hash.</span>
        </label>
        <label className="block"><Label>Keep raw telemetry for</Label>
          <Select value={f.retention} onChange={(e) => setF({ ...f, retention: Number(e.target.value) })}>
            {[7, 14, 30, 60, 90, 180, 365].map((d) => <option key={d} value={d}>{d} days</option>)}
          </Select>
          <span className="mt-1 block text-[12px] text-faint">Incident evidence and audit logs are kept separately and are not deleted by this setting. Choose according to your legal and contractual obligations.</span>
        </label>
        <div className="flex justify-end"><Button variant="primary" loading={save.isPending} onClick={() => save.mutate()}>Save settings</Button></div>
      </div>
    </Card>
  )
}

function TokensTab() {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [created, setCreated] = useState<string | null>(null)
  const list = useQuery({ queryKey: ['tokens'], queryFn: () => api.get<{ id: string; name: string; prefix: string; created_at: string; last_used_at: string | null; revoked: boolean }[]>('/admin/ingest-tokens') })
  const create = useMutation({
    mutationFn: () => api.post<{ token: string }>('/admin/ingest-tokens', { name }),
    onSuccess: (r) => { setCreated(r.token); setName(''); qc.invalidateQueries({ queryKey: ['tokens'] }) },
    onError: toastError,
  })
  const revoke = useMutation({ mutationFn: (id: string) => api.del(`/admin/ingest-tokens/${id}`), onSuccess: () => { toast('Token revoked'); qc.invalidateQueries({ queryKey: ['tokens'] }) } })
  return (
    <Card className="overflow-hidden">
      <CardHeader title="Ingest tokens" subtitle="Let log shippers (Fluent Bit, Vector, scripts) send telemetry into this organization only." />
      <div className="flex gap-2 border-y border-line bg-bg-elev px-4 py-2.5">
        <Input className="max-w-xs" placeholder="Token name, e.g. fluent-bit-dmz" value={name} onChange={(e) => setName(e.target.value)} />
        <Button variant="primary" icon={<Plus className="size-4" />} disabled={name.length < 2} loading={create.isPending} onClick={() => create.mutate()}>Create token</Button>
      </div>
      {!list.data ? <SkeletonRows /> : !list.data.length ? <EmptyState icon={<KeyRound className="size-5" />} title="No tokens yet" /> : (
        <table className="sx-table">
          <thead><tr><th>Name</th><th className="w-32">Prefix</th><th className="w-36">Created</th><th className="w-36">Last used</th><th className="w-28" /></tr></thead>
          <tbody>
            {list.data.map((t) => (
              <tr key={t.id}>
                <td className="font-medium">{t.name} {t.revoked && <Badge>revoked</Badge>}</td>
                <td><Mono className="text-muted">{t.prefix}…</Mono></td>
                <td className="text-muted">{dateTime(t.created_at)}</td>
                <td className="text-muted">{relTime(t.last_used_at)}</td>
                <td className="text-right">{!t.revoked && <Button size="sm" variant="danger" onClick={() => revoke.mutate(t.id)}>Revoke</Button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <Modal open={!!created} onClose={() => setCreated(null)} title="Copy your new token" description="It is shown only once. Store it in your log shipper's secret configuration."
        footer={<Button variant="primary" onClick={() => setCreated(null)}>Done</Button>}>
        <div className="flex items-center gap-2 rounded-lg border border-line bg-bg-elev p-3">
          <Mono className="flex-1 break-all text-fg">{created}</Mono>
          <Button size="sm" icon={<Copy className="size-3.5" />} onClick={() => { navigator.clipboard?.writeText(created ?? ''); toast('Copied') }}>Copy</Button>
        </div>
      </Modal>
    </Card>
  )
}

function AuditTab() {
  const { can } = useAuth()
  const [action, setAction] = useState('')
  const [scope, setScope] = useState<'organization' | 'platform'>('organization')
  const [offset, setOffset] = useState(0)
  const q = useQuery({ queryKey: ['audit', action, offset, scope], queryFn: () => api.get<Page<{ id: string; actor: string; action: string; resource_type: string; resource_id: string | null; result: string; details: Record<string, unknown>; source_ip: string | null; created_at: string }>>('/admin/audit-logs', { action, offset, limit: 100, scope }) })
  return (
    <Card className="overflow-hidden">
      <CardHeader title="Audit log" subtitle="Append-only record of sign-ins, changes, AI requests and reports. Entries cannot be edited or deleted." icon={<ShieldCheck className="size-4" />} />
      <div className="flex flex-wrap items-center gap-2 border-y border-line bg-bg-elev px-4 py-2.5">
        {can('platform:manage') && (
          <Segmented value={scope} onChange={(v) => { setScope(v); setOffset(0) }} items={[{ value: 'organization', label: 'This organization' }, { value: 'platform', label: 'Platform (no organization)' }]} />
        )}
        <Select className="max-w-xs" value={action} onChange={(e) => { setAction(e.target.value); setOffset(0) }}>
          <option value="">All actions</option>
          {['auth', 'incident', 'response', 'ai', 'rule', 'user', 'tenant', 'threatintel', 'report', 'ingest_token', 'authorization'].map((a) => <option key={a} value={a}>{a}</option>)}
        </Select>
      </div>
      {!q.data ? <SkeletonRows /> : (
        <div className="overflow-x-auto">
          <table className="sx-table min-w-[860px] text-[12.5px]">
            <thead><tr><th className="w-40">Time</th><th className="w-52">Actor</th><th className="w-48">Action</th><th>Details</th><th className="w-20">Result</th></tr></thead>
            <tbody>
              {q.data.items.map((a) => (
                <tr key={a.id}>
                  <td className="tnum text-muted">{dateTime(a.created_at, { seconds: true })}</td>
                  <td className="truncate">{a.actor}{a.source_ip && <div className="text-[11.5px] text-faint">{a.source_ip}</div>}</td>
                  <td><Mono>{a.action}</Mono></td>
                  <td className="max-w-0 truncate text-muted" title={JSON.stringify(a.details)}>{a.resource_type}{a.resource_id ? ` ${a.resource_id.slice(0, 36)}` : ''} {Object.keys(a.details).length ? JSON.stringify(a.details) : ''}</td>
                  <td><Badge tone={a.result === 'success' ? 'ok' : 'danger'}>{a.result}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {q.data && <Pager total={q.data.total} offset={offset} limit={100} onChange={setOffset} />}
    </Card>
  )
}

function OrgsTab() {
  const { me } = useAuth()
  const qc = useQueryClient()
  const [f, setF] = useState({ name: '', slug: '' })
  const create = useMutation({
    mutationFn: () => api.post('/admin/tenants', f),
    onSuccess: () => { toast('Organization created'); setF({ name: '', slug: '' }); qc.invalidateQueries({ queryKey: ['me'] }) },
    onError: toastError,
  })
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card>
        <CardHeader title="Organizations" subtitle="Each organization's data is isolated (enforced in the API and by PostgreSQL row-level security)." />
        <ul className="divide-y divide-line border-t border-line">
          {me.tenants.map((t) => (
            <li key={t.id} className="flex items-center justify-between px-4 py-2.5 text-[13px]">
              <span><span className="font-medium">{t.name}</span> <span className="text-faint">· {t.slug}</span></span>
              {t.demo && <Badge tone="ai">synthetic demo</Badge>}
            </li>
          ))}
        </ul>
      </Card>
      <Card className="p-4">
        <div className="mb-3 text-[13.5px] font-semibold">New organization</div>
        <div className="space-y-3">
          <label className="block"><Label>Name</Label><Input value={f.name} onChange={(e) => setF({ name: e.target.value, slug: f.slug || '' })} placeholder="Acme Manufacturing" /></label>
          <label className="block"><Label hint="lowercase, used for SSO tenant mapping">Slug</Label><Input value={f.slug} onChange={(e) => setF({ ...f, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '-') })} placeholder="acme" /></label>
          <div className="flex justify-end"><Button variant="primary" disabled={!f.name || !f.slug} loading={create.isPending} onClick={() => create.mutate()}>Create</Button></div>
        </div>
      </Card>
    </div>
  )
}

export default function Admin() {
  const { can } = useAuth()
  const isSuperAdmin = can('platform:manage')
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') ?? 'users') as Tab
  return (
    <div>
      <PageHeader title="Administration" description="Users, organization settings, ingest tokens and the audit trail." />
      <Tabs
        value={tab}
        onChange={(t) => setParams({ tab: t }, { replace: true })}
        className="mb-5"
        items={[
          { value: 'users', label: 'Users' },
          { value: 'settings', label: 'Organization settings' },
          { value: 'tokens', label: 'Ingest tokens' },
          { value: 'audit', label: 'Audit log' },
          ...(isSuperAdmin ? [{ value: 'orgs' as Tab, label: 'Organizations' }] : []),
        ]}
      />
      {tab === 'users' && <UsersTab />}
      {tab === 'settings' && <SettingsTab />}
      {tab === 'tokens' && <TokensTab />}
      {tab === 'audit' && <AuditTab />}
      {tab === 'orgs' && isSuperAdmin && <OrgsTab />}
    </div>
  )
}
