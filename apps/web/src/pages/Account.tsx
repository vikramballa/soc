import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, KeyRound, LogOut, Minus, Monitor, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { PasswordModal } from '../components/Layout'
import { toast, toastError } from '../components/toast'
import { Badge, Button, Card, CardHeader, EmptyState, KeyValue, PageHeader, SkeletonRows } from '../components/ui'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import { dateTime, relTime, ROLE_LABEL } from '../lib/format'

interface SessionRow { id: string; created_at: string; expires_at: string; ip: string | null; user_agent: string | null; current: boolean }

/** "Firefox on Windows" is all a person needs to recognise a device; the full string is in the tooltip. */
function deviceName(ua: string | null): string {
  if (!ua) return 'Unknown device'
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl|python|httpx/i.test(ua) ? 'Script' : 'Browser'
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : ''
  return os ? `${browser} on ${os}` : browser
}

export default function Account() {
  const { me } = useAuth()
  const qc = useQueryClient()
  const [pw, setPw] = useState(false)
  const sessions = useQuery({ queryKey: ['my-sessions'], queryFn: () => api.get<SessionRow[]>('/auth/sessions') })
  const refresh = () => qc.invalidateQueries({ queryKey: ['my-sessions'] })
  const revoke = useMutation({
    mutationFn: (id: string) => api.del(`/auth/sessions/${id}`),
    onSuccess: () => { toast('Signed out that session'); refresh() },
    onError: toastError,
  })
  const revokeOthers = useMutation({
    mutationFn: () => api.post<{ revoked: number }>('/auth/sessions/revoke-others'),
    onSuccess: (r) => { toast(r.revoked ? `Signed out ${r.revoked} other session${r.revoked > 1 ? 's' : ''}` : 'No other sessions to sign out'); refresh() },
    onError: toastError,
  })
  const granted = me.access.filter((a) => a.granted)
  const missing = me.access.filter((a) => !a.granted)
  const others = (sessions.data ?? []).filter((s) => !s.current).length
  const roleBadge = <Badge tone="accent">{ROLE_LABEL[me.user.role] ?? me.user.role}</Badge>

  return (
    <div>
      <PageHeader
        title="My account"
        description="Your profile, what your role lets you do in SentinelX, and where you are signed in."
        actions={me.user.auth_provider === 'local' && <Button icon={<KeyRound className="size-4" />} onClick={() => setPw(true)}>Change password</Button>}
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <Card className="self-start p-4">
          <div className="flex items-center gap-3">
            <div className="flex size-11 items-center justify-center rounded-full bg-surface-3 text-[15px] font-semibold ring-1 ring-line">
              {me.user.display_name.split(/\s+/).map((p) => p[0]).join('').slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0">
              <div className="truncate text-[15px] font-semibold">{me.user.display_name}</div>
              <div className="truncate text-[12.5px] text-muted">{me.user.email}</div>
            </div>
          </div>
          <KeyValue
            className="mt-4"
            items={[
              ['Role', roleBadge],
              ['Organization', me.tenant?.name],
              ['Sign-in method', me.user.auth_provider === 'local' ? 'Email and password' : 'Single sign-on (Keycloak)'],
            ]}
          />
          <p className="mt-4 rounded-lg border border-line bg-bg-elev p-3 text-[12.5px] text-muted">{me.user.role_description}</p>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader
            icon={<ShieldCheck className="size-4" />}
            title="What you can do"
            subtitle="SentinelX checks these permissions on the server for every request — hidden buttons are only a convenience."
          />
          <div className="grid gap-x-6 gap-y-1 border-t border-line px-4 py-3 md:grid-cols-2">
            <div>
              <div className="mb-1.5 text-[11.5px] font-medium tracking-[0.04em] text-faint uppercase">Included in your role ({granted.length})</div>
              <ul className="space-y-1.5">
                {granted.map((a) => (
                  <li key={a.permission} className="flex items-start gap-2 text-[13px]">
                    <Check className="mt-0.5 size-3.5 shrink-0 text-ok" aria-label="Allowed" />
                    <span>{a.description}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="mb-1.5 text-[11.5px] font-medium tracking-[0.04em] text-faint uppercase">Not included ({missing.length})</div>
              {missing.length ? (
                <ul className="space-y-1.5">
                  {missing.map((a) => (
                    <li key={a.permission} className="flex items-start gap-2 text-[13px] text-faint">
                      <Minus className="mt-0.5 size-3.5 shrink-0" aria-label="Not allowed" />
                      <span>{a.description}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-[13px] text-muted">Nothing — your role has full access.</p>
              )}
              {missing.length > 0 && <p className="mt-3 text-[12px] text-muted">Need one of these? Ask an administrator of {me.tenant?.name ?? 'your organization'} to change your role.</p>}
            </div>
          </div>
        </Card>
      </div>

      <Card className="mt-4 overflow-hidden">
        <CardHeader
          icon={<Monitor className="size-4" />}
          title="Where you're signed in"
          subtitle="If you don't recognise a session, sign it out and change your password."
          action={<Button size="sm" icon={<LogOut className="size-3.5" />} disabled={!others} loading={revokeOthers.isPending} onClick={() => revokeOthers.mutate()}>Sign out all other sessions</Button>}
        />
        {sessions.error ? (
          <EmptyState title="Could not load sessions">{String((sessions.error as Error).message)}</EmptyState>
        ) : !sessions.data ? (
          <SkeletonRows rows={2} />
        ) : (
          <div className="overflow-x-auto">
            <table className="sx-table min-w-[640px] border-t border-line">
              <thead><tr><th>Device</th><th className="w-40">IP address</th><th className="w-40">Signed in</th><th className="w-40">Expires</th><th className="w-28" /></tr></thead>
              <tbody>
                {sessions.data.map((s) => (
                  <tr key={s.id}>
                    <td title={s.user_agent ?? undefined}>
                      <span className="font-medium">{deviceName(s.user_agent)}</span>
                      {s.current && <Badge tone="ok" className="ml-2">this browser</Badge>}
                    </td>
                    <td className="font-mono text-[12px] text-muted">{s.ip ?? '—'}</td>
                    <td className="text-muted" title={dateTime(s.created_at)}>{relTime(s.created_at)}</td>
                    <td className="text-muted">{dateTime(s.expires_at)}</td>
                    <td className="text-right">
                      {!s.current && <Button size="sm" variant="ghost" loading={revoke.isPending && revoke.variables === s.id} onClick={() => revoke.mutate(s.id)}>Sign out</Button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <PasswordModal open={pw} onClose={() => { setPw(false); refresh() }} />
    </div>
  )
}
