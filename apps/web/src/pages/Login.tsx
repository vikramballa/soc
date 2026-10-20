import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, KeyRound, ShieldCheck } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Button, Input, Label } from '../components/ui'
import { api, ApiError } from '../lib/api'

interface AuthConfig {
  local_login: boolean
  sso: boolean
  version: string
}

const SSO_ERRORS: Record<string, string> = {
  sso_failed: 'Single sign-on did not complete. Please try again.',
  sso_not_authorized: 'Your SSO account is not authorized for SentinelX. Ask an administrator to grant a SentinelX role.',
}

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [params] = useSearchParams()
  const nav = useNavigate()
  const qc = useQueryClient()
  const cfg = useQuery({ queryKey: ['auth-config'], queryFn: () => api.get<AuthConfig>('/auth/config') })
  const ssoError = params.get('error')

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.post('/auth/login', { email: email.trim(), password })
      await qc.invalidateQueries({ queryKey: ['me'] })
      const next = params.get('next')
      nav(next && next.startsWith('/') && !next.startsWith('//') ? next : '/', { replace: true })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Sign-in failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid min-h-full lg:grid-cols-[1.05fr_1fr]">
      <div className="relative hidden overflow-hidden border-r border-line bg-bg-elev lg:block">
        <div className="absolute inset-0 opacity-[0.55] [background-image:radial-gradient(var(--border)_1px,transparent_1px)] [background-size:22px_22px]" />
        <div className="absolute -top-40 -left-40 size-[520px] rounded-full bg-accent/10 blur-3xl" />
        <div className="relative flex h-full flex-col justify-between p-12">
          <div className="flex items-center gap-2.5">
            <img src="/favicon.svg" alt="" className="size-8" />
            <span className="text-[16px] font-semibold tracking-[-0.01em]">SentinelX</span>
          </div>
          <div className="max-w-md">
            <h1 className="text-[30px] leading-[1.15] font-semibold tracking-[-0.025em]">
              Thousands of security events.
              <br />
              <span className="text-muted">A handful of incidents that matter.</span>
            </h1>
            <ul className="mt-8 space-y-3.5 text-[13.5px] text-muted">
              {[
                'Correlates Wazuh, Suricata and Zeek telemetry into explainable incidents',
                'Every risk score shows exactly which factors produced it',
                'A local AI analyst that cites the evidence behind every claim',
              ].map((t) => (
                <li key={t} className="flex gap-2.5">
                  <ShieldCheck className="mt-0.5 size-4 shrink-0 text-accent" />
                  {t}
                </li>
              ))}
            </ul>
          </div>
          <p className="text-[12px] text-faint">Open-source · self-hosted · your telemetry never leaves your network</p>
        </div>
      </div>

      <div className="flex items-center justify-center p-6">
        <div className="animate-in w-full max-w-[360px]">
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <img src="/favicon.svg" alt="" className="size-8" />
            <span className="text-[16px] font-semibold">SentinelX</span>
          </div>
          <h2 className="text-[20px] font-semibold tracking-[-0.015em]">Sign in</h2>
          <p className="mt-1 text-[13px] text-muted">Use the account your administrator created for you.</p>

          {(error || ssoError) && (
            <div role="alert" className="mt-5 rounded-lg border border-danger/25 bg-danger/8 px-3 py-2.5 text-[13px] text-danger">
              {error ?? SSO_ERRORS[ssoError ?? ''] ?? 'Sign-in failed'}
            </div>
          )}

          {cfg.data?.local_login !== false && (
            <form onSubmit={submit} className="mt-6 space-y-4">
              <label className="block">
                <Label>Email</Label>
                <Input type="email" autoComplete="username" autoFocus required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />
              </label>
              <label className="block">
                <Label>Password</Label>
                <Input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
              </label>
              <Button type="submit" variant="primary" className="w-full" loading={busy}>
                Sign in <ArrowRight className="size-3.5" />
              </Button>
            </form>
          )}

          {cfg.data?.sso && (
            <>
              <div className="my-5 flex items-center gap-3 text-[12px] text-faint">
                <span className="h-px flex-1 bg-line" /> or <span className="h-px flex-1 bg-line" />
              </div>
              <a href="/api/v1/auth/oidc/login">
                <Button className="w-full" icon={<KeyRound className="size-4" />}>Continue with single sign-on</Button>
              </a>
            </>
          )}

          <p className="mt-8 text-[12px] text-faint">
            First run? The administrator password was printed by <code className="font-mono text-muted">sentinelx init</code> and saved to <code className="font-mono text-muted">.sentinelx-admin.txt</code>.
          </p>
          {cfg.data && <p className="mt-2 text-[11.5px] text-faint">SentinelX v{cfg.data.version}</p>}
        </div>
      </div>
    </div>
  )
}
