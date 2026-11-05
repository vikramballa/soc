import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, KeyRound, LogOut, ShieldCheck, Smartphone } from 'lucide-react'
import { useEffect, useRef, useState, type FormEvent } from 'react'
import { api, setReauthHandler } from '../lib/api'
import type { Me } from '../lib/types'
import { Modal } from './overlay'
import { toast, toastError } from './toast'
import { Badge, Button, Input, Label, Mono } from './ui'

interface MfaStatus {
  enabled: boolean
  enabled_at: string | null
  recovery_codes_left: number
  required: boolean
  available: boolean
}

function groupSecret(secret: string) {
  return secret.match(/.{1,4}/g)?.join(' ') ?? secret
}

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <Button
      size="sm"
      variant="ghost"
      icon={done ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          setDone(true)
          setTimeout(() => setDone(false), 1500)
        } catch {
          toast('Copy failed - select the text instead', 'error')
        }
      }}
    >
      {done ? 'Copied' : label}
    </Button>
  )
}

/** Enrolment: new secret -> user adds it to an authenticator app -> confirms one code -> recovery codes. */
export function MfaSetup({ onDone }: { onDone: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null)
  const [code, setCode] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const [busy, setBusy] = useState(false)

  const start = async () => {
    setBusy(true)
    try {
      setSetup(await api.post<{ secret: string; otpauth_uri: string }>('/auth/mfa/setup'))
    } catch (e) {
      toastError(e)
    } finally {
      setBusy(false)
    }
  }
  const confirm = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      const r = await api.post<{ recovery_codes: string[] }>('/auth/mfa/enable', { code })
      setCodes(r.recovery_codes)
    } catch (err) {
      toastError(err)
    } finally {
      setBusy(false)
    }
  }

  if (codes) {
    return (
      <div className="space-y-3">
        <div className="flex items-center gap-2 text-[13px] font-medium text-ok">
          <ShieldCheck className="size-4" /> Two-step verification is on
        </div>
        <p className="text-[13px] text-muted">
          Save these recovery codes somewhere safe (a password manager). Each one signs you in once if you lose your phone.
        </p>
        <div className="grid grid-cols-2 gap-1.5 rounded-lg border border-line bg-bg-elev p-3 font-mono text-[13px]">
          {codes.map((c) => <span key={c}>{c}</span>)}
        </div>
        <div className="flex justify-between">
          <CopyButton text={codes.join('\n')} label="Copy codes" />
          <Button variant="primary" onClick={onDone}>I saved them</Button>
        </div>
      </div>
    )
  }
  if (!setup) {
    return (
      <div className="space-y-3">
        <p className="text-[13px] text-muted">
          After your password, SentinelX will also ask for a 6-digit code from an authenticator app (Google Authenticator,
          Microsoft Authenticator, 1Password, Bitwarden…). A stolen password alone is then not enough.
        </p>
        <Button variant="primary" icon={<Smartphone className="size-4" />} loading={busy} onClick={start}>
          Set up two-step verification
        </Button>
      </div>
    )
  }
  return (
    <form onSubmit={confirm} className="space-y-4">
      <ol className="list-decimal space-y-2 pl-4 text-[13px] text-muted">
        <li>
          In your authenticator app choose <span className="text-fg">Add account → Enter a setup key</span>, or{' '}
          <a className="text-accent hover:underline" href={setup.otpauth_uri}>open it directly</a> on this device.
        </li>
        <li>Use this key (time-based):</li>
      </ol>
      <div className="flex items-center justify-between gap-2 rounded-lg border border-line bg-bg-elev px-3 py-2">
        <Mono className="text-[14px] tracking-wide">{groupSecret(setup.secret)}</Mono>
        <CopyButton text={setup.secret} />
      </div>
      <label className="block">
        <Label>Enter the 6-digit code the app shows</Label>
        <Input inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} autoFocus />
      </label>
      <Button type="submit" variant="primary" loading={busy} disabled={code.length !== 6}>Turn on</Button>
    </form>
  )
}

/** Account menu entry: shows status, enrolment or switching it off. */
export function TwoStepModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const status = useQuery({ queryKey: ['mfa'], queryFn: () => api.get<MfaStatus>('/auth/mfa'), enabled: open })
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['mfa'] })
    qc.invalidateQueries({ queryKey: ['me'] })
  }
  const disable = async () => {
    setBusy(true)
    try {
      await api.post('/auth/mfa/disable', { password, code })
      toast('Two-step verification turned off')
      setPassword('')
      setCode('')
      refresh()
    } catch (e) {
      toastError(e)
    } finally {
      setBusy(false)
    }
  }
  const s = status.data
  return (
    <Modal open={open} onClose={onClose} title="Two-step verification" description="Protects your SentinelX account if your password leaks.">
      {!s ? (
        <p className="text-[13px] text-muted">Loading…</p>
      ) : !s.available ? (
        <p className="text-[13px] text-muted">Your account signs in through single sign-on; two-step verification is managed by your identity provider.</p>
      ) : s.enabled ? (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-[13px]">
            <Badge tone="ok"><ShieldCheck className="size-3" /> On</Badge>
            <span className="text-muted">{s.recovery_codes_left} recovery codes left</span>
          </div>
          {s.required ? (
            <p className="text-[13px] text-muted">Your role requires two-step verification, so it cannot be turned off.</p>
          ) : (
            <>
              <p className="text-[13px] text-muted">To turn it off, confirm your password and a current code.</p>
              <label className="block"><Label>Password</Label><Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" /></label>
              <label className="block"><Label>Code</Label><Input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value.trim())} autoComplete="one-time-code" /></label>
              <div className="flex justify-end"><Button variant="danger" loading={busy} disabled={!password || code.length < 6} onClick={disable}>Turn off</Button></div>
            </>
          )}
        </div>
      ) : (
        <MfaSetup onDone={() => { refresh(); onClose() }} />
      )}
    </Modal>
  )
}

/** Shown instead of the app when the user's role requires two-step verification and it is not set up yet. */
export function MfaEnrollmentScreen({ me }: { me: Me }) {
  const qc = useQueryClient()
  const logout = async () => {
    await api.post('/auth/logout').catch(() => undefined)
    qc.clear()
    window.location.assign('/login')
  }
  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <div className="animate-in w-full max-w-md rounded-2xl border border-line bg-surface p-6 shadow-xl">
        <div className="mb-4 flex items-center gap-2.5">
          <img src="/favicon.svg" alt="" className="size-7" />
          <span className="text-[15px] font-semibold">SentinelX</span>
        </div>
        <h1 className="text-[18px] font-semibold tracking-[-0.01em]">Set up two-step verification</h1>
        <p className="mt-1 mb-5 text-[13px] text-muted">
          Administrator accounts ({me.user.email}) must use a second factor before they can continue.
        </p>
        <MfaSetup onDone={() => qc.invalidateQueries({ queryKey: ['me'] })} />
        <button onClick={logout} className="mt-6 flex items-center gap-1.5 text-[12.5px] text-faint hover:text-fg">
          <LogOut className="size-3.5" /> Sign out
        </button>
      </div>
    </div>
  )
}

/** Answers the server's "confirm your password" challenge for sensitive changes and retries the request. */
export function ReauthHost({ me }: { me: Me }) {
  const [open, setOpen] = useState(false)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const pending = useRef<((ok: boolean) => void) | null>(null)

  useEffect(() => {
    setReauthHandler(
      () =>
        new Promise<boolean>((resolve) => {
          pending.current = resolve
          setPassword('')
          setCode('')
          setError(null)
          setOpen(true)
        }),
    )
    return () => setReauthHandler(null)
  }, [])

  const finish = (ok: boolean) => {
    setOpen(false)
    pending.current?.(ok)
    pending.current = null
  }
  const submit = async (e?: FormEvent) => {
    e?.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.post('/auth/reauth', { password, code: me.user.mfa_enabled ? code : undefined })
      finish(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Confirmation failed')
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal
      open={open}
      onClose={() => finish(false)}
      size="sm"
      title="Confirm it's you"
      description="This change affects how SentinelX protects your organization. Re-enter your password to continue."
      footer={
        <>
          <Button variant="ghost" onClick={() => finish(false)}>Cancel</Button>
          <Button variant="primary" icon={<KeyRound className="size-3.5" />} loading={busy} disabled={!password || (me.user.mfa_enabled && code.length < 6)} onClick={() => submit()}>
            Confirm
          </Button>
        </>
      }
    >
      <form onSubmit={submit} className="space-y-3">
        {error && <div role="alert" className="rounded-lg border border-danger/25 bg-danger/8 px-3 py-2 text-[12.5px] text-danger">{error}</div>}
        <label className="block"><Label>Password</Label><Input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" /></label>
        {me.user.mfa_enabled && (
          <label className="block"><Label>Two-step verification code</Label><Input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value.trim())} autoComplete="one-time-code" /></label>
        )}
        <button type="submit" hidden />
      </form>
    </Modal>
  )
}
