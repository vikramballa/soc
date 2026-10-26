import { useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Activity,
  Bell,
  BookOpenCheck,
  Bot,
  Boxes,
  BrainCircuit,
  ChevronsUpDown,
  FileText,
  Globe2,
  Grid3x3,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Plug,
  Search,
  Settings,
  ShieldAlert,
  Sun,
  UserRound,
  Users,
} from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import { api, setTenantOverride } from '../lib/api'
import { useAuth } from '../lib/auth'
import { ROLE_LABEL } from '../lib/format'
import { CommandPalette } from './CommandPalette'
import { Modal } from './overlay'
import { toast, toastError } from './toast'
import { Badge, Button, Input, Kbd, Label } from './ui'

interface NavItem {
  to: string
  label: string
  icon: ReactNode
  perm?: string
}

const NAV: { group: string; items: NavItem[] }[] = [
  { group: '', items: [{ to: '/', label: 'Dashboard', icon: <LayoutDashboard /> }] },
  {
    group: 'Investigate',
    items: [
      { to: '/incidents', label: 'Incidents', icon: <ShieldAlert /> },
      { to: '/alerts', label: 'Alerts', icon: <Bell /> },
      { to: '/events', label: 'Events', icon: <Activity />, perm: 'event:read' },
      { to: '/ai', label: 'AI Analyst', icon: <Bot /> },
    ],
  },
  {
    group: 'Context',
    items: [
      { to: '/assets', label: 'Assets', icon: <Boxes /> },
      { to: '/users', label: 'Users', icon: <Users /> },
      { to: '/threat-intel', label: 'Threat Intel', icon: <Globe2 /> },
      { to: '/mitre', label: 'MITRE ATT&CK', icon: <Grid3x3 /> },
    ],
  },
  {
    group: 'Detection',
    items: [
      { to: '/rules', label: 'Detection Rules', icon: <BookOpenCheck /> },
      { to: '/ml', label: 'ML Analytics', icon: <BrainCircuit /> },
    ],
  },
  {
    group: 'Manage',
    items: [
      { to: '/reports', label: 'Reports', icon: <FileText />, perm: 'report:generate' },
      { to: '/integrations', label: 'Integrations', icon: <Plug /> },
      { to: '/admin', label: 'Administration', icon: <Settings />, perm: 'admin:manage' },
    ],
  },
]

interface Health {
  status: string
  worker?: { running: boolean; queued_jobs: number }
  ai_analyst?: string
  core_detection?: string
}

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => document.documentElement.getAttribute('data-theme') || 'dark')
  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    document.documentElement.setAttribute('data-theme', next)
    try {
      localStorage.setItem('sx-theme', next)
    } catch {
      /* ignore */
    }
    setTheme(next)
  }
  return [theme, toggle]
}

function StatusPill() {
  const { data } = useQuery({
    queryKey: ['health'],
    queryFn: async () => (await fetch('/health')).json() as Promise<Health>,
    refetchInterval: 30_000,
  })
  const core = data?.worker?.running
  const ai = data?.ai_analyst === 'available'
  return (
    <div className="hidden items-center gap-3 rounded-lg border border-line bg-bg-elev px-2.5 py-1 text-[12px] md:flex">
      <span className="flex items-center gap-1.5" title={core ? 'Ingestion, detection and correlation are running' : 'Background worker is not running — events will queue'}>
        <span className={clsx('size-1.5 rounded-full', data ? (core ? 'bg-ok' : 'pulse-dot bg-warn') : 'bg-faint')} />
        <span className="text-muted">Core detection</span>
        <span className={core ? 'text-fg' : 'text-warn'}>{data ? (core ? 'operational' : 'degraded') : '…'}</span>
      </span>
      <span className="h-3 w-px bg-line" />
      <span className="flex items-center gap-1.5" title="Local Ollama model used by the AI analyst. Detection never depends on it.">
        <span className={clsx('size-1.5 rounded-full', ai ? 'bg-ai' : 'bg-faint')} />
        <span className="text-muted">AI Analyst</span>
        <span className={ai ? 'text-fg' : 'text-faint'}>{data ? (ai ? 'available' : 'unavailable') : '…'}</span>
      </span>
    </div>
  )
}

function OrgSwitcher() {
  const { me, isSuperAdmin } = useAuth()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const qc = useQueryClient()
  const nav = useNavigate()
  useEffect(() => {
    const h = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false)
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])
  const switchTo = (id: string) => {
    setTenantOverride(id === me.home_tenant_id ? null : id)
    setOpen(false)
    qc.clear()
    nav('/')
    qc.invalidateQueries()
  }
  const t = me.tenant
  return (
    <div ref={ref} className="relative">
      <button
        disabled={!isSuperAdmin}
        onClick={() => setOpen((o) => !o)}
        className="press flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-left enabled:hover:bg-surface-2"
      >
        <div className="flex size-7 shrink-0 items-center justify-center rounded-md bg-accent-soft text-[12px] font-semibold text-accent-strong">
          {t?.name.slice(0, 1).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[13px] font-medium">{t?.name}</div>
          <div className="truncate text-[11.5px] text-faint">{t?.demo ? 'Synthetic demo data' : 'Organization'}</div>
        </div>
        {isSuperAdmin && <ChevronsUpDown className="size-3.5 text-faint" />}
      </button>
      {open && (
        <div className="animate-modal absolute top-full left-0 z-40 mt-1 w-full origin-top rounded-xl border border-line bg-surface p-1 shadow-2xl">
          <div className="px-2 py-1.5 text-[11px] font-medium tracking-wide text-faint uppercase">Organizations</div>
          {me.tenants.map((o) => (
            <button
              key={o.id}
              onClick={() => switchTo(o.id)}
              className={clsx('flex w-full items-center justify-between gap-2 rounded-lg px-2 py-1.5 text-left text-[13px] hover:bg-surface-2', o.id === t?.id && 'text-accent-strong')}
            >
              <span className="truncate">{o.name}</span>
              {o.demo && <Badge tone="ai">demo</Badge>}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export function PasswordModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    setBusy(true)
    try {
      await api.post('/auth/password', { current_password: cur, new_password: next })
      toast('Password changed. Other sessions were signed out.')
      onClose()
    } catch (e) {
      toastError(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Change password"
      description="Use at least 12 characters mixing letters and digits."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={busy} disabled={!cur || next.length < 12} onClick={submit}>Change password</Button>
        </>
      }
    >
      <div className="space-y-3">
        <label className="block"><Label>Current password</Label><Input type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" /></label>
        <label className="block"><Label>New password</Label><Input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" /></label>
      </div>
    </Modal>
  )
}

function UserMenu() {
  const { me } = useAuth()
  const [open, setOpen] = useState(false)
  const [pw, setPw] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const qc = useQueryClient()
  const nav = useNavigate()
  useEffect(() => {
    const h = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false)
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])
  const logout = async () => {
    try {
      await api.post('/auth/logout')
    } finally {
      setTenantOverride(null)
      qc.clear()
      nav('/login')
    }
  }
  const initials = me.user.display_name.split(/\s+/).map((p) => p[0]).join('').slice(0, 2).toUpperCase()
  return (
    <div ref={ref} className="relative">
      <button onClick={() => setOpen((o) => !o)} className="press flex size-8 items-center justify-center rounded-full bg-surface-3 text-[12px] font-semibold text-fg ring-1 ring-line" aria-label="Account menu">
        {initials}
      </button>
      {open && (
        <div className="animate-modal absolute top-full right-0 z-40 mt-1.5 w-64 origin-top-right rounded-xl border border-line bg-surface p-1 shadow-2xl">
          <div className="px-2.5 py-2">
            <div className="truncate text-[13px] font-medium">{me.user.display_name}</div>
            <div className="truncate text-[12px] text-faint">{me.user.email}</div>
            <Badge tone="accent" className="mt-1.5">{ROLE_LABEL[me.user.role] ?? me.user.role}</Badge>
          </div>
          <div className="my-1 h-px bg-line" />
          <button onClick={() => { setOpen(false); nav('/account') }} className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-[13px] text-muted hover:bg-surface-2 hover:text-fg">
            <UserRound className="size-4" /> My account &amp; access
          </button>
          {me.user.auth_provider === 'local' && (
            <button onClick={() => { setPw(true); setOpen(false) }} className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-[13px] text-muted hover:bg-surface-2 hover:text-fg">
              <KeyRound className="size-4" /> Change password
            </button>
          )}
          <button onClick={logout} className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-[13px] text-muted hover:bg-surface-2 hover:text-fg">
            <LogOut className="size-4" /> Sign out
          </button>
        </div>
      )}
      <PasswordModal open={pw} onClose={() => setPw(false)} />
    </div>
  )
}

export function Layout({ children }: { children: ReactNode }) {
  const { can, me, isSuperAdmin } = useAuth()
  const [theme, toggleTheme] = useTheme()
  const [palette, setPalette] = useState(false)
  const [mobileNav, setMobileNav] = useState(false)
  const loc = useLocation()
  useEffect(() => setMobileNav(false), [loc.pathname])
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPalette((p) => !p)
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])

  const sidebar = (
    <nav className="flex h-full flex-col">
      <div className="flex h-14 items-center gap-2.5 px-4">
        <img src="/favicon.svg" alt="" className="size-7" />
        <div className="leading-tight">
          <div className="text-[14.5px] font-semibold tracking-[-0.01em]">SentinelX</div>
          <div className="text-[11px] text-faint">Security operations</div>
        </div>
      </div>
      <div className="px-2 pb-2"><OrgSwitcher /></div>
      <div className="flex-1 overflow-y-auto px-2 pb-4">
        {NAV.map((g) => {
          const items = g.items.filter((i) => !i.perm || can(i.perm))
          if (!items.length) return null
          return (
            <div key={g.group} className="mt-3 first:mt-1">
              {g.group && <div className="px-2.5 pb-1 text-[11px] font-medium tracking-[0.04em] text-faint uppercase">{g.group}</div>}
              {items.map((i) => (
                <NavLink
                  key={i.to}
                  to={i.to}
                  end={i.to === '/'}
                  className={({ isActive }) =>
                    clsx(
                      'group flex h-8 items-center gap-2.5 rounded-lg px-2.5 text-[13px] transition-colors duration-150 [&>svg]:size-4 [&>svg]:shrink-0',
                      isActive ? 'bg-surface-2 font-medium text-fg [&>svg]:text-accent' : 'text-muted hover:bg-surface-2/60 hover:text-fg [&>svg]:text-faint',
                    )
                  }
                >
                  {i.icon}
                  {i.label}
                </NavLink>
              ))}
            </div>
          )
        })}
      </div>
      <NavLink to="/account" className="block border-t border-line px-4 py-3 text-[11.5px] text-faint hover:bg-surface-2/60" title="Your account, role and access">
        Signed in as <span className="text-muted">{me.user.display_name}</span>
        <span className="block text-faint">{ROLE_LABEL[me.user.role] ?? me.user.role} · view my access</span>
      </NavLink>
    </nav>
  )

  return (
    <div className="flex h-full">
      <aside className="hidden w-[232px] shrink-0 border-r border-line bg-bg-elev lg:block">{sidebar}</aside>
      {mobileNav && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="animate-overlay absolute inset-0 bg-[var(--overlay)]" onClick={() => setMobileNav(false)} />
          <aside className="animate-drawer absolute inset-y-0 left-0 w-[260px] border-r border-line bg-bg-elev">{sidebar}</aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-line bg-bg/80 px-4 backdrop-blur lg:px-6">
          <button className="lg:hidden" onClick={() => setMobileNav(true)} aria-label="Open navigation">
            <Menu className="size-5 text-muted" />
          </button>
          <button
            onClick={() => setPalette(true)}
            className="press flex h-8.5 w-full max-w-[420px] items-center gap-2 rounded-lg border border-line bg-bg-elev px-2.5 text-[13px] text-faint hover:border-line-strong"
          >
            <Search className="size-4" />
            <span className="flex-1 text-left">Search incidents, hosts, IPs, pages…</span>
            <Kbd>⌘</Kbd>
            <Kbd>K</Kbd>
          </button>
          <div className="ml-auto flex items-center gap-2.5">
            <StatusPill />
            <button onClick={toggleTheme} className="press flex size-8 items-center justify-center rounded-lg text-muted hover:bg-surface-2 hover:text-fg" aria-label="Toggle theme" title="Toggle light / dark">
              {theme === 'dark' ? <Sun className="size-4" /> : <Moon className="size-4" />}
            </button>
            <UserMenu />
          </div>
        </header>
        {me.tenant?.demo && (
          <div className="border-b border-ai/20 bg-ai-soft px-6 py-1.5 text-[12px] text-ai">
            You are viewing the <b>Demo Lab</b> — every event here is synthetic and clearly labelled.
            {isSuperAdmin ? ' Switch organization in the sidebar to see your real data.' : ' It is safe to explore and practise here.'}
          </div>
        )}
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1480px] px-4 py-6 lg:px-8">{children}</div>
        </main>
      </div>
      <CommandPalette open={palette} onClose={() => setPalette(false)} />
    </div>
  )
}
