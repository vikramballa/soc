import { useQuery, useQueryClient } from '@tanstack/react-query'
import { createContext, useContext, useEffect, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { api, ApiError, setUnauthorizedHandler } from './api'
import type { Me } from './types'

interface AuthCtx {
  me: Me
  can: (perm: string) => boolean
  isSuperAdmin: boolean
}

const Ctx = createContext<AuthCtx | null>(null)

function useMeQuery() {
  return useQuery({
    queryKey: ['me'],
    queryFn: () => api.get<Me>('/auth/me'),
    retry: (n, e) => !(e instanceof ApiError && e.status === 401) && n < 2,
    staleTime: 60_000,
  })
}

export function AuthGate({ children, fallback }: { children: ReactNode; fallback: ReactNode }) {
  const q = useMeQuery()
  const nav = useNavigate()
  const loc = useLocation()
  const qc = useQueryClient()
  useEffect(() => {
    setUnauthorizedHandler(() => {
      qc.clear()
      if (!window.location.pathname.startsWith('/login')) nav(`/login?next=${encodeURIComponent(window.location.pathname)}`)
    })
  }, [nav, qc])
  useEffect(() => {
    if (q.error instanceof ApiError && q.error.status === 401 && !loc.pathname.startsWith('/login')) {
      nav(`/login?next=${encodeURIComponent(loc.pathname + loc.search)}`, { replace: true })
    }
  }, [q.error, nav, loc])
  if (!q.data) return <>{fallback}</>
  const perms = new Set(q.data.permissions)
  return (
    <Ctx.Provider value={{ me: q.data, can: (p) => perms.has(p), isSuperAdmin: perms.has('tenant:switch') }}>
      {children}
    </Ctx.Provider>
  )
}

/** Shows a clear "no access" page instead of a page full of failing requests. The API enforces the same
 * permissions server-side - this is only for a better experience, never for security. */
export function RequirePerm({ perm, children }: { perm: string; children: ReactNode }) {
  const { can, me } = useAuth()
  if (can(perm)) return <>{children}</>
  return (
    <div className="flex flex-col items-center justify-center px-6 py-20 text-center">
      <div className="mb-3 flex size-10 items-center justify-center rounded-xl border border-line bg-surface-2 text-faint">🔒</div>
      <h2 className="text-[15px] font-semibold">You don't have access to this page</h2>
      <p className="mt-1 max-w-md text-[13px] text-muted">
        Your role ({me.user.role.replace('_', ' ').toLowerCase()}) doesn't include this. Ask an administrator if you need it.
      </p>
    </div>
  )
}

export function useAuth(): AuthCtx {
  const c = useContext(Ctx)
  if (!c) throw new Error('useAuth outside AuthGate')
  return c
}
