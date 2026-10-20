/** Small typed fetch wrapper. Cookie session + CSRF header; super-admins may target another tenant. */

export class ApiError extends Error {
  status: number
  details: unknown
  constructor(status: number, message: string, details?: unknown) {
    super(message)
    this.status = status
    this.details = details
  }
}

const TENANT_KEY = 'sx-tenant'

function getTenantOverride(): string | null {
  try {
    return localStorage.getItem(TENANT_KEY)
  } catch {
    return null
  }
}

export function setTenantOverride(id: string | null) {
  try {
    if (id) localStorage.setItem(TENANT_KEY, id)
    else localStorage.removeItem(TENANT_KEY)
  } catch {
    /* private mode - the switch simply won't persist */
  }
}

type Query = Record<string, string | number | boolean | null | undefined>

function qs(params?: Query): string {
  if (!params) return ''
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, String(v))
  }
  const s = sp.toString()
  return s ? `?${s}` : ''
}

let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

async function request<T>(method: string, path: string, body?: unknown, params?: Query): Promise<T> {
  const headers: Record<string, string> = { 'X-Requested-With': 'SentinelX', Accept: 'application/json' }
  const tenant = getTenantOverride()
  if (tenant) headers['X-SentinelX-Tenant'] = tenant
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  let res: Response
  try {
    res = await fetch(`/api/v1${path}${qs(params)}`, {
      method,
      headers,
      credentials: 'same-origin',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new ApiError(0, 'Cannot reach the SentinelX server. Is it running?')
  }
  if (res.status === 204) return undefined as T
  const text = await res.text()
  let data: unknown = undefined
  try {
    data = text ? JSON.parse(text) : undefined
  } catch {
    data = text
  }
  if (!res.ok) {
    if (res.status === 401 && !path.startsWith('/auth/login')) onUnauthorized?.()
    const detail = String((data as { detail?: string })?.detail ?? '')
    if (tenant && ((res.status === 403 && detail.includes('organization')) || (res.status === 404 && detail === 'Organization not found'))) {
      // the selected organization no longer exists or is not accessible: fall back to the home organization
      setTenantOverride(null)
      window.location.assign('/')
    }
    const d = data as { detail?: unknown; errors?: { field: string; message: string }[] } | undefined
    let msg = typeof d?.detail === 'string' ? d.detail : `Request failed (${res.status})`
    if (d?.errors?.length) msg = d.errors.map((e) => `${e.field || 'input'}: ${e.message}`).join('; ')
    throw new ApiError(res.status, msg, data)
  }
  return data as T
}

export const api = {
  get: <T>(path: string, params?: Query) => request<T>('GET', path, undefined, params),
  post: <T>(path: string, body?: unknown, params?: Query) => request<T>('POST', path, body ?? {}, params),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
  put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
  del: <T>(path: string) => request<T>('DELETE', path),
}

export function apiUrl(path: string, params?: Query) {
  return `/api/v1${path}${qs(params)}`
}
