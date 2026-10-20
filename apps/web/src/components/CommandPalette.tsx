/** ⌘K palette. Opened by keyboard many times a day -> deliberately no open/close animation. */
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { ArrowRight, Globe2, Hash, Monitor, Search, ShieldAlert } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import type { IncidentSummary, Page } from '../lib/types'
import { SeverityBadge } from './security'

const PAGES = [
  ['Dashboard', '/'], ['Incidents', '/incidents'], ['Alerts', '/alerts'], ['Events', '/events'],
  ['AI Analyst', '/ai'], ['Assets', '/assets'], ['Users', '/users'], ['Threat Intel', '/threat-intel'],
  ['MITRE ATT&CK', '/mitre'], ['Detection Rules', '/rules'], ['ML Analytics', '/ml'], ['Reports', '/reports'],
  ['Integrations', '/integrations'], ['Administration', '/admin'],
] as const

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$/i
const HASH_RE = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i
const DOMAIN_RE = /^([a-z0-9-]+\.)+[a-z]{2,}$/i

interface Item {
  key: string
  icon: React.ReactNode
  label: React.ReactNode
  hint?: string
  go: () => void
}

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)
  const nav = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (open) {
      setQ('')
      setIdx(0)
      setTimeout(() => inputRef.current?.focus(), 0)
    }
  }, [open])

  const term = q.trim()
  const incidents = useQuery({
    queryKey: ['palette-incidents', term],
    queryFn: () => api.get<Page<IncidentSummary>>('/incidents', { q: term, limit: 5, status: undefined }),
    enabled: open && term.length >= 2,
  })

  const items: Item[] = useMemo(() => {
    const go = (path: string) => () => {
      nav(path)
      onClose()
    }
    const out: Item[] = []
    if (term) {
      if (IP_RE.test(term) || HASH_RE.test(term) || DOMAIN_RE.test(term)) {
        out.push({ key: 'ti', icon: <Globe2 />, label: <>Look up <b>{term}</b> in threat intelligence</>, go: go(`/threat-intel?q=${encodeURIComponent(term)}`) })
        out.push({ key: 'ev', icon: <Search />, label: <>Search events for <b>{term}</b></>, go: go(`/events?${IP_RE.test(term) ? 'ip' : 'q'}=${encodeURIComponent(term)}`) })
      } else {
        out.push({ key: 'host', icon: <Monitor />, label: <>Events on host <b>{term}</b></>, go: go(`/events?host=${encodeURIComponent(term)}`) })
        out.push({ key: 'evq', icon: <Search />, label: <>Search events containing <b>{term}</b></>, go: go(`/events?q=${encodeURIComponent(term)}`) })
      }
      for (const inc of incidents.data?.items ?? []) {
        out.unshift({
          key: inc.id,
          icon: <ShieldAlert />,
          label: (
            <span className="flex min-w-0 items-center gap-2">
              <span className="font-mono text-[11.5px] text-faint">INC-{inc.number}</span>
              <span className="truncate">{inc.title}</span>
              <SeverityBadge severity={inc.severity} size="sm" />
            </span>
          ),
          go: go(`/incidents/${inc.id}`),
        })
      }
    }
    for (const [label, path] of PAGES) {
      if (!term || label.toLowerCase().includes(term.toLowerCase()))
        out.push({ key: path, icon: <Hash />, label, hint: 'Page', go: go(path) })
    }
    return out
  }, [term, incidents.data, nav, onClose])

  useEffect(() => setIdx(0), [term])
  if (!open) return null

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setIdx((i) => Math.min(items.length - 1, i + 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setIdx((i) => Math.max(0, i - 1))
    } else if (e.key === 'Enter') {
      items[idx]?.go()
    } else if (e.key === 'Escape') {
      onClose()
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-[55] flex items-start justify-center p-4 pt-[14vh]" onKeyDown={onKey}>
      <div className="fixed inset-0 bg-[var(--overlay)]" onClick={onClose} />
      <div className="relative w-full max-w-xl overflow-hidden rounded-2xl border border-line bg-surface shadow-2xl">
        <div className="flex items-center gap-2.5 border-b border-line px-4">
          <Search className="size-4 text-faint" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Type an incident number, title, host, IP, domain or page…"
            className="h-12 flex-1 bg-transparent text-[14px] outline-none placeholder:text-faint"
          />
        </div>
        <div className="max-h-[50vh] overflow-y-auto p-1.5">
          {items.map((it, i) => (
            <button
              key={it.key}
              onMouseEnter={() => setIdx(i)}
              onClick={it.go}
              className={clsx(
                'flex w-full items-center gap-3 rounded-lg px-2.5 py-2 text-left text-[13px] [&>svg]:size-4 [&>svg]:shrink-0 [&>svg]:text-faint',
                i === idx ? 'bg-surface-2 text-fg' : 'text-muted',
              )}
            >
              {it.icon}
              <span className="min-w-0 flex-1 truncate">{it.label}</span>
              {it.hint && <span className="text-[11.5px] text-faint">{it.hint}</span>}
              {i === idx && <ArrowRight className="size-3.5 text-faint" />}
            </button>
          ))}
          {!items.length && <div className="px-3 py-6 text-center text-[13px] text-faint">No matches</div>}
        </div>
      </div>
    </div>,
    document.body,
  )
}
