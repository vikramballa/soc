/** Evidence graph: detections in the middle ring, the entities they involve around them. */
import clsx from 'clsx'
import { useMemo, useState } from 'react'

interface Node {
  id: string
  kind: string
  label: string
  severity?: number
  criticality?: number
  threat?: boolean
  alerts?: number
}
interface Edge {
  source: string
  target: string
}

const KIND_STYLE: Record<string, { fill: string; label: string }> = {
  host: { fill: 'var(--accent)', label: 'Host' },
  user: { fill: 'var(--sev-low)', label: 'User' },
  ip: { fill: 'var(--text-muted)', label: 'IP address' },
  domain: { fill: 'var(--ok)', label: 'Domain' },
  hash: { fill: 'var(--sev-medium)', label: 'File hash' },
  alert: { fill: 'var(--sev-high)', label: 'Detection' },
}

export function EvidenceGraph({ nodes, edges }: { nodes: Node[]; edges: Edge[] }) {
  const [hover, setHover] = useState<string | null>(null)
  const W = 760
  const H = 460
  const layout = useMemo(() => {
    const alerts = nodes.filter((n) => n.kind === 'alert')
    const ents = nodes.filter((n) => n.kind !== 'alert')
    const pos = new Map<string, { x: number; y: number }>()
    const cx = W / 2
    const cy = H / 2
    alerts.forEach((n, i) => {
      const a = (i / Math.max(1, alerts.length)) * Math.PI * 2 - Math.PI / 2
      const r = alerts.length === 1 ? 0 : 95
      pos.set(n.id, { x: cx + Math.cos(a) * r, y: cy + Math.sin(a) * r * 0.8 })
    })
    // place entities near the mean angle of the detections that reference them
    const order = [...ents].sort((a, b) => {
      const ka = Object.keys(KIND_STYLE).indexOf(a.kind)
      const kb = Object.keys(KIND_STYLE).indexOf(b.kind)
      return ka - kb
    })
    order.forEach((n, i) => {
      const a = (i / Math.max(1, order.length)) * Math.PI * 2 - Math.PI / 2
      pos.set(n.id, { x: cx + Math.cos(a) * 300, y: cy + Math.sin(a) * 185 })
    })
    return pos
  }, [nodes])

  const linked = useMemo(() => {
    if (!hover) return null
    const s = new Set([hover])
    edges.forEach((e) => {
      if (e.source === hover) s.add(e.target)
      if (e.target === hover) s.add(e.source)
    })
    return s
  }, [hover, edges])

  if (!nodes.length) return <p className="py-10 text-center text-[13px] text-faint">No entities to graph.</p>
  return (
    <div>
      <div className="overflow-x-auto">
        <svg viewBox={`0 0 ${W} ${H}`} className="mx-auto w-full min-w-[620px]" role="img" aria-label="Evidence relationship graph">
          {edges.map((e, i) => {
            const a = layout.get(e.source)
            const b = layout.get(e.target)
            if (!a || !b) return null
            const on = !linked || (linked.has(e.source) && linked.has(e.target))
            return (
              <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="var(--border-strong)" strokeWidth={on && linked ? 1.6 : 1}
                opacity={on ? 0.9 : 0.15} className="transition-opacity duration-150" />
            )
          })}
          {nodes.map((n) => {
            const p = layout.get(n.id)
            if (!p) return null
            const st = KIND_STYLE[n.kind] ?? KIND_STYLE.ip
            const on = !linked || linked.has(n.id)
            const r = n.kind === 'alert' ? 7 : 6 + Math.min(4, n.alerts ?? 0)
            const label = n.label.length > 34 ? n.label.slice(0, 32) + '…' : n.label
            return (
              <g key={n.id} opacity={on ? 1 : 0.2} className="cursor-default transition-opacity duration-150"
                onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)}>
                <title>{`${st.label}: ${n.label}`}</title>
                {n.threat && <circle cx={p.x} cy={p.y} r={r + 5} fill="none" stroke="var(--sev-critical)" strokeWidth="1.5" strokeDasharray="3 2" />}
                {n.kind === 'alert' ? (
                  <rect x={p.x - r} y={p.y - r} width={r * 2} height={r * 2} rx="3" fill={st.fill} stroke="var(--surface)" strokeWidth="2" />
                ) : (
                  <circle cx={p.x} cy={p.y} r={r} fill={st.fill} stroke="var(--surface)" strokeWidth="2" />
                )}
                <text x={p.x} y={p.y + r + 13} textAnchor="middle" className={clsx('text-[11px]', n.kind === 'alert' ? 'fill-[var(--text)]' : 'fill-[var(--text-muted)]')}
                  style={{ fontFamily: n.kind === 'alert' ? undefined : 'var(--font-mono)' }}>
                  {label}
                </text>
              </g>
            )
          })}
        </svg>
      </div>
      <div className="mt-2 flex flex-wrap items-center justify-center gap-4 text-[12px] text-muted">
        {Object.entries(KIND_STYLE).map(([k, v]) => (
          <span key={k} className="flex items-center gap-1.5">
            <span className={clsx('inline-block size-2.5', k === 'alert' ? 'rounded-[2px]' : 'rounded-full')} style={{ background: v.fill }} />
            {v.label}
          </span>
        ))}
        <span className="flex items-center gap-1.5"><span className="inline-block size-2.5 rounded-full border border-dashed border-critical" />Threat-intel match</span>
      </div>
      <p className="mt-1 text-center text-[11.5px] text-faint">Hover a node to highlight what it is connected to.</p>
    </div>
  )
}
