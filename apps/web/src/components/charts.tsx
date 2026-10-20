/** Lightweight SVG charts: single-series, one hue, recessive axes, hover tooltips on every mark. */
import clsx from 'clsx'
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { compact, num } from '../lib/format'

interface Point {
  label: string
  value: number
  tip?: string
}

function niceMax(v: number) {
  if (v <= 4) return 4
  const p = 10 ** Math.floor(Math.log10(v))
  const n = v / p
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p
}

function Tooltip({ x, y, children }: { x: number; y: number; children: ReactNode }) {
  return (
    <div
      className="pointer-events-none absolute z-10 -translate-x-1/2 -translate-y-full rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[12px] whitespace-nowrap shadow-xl"
      style={{ left: x, top: y - 8 }}
    >
      {children}
    </div>
  )
}

/** Vertical bars (e.g. incidents per day). Bars anchored to the baseline, rounded data-end, 2px gaps. */
export function BarChart({
  data,
  height = 140,
  unit,
  className,
}: {
  data: Point[]
  height?: number
  unit: string
  className?: string
}) {
  const [hover, setHover] = useState<number | null>(null)
  const max = niceMax(Math.max(1, ...data.map((d) => d.value)))
  const ticks = [0, max / 2, max]
  const padL = 28
  const padB = 20
  const W = 100 // percentage-based x layout
  return (
    <div className={clsx('relative', className)} style={{ height }}>
      <svg className="absolute inset-0 h-full w-full overflow-visible" role="img" aria-label={`Bar chart of ${unit}`}>
        {ticks.map((t) => {
          const y = (1 - t / max) * (height - padB)
          return (
            <g key={t}>
              <line x1={padL} x2="100%" y1={y} y2={y} stroke="var(--border)" strokeDasharray={t === 0 ? undefined : '2 4'} />
              <text x={padL - 6} y={y + 3.5} textAnchor="end" className="fill-[var(--text-faint)] text-[10.5px] tnum">
                {compact(t)}
              </text>
            </g>
          )
        })}
      </svg>
      <div className="absolute flex items-end" style={{ left: padL, right: 0, top: 0, bottom: padB }}>
        {data.map((d, i) => {
          const h = (d.value / max) * 100
          return (
            <div
              key={i}
              className="group relative flex h-full flex-1 items-end justify-center px-[1px]"
              style={{ width: `${W / data.length}%` }}
              onMouseEnter={() => setHover(i)}
              onMouseLeave={() => setHover(null)}
            >
              <div
                className={clsx('w-full max-w-[28px] rounded-t-[4px] transition-colors duration-150', hover === i ? 'bg-accent-strong' : 'bg-accent/75')}
                style={{ height: d.value ? `max(${h}%, 2px)` : 0 }}
              />
              {hover === i && (
                <div className="pointer-events-none absolute bottom-full left-1/2 z-10 mb-1 -translate-x-1/2 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[12px] whitespace-nowrap shadow-xl">
                  <div className="text-faint">{d.tip ?? d.label}</div>
                  <div className="tnum font-medium">{num(d.value)} {unit}</div>
                </div>
              )}
            </div>
          )
        })}
      </div>
      <div className="absolute right-0 bottom-0 flex justify-between text-[10.5px] text-faint" style={{ left: padL }}>
        <span>{data[0]?.label}</span>
        <span>{data[Math.floor(data.length / 2)]?.label}</span>
        <span>{data[data.length - 1]?.label}</span>
      </div>
    </div>
  )
}

/** Area/line with crosshair + tooltip (e.g. events per hour). 2px line, faint fill. */
export function AreaChart({ data, height = 120, unit }: { data: Point[]; height?: number; unit: string }) {
  const ref = useRef<HTMLDivElement>(null)
  const [hover, setHover] = useState<number | null>(null)
  const [width, setWidth] = useState(600)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(([e]) => setWidth(e.contentRect.width))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  const max = niceMax(Math.max(1, ...data.map((d) => d.value)))
  const padB = 18
  const h = height - padB
  const pts = useMemo(
    () => data.map((d, i) => [data.length === 1 ? width / 2 : (i / (data.length - 1)) * width, h - (d.value / max) * h] as const),
    [data, width, h, max],
  )
  const line = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join('')
  const area = pts.length ? `${line}L${pts[pts.length - 1][0]},${h}L${pts[0][0]},${h}Z` : ''
  const onMove = (e: React.MouseEvent) => {
    const r = ref.current!.getBoundingClientRect()
    const x = e.clientX - r.left
    const i = Math.round((x / r.width) * (data.length - 1))
    setHover(Math.max(0, Math.min(data.length - 1, i)))
  }
  if (!data.length) return <div style={{ height }} className="flex items-center justify-center text-[12px] text-faint">No data in this window</div>
  return (
    <div
      ref={ref}
      className="relative"
      style={{ height }}
      onMouseMove={onMove}
      onMouseLeave={() => setHover(null)}
    >
      <svg width="100%" height={height} className="overflow-visible" role="img" aria-label={`Trend of ${unit}`}>
        <defs>
          <linearGradient id="sx-area" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.22" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <line x1="0" x2="100%" y1={h} y2={h} stroke="var(--border)" />
        <line x1="0" x2="100%" y1={h / 2} y2={h / 2} stroke="var(--border)" strokeDasharray="2 4" />
        <text x="0" y={h / 2 - 4} className="fill-[var(--text-faint)] text-[10.5px] tnum">{compact(max / 2)}</text>
        <path d={area} fill="url(#sx-area)" />
        <path d={line} fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
        {hover != null && pts[hover] && (
          <>
            <line x1={pts[hover][0]} x2={pts[hover][0]} y1={0} y2={h} stroke="var(--border-strong)" />
            <circle cx={pts[hover][0]} cy={pts[hover][1]} r="4.5" fill="var(--accent)" stroke="var(--surface)" strokeWidth="2" />
          </>
        )}
      </svg>
      <div className="absolute right-0 bottom-0 left-0 flex justify-between text-[10.5px] text-faint">
        <span>{data[0]?.label}</span>
        <span>{data[data.length - 1]?.label}</span>
      </div>
      {hover != null && pts[hover] && (
        <Tooltip x={pts[hover][0]} y={pts[hover][1]}>
          <div className="text-faint">{data[hover].tip ?? data[hover].label}</div>
          <div className="tnum font-medium">{num(data[hover].value)} {unit}</div>
        </Tooltip>
      )}
    </div>
  )
}

/** Horizontal magnitude bars with values as text (funnels, top-N, risk contributors). */
export function HBar({
  value,
  max,
  className,
  tone = 'accent',
}: {
  value: number
  max: number
  className?: string
  tone?: 'accent' | 'ai' | 'critical' | 'high' | 'medium' | 'low' | 'info'
}) {
  const w = max ? Math.max(value > 0 ? 2 : 0, (value / max) * 100) : 0
  const tones = {
    accent: 'bg-accent',
    ai: 'bg-ai',
    critical: 'bg-critical',
    high: 'bg-high',
    medium: 'bg-medium',
    low: 'bg-low',
    info: 'bg-info',
  }
  return (
    <div className={clsx('h-1.5 w-full overflow-hidden rounded-full bg-surface-3', className)}>
      <div className={clsx('h-full rounded-full transition-[width] duration-500 ease-[var(--ease-out)]', tones[tone])} style={{ width: `${w}%` }} />
    </div>
  )
}
