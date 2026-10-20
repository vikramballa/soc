/** Security-specific display components. Severity is never conveyed by colour alone. */
import clsx from 'clsx'
import { CircleAlert, CircleDot, Info, OctagonAlert, TriangleAlert } from 'lucide-react'
import { CATEGORY_LABEL, SEVERITY_LABEL, SOURCE_LABEL, STATUS_LABEL, riskBand } from '../lib/format'
import type { Severity } from '../lib/types'

const SEV_STYLE: Record<Severity, { text: string; bg: string; bar: string }> = {
  critical: { text: 'text-critical', bg: 'bg-critical/12', bar: 'bg-critical' },
  high: { text: 'text-high', bg: 'bg-high/12', bar: 'bg-high' },
  medium: { text: 'text-medium', bg: 'bg-medium/12', bar: 'bg-medium' },
  low: { text: 'text-low', bg: 'bg-low/12', bar: 'bg-low' },
  informational: { text: 'text-info', bg: 'bg-info/12', bar: 'bg-info' },
}

export const sevText = (s: Severity) => SEV_STYLE[s]?.text ?? 'text-info'
export const sevBar = (s: Severity) => SEV_STYLE[s]?.bar ?? 'bg-info'

function SevIcon({ s, className }: { s: Severity; className?: string }) {
  const cls = clsx('shrink-0', className)
  if (s === 'critical') return <OctagonAlert className={cls} />
  if (s === 'high') return <TriangleAlert className={cls} />
  if (s === 'medium') return <CircleAlert className={cls} />
  if (s === 'low') return <CircleDot className={cls} />
  return <Info className={cls} />
}

export function SeverityBadge({ severity, size = 'md' }: { severity: Severity; size?: 'sm' | 'md' }) {
  const st = SEV_STYLE[severity] ?? SEV_STYLE.informational
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded-md font-medium whitespace-nowrap',
        size === 'sm' ? 'h-5 px-1.5 text-[11px]' : 'h-6 px-2 text-[12px]',
        st.text,
        st.bg,
      )}
    >
      <SevIcon s={severity} className={size === 'sm' ? 'size-3' : 'size-3.5'} />
      {SEVERITY_LABEL[severity]}
    </span>
  )
}

export function RiskScore({ score, size = 'md' }: { score: number; size?: 'sm' | 'md' | 'lg' }) {
  const band = riskBand(score)
  const dim = size === 'lg' ? 64 : size === 'md' ? 36 : 28
  const stroke = size === 'lg' ? 6 : 3.5
  const r = (dim - stroke) / 2
  const c = 2 * Math.PI * r
  return (
    <div className="relative inline-flex shrink-0 items-center justify-center" style={{ width: dim, height: dim }}
      title={`Risk ${score}/100 (${SEVERITY_LABEL[band]})`} aria-label={`Risk score ${score} of 100`}>
      <svg width={dim} height={dim} className="-rotate-90">
        <circle cx={dim / 2} cy={dim / 2} r={r} fill="none" stroke="var(--surface-3)" strokeWidth={stroke} />
        <circle
          cx={dim / 2}
          cy={dim / 2}
          r={r}
          fill="none"
          strokeWidth={stroke}
          strokeLinecap="round"
          className={clsx('stroke-current transition-[stroke-dashoffset] duration-500', sevText(band))}
          strokeDasharray={c}
          strokeDashoffset={c * (1 - Math.max(0, Math.min(100, score)) / 100)}
        />
      </svg>
      <span className={clsx('tnum absolute font-semibold', size === 'lg' ? 'text-[19px]' : size === 'md' ? 'text-[12px]' : 'text-[11px]')}>
        {score}
      </span>
    </div>
  )
}

const STATUS_STYLE: Record<string, string> = {
  new: 'bg-accent-soft text-accent-strong',
  triaged: 'bg-surface-3 text-fg',
  investigating: 'bg-medium/12 text-medium',
  contained: 'bg-low/12 text-low',
  resolved: 'bg-ok/12 text-ok',
  closed: 'bg-surface-3 text-faint',
  merged: 'bg-surface-3 text-faint',
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={clsx('inline-flex h-5 items-center rounded-md px-1.5 text-[11.5px] font-medium', STATUS_STYLE[status] ?? STATUS_STYLE.triaged)}>
      {STATUS_LABEL[status] ?? status}
    </span>
  )
}

export function CategoryLabel({ category }: { category: string }) {
  return <span className="text-[12px] text-muted">{CATEGORY_LABEL[category] ?? category}</span>
}

const SOURCE_COLOR: Record<string, string> = {
  wazuh: 'bg-[#3d9df2]',
  suricata: 'bg-[#f2994a]',
  zeek: 'bg-[#45c48b]',
  sentinelx: 'bg-accent',
  ml: 'bg-ai',
}

export function SourcePills({ sources }: { sources: string[] }) {
  return (
    <span className="inline-flex flex-wrap gap-1">
      {sources.map((s) => (
        <span key={s} className="inline-flex h-5 items-center gap-1 rounded-md border border-line px-1.5 text-[11px] text-muted">
          <span className={clsx('size-1.5 rounded-full', SOURCE_COLOR[s] ?? 'bg-info')} />
          {SOURCE_LABEL[s] ?? s}
        </span>
      ))}
    </span>
  )
}

export function TechniqueChip({ id, name, onClick }: { id: string; name?: string; onClick?: () => void }) {
  const Tag = onClick ? 'button' : 'span'
  return (
    <Tag
      onClick={onClick}
      className={clsx(
        'inline-flex h-6 items-center gap-1.5 rounded-md border border-line bg-surface-2 px-1.5 text-[12px]',
        onClick && 'press hover:border-line-strong',
      )}
      title={name ? `${id} ${name}` : id}
    >
      <span className="font-mono text-[11px] text-accent-strong">{id}</span>
      {name && <span className="max-w-[220px] truncate text-muted">{name}</span>}
    </Tag>
  )
}

export function ConfidenceMeter({ value }: { value: number }) {
  const label = value >= 0.75 ? 'High' : value >= 0.5 ? 'Moderate' : 'Low'
  return (
    <span className="inline-flex items-center gap-2" title={`Confidence ${(value * 100).toFixed(0)}%`}>
      <span className="flex gap-0.5">
        {[0.25, 0.5, 0.75].map((t) => (
          <span key={t} className={clsx('h-2.5 w-1.5 rounded-sm', value >= t ? 'bg-accent' : 'bg-surface-3')} />
        ))}
      </span>
      <span className="text-[12.5px]">
        {label} <span className="tnum text-faint">{Math.round(value * 100)}%</span>
      </span>
    </span>
  )
}

export function CriticalityDots({ value }: { value: number }) {
  const labels = ['', 'Low', 'Normal', 'Important', 'High', 'Critical']
  return (
    <span className="inline-flex items-center gap-1.5" title={`Criticality ${value}/5 — ${labels[value]}`}>
      <span className="flex gap-0.5">
        {[1, 2, 3, 4, 5].map((i) => (
          <span key={i} className={clsx('size-1.5 rounded-full', i <= value ? (value >= 4 ? 'bg-high' : 'bg-accent') : 'bg-surface-3')} />
        ))}
      </span>
      <span className="text-[12px] text-muted">{labels[value]}</span>
    </span>
  )
}
