import clsx from 'clsx'
import { AlertTriangle, Inbox, Loader2 } from 'lucide-react'
import {
  forwardRef,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react'

/* Button */
type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'ai'
type Size = 'sm' | 'md'

const VARIANTS: Record<Variant, string> = {
  primary: 'bg-accent text-accent-contrast hover:bg-accent-strong font-medium shadow-[0_1px_0_rgb(255_255_255/0.15)_inset]',
  secondary: 'bg-surface-2 text-fg border border-line hover:border-line-strong hover:bg-surface-3',
  ghost: 'text-muted hover:text-fg hover:bg-surface-2',
  danger: 'bg-danger/10 text-danger border border-danger/25 hover:bg-danger/15',
  ai: 'bg-ai text-white font-medium hover:brightness-110 shadow-[0_1px_0_rgb(255_255_255/0.2)_inset]',
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  size?: Size
  icon?: ReactNode
  loading?: boolean
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', icon, loading, className, children, disabled, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={clsx(
        'press inline-flex items-center justify-center gap-1.5 rounded-lg whitespace-nowrap select-none',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        size === 'sm' ? 'h-7 px-2.5 text-[12.5px]' : 'h-8.5 px-3 text-[13px]',
        VARIANTS[variant],
        className,
      )}
      {...rest}
    >
      {loading ? <Loader2 className="spin size-3.5" /> : icon}
      {children}
    </button>
  )
})

export function IconButton({
  label,
  className,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button
      aria-label={label}
      title={label}
      className={clsx(
        'press inline-flex size-8 items-center justify-center rounded-lg text-muted hover:bg-surface-2 hover:text-fg',
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  )
}

/* Card */
export function Card({
  className,
  children,
  ...rest
}: { className?: string; children: ReactNode } & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={clsx('rounded-xl border border-line bg-surface shadow-[var(--shadow)]', className)} {...rest}>
      {children}
    </div>
  )
}

export function CardHeader({
  title,
  subtitle,
  action,
  icon,
  className,
}: {
  title: ReactNode
  subtitle?: ReactNode
  action?: ReactNode
  icon?: ReactNode
  className?: string
}) {
  return (
    <div className={clsx('flex items-start justify-between gap-3 px-4 pt-3.5 pb-3', className)}>
      <div className="flex min-w-0 items-start gap-2.5">
        {icon && <div className="mt-0.5 text-faint">{icon}</div>}
        <div className="min-w-0">
          <h3 className="text-[13.5px] font-semibold tracking-[-0.005em] text-fg">{title}</h3>
          {subtitle && <p className="mt-0.5 text-[12.5px] text-muted">{subtitle}</p>}
        </div>
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  )
}

/* Badge */
export function Badge({
  children,
  tone = 'neutral',
  className,
  title,
}: {
  children: ReactNode
  tone?: 'neutral' | 'accent' | 'ok' | 'warn' | 'danger' | 'ai' | 'outline'
  className?: string
  title?: string
}) {
  const tones = {
    neutral: 'bg-surface-3 text-muted',
    accent: 'bg-accent-soft text-accent-strong',
    ok: 'bg-ok/12 text-ok',
    warn: 'bg-warn/12 text-warn',
    danger: 'bg-danger/12 text-danger',
    ai: 'bg-ai-soft text-ai',
    outline: 'border border-line text-muted',
  }
  return (
    <span
      title={title}
      className={clsx(
        'inline-flex h-5 items-center gap-1 rounded-md px-1.5 text-[11.5px] font-medium whitespace-nowrap',
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  )
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={clsx('font-mono text-[12px] tracking-tight', className)}>{children}</span>
}

export function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="inline-flex h-5 min-w-5 items-center justify-center rounded border border-line bg-surface-2 px-1 font-sans text-[11px] text-faint">
      {children}
    </kbd>
  )
}

/* Inputs */
const field =
  'w-full rounded-lg border border-line bg-bg-elev px-3 text-[13px] text-fg placeholder:text-faint transition-[border-color,box-shadow] duration-150 hover:border-line-strong focus:border-accent focus:outline-none focus:ring-3 focus:ring-accent/15 disabled:opacity-60'

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement> & { icon?: ReactNode }>(
  function Input({ className, icon, ...rest }, ref) {
    if (icon)
      return (
        <div className={clsx('relative', className)}>
          <span className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-faint">{icon}</span>
          <input ref={ref} className={clsx(field, 'h-8.5 pl-8')} {...rest} />
        </div>
      )
    return <input ref={ref} className={clsx(field, 'h-8.5', className)} {...rest} />
  },
)

export function Textarea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={clsx(field, 'min-h-20 py-2 leading-relaxed', className)} {...rest} />
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={clsx(
        field,
        'h-8.5 cursor-pointer appearance-none bg-[length:16px] bg-[right_8px_center] bg-no-repeat pr-8',
        "bg-[url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23889' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E\")]",
        className,
      )}
      {...rest}
    >
      {children}
    </select>
  )
}

export function Label({ children, hint }: { children: ReactNode; hint?: ReactNode }) {
  return (
    <span className="mb-1.5 flex items-baseline justify-between gap-2 text-[12.5px] font-medium text-muted">
      {children}
      {hint && <span className="font-normal text-faint">{hint}</span>}
    </span>
  )
}

export function Switch({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
  label: string
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={clsx(
        'relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors duration-150 disabled:opacity-50',
        checked ? 'bg-accent' : 'bg-surface-3 ring-1 ring-line-strong ring-inset',
      )}
    >
      <span
        className={clsx(
          'inline-block size-3.5 rounded-full bg-white shadow transition-transform duration-200 ease-[var(--ease-out)]',
          checked ? 'translate-x-[18px]' : 'translate-x-[3px]',
        )}
      />
    </button>
  )
}

/* Tabs */
export function Tabs<T extends string>({
  value,
  onChange,
  items,
  className,
}: {
  value: T
  onChange: (v: T) => void
  items: { value: T; label: ReactNode; count?: number | null }[]
  className?: string
}) {
  return (
    <div role="tablist" className={clsx('flex items-center gap-1 border-b border-line', className)}>
      {items.map((it) => {
        const active = it.value === value
        return (
          <button
            key={it.value}
            role="tab"
            aria-selected={active}
            onClick={() => onChange(it.value)}
            className={clsx(
              'relative -mb-px flex h-9 items-center gap-1.5 px-2.5 text-[13px] transition-colors duration-150',
              active ? 'font-medium text-fg' : 'text-muted hover:text-fg',
            )}
          >
            {it.label}
            {it.count != null && (
              <span className={clsx('tnum rounded px-1 text-[11px]', active ? 'bg-accent-soft text-accent-strong' : 'bg-surface-3 text-faint')}>
                {it.count}
              </span>
            )}
            {active && <span className="absolute inset-x-1.5 bottom-0 h-0.5 rounded-full bg-accent" />}
          </button>
        )
      })}
    </div>
  )
}

export function Segmented<T extends string>({
  value,
  onChange,
  items,
}: {
  value: T
  onChange: (v: T) => void
  items: { value: T; label: ReactNode }[]
}) {
  return (
    <div className="inline-flex rounded-lg border border-line bg-bg-elev p-0.5">
      {items.map((it) => (
        <button
          key={it.value}
          onClick={() => onChange(it.value)}
          className={clsx(
            'h-7 rounded-md px-2.5 text-[12.5px] transition-colors duration-150',
            it.value === value ? 'bg-surface-3 font-medium text-fg shadow-sm' : 'text-muted hover:text-fg',
          )}
        >
          {it.label}
        </button>
      ))}
    </div>
  )
}

/* States */
export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={clsx('spin size-4 text-faint', className)} />
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={clsx('skeleton', className)} />
}

export function SkeletonRows({ rows = 6 }: { rows?: number }) {
  return (
    <div className="space-y-2 p-4">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-9" />
      ))}
    </div>
  )
}

export function EmptyState({
  icon,
  title,
  children,
  action,
  className,
}: {
  icon?: ReactNode
  title: ReactNode
  children?: ReactNode
  action?: ReactNode
  className?: string
}) {
  return (
    <div className={clsx('flex flex-col items-center justify-center px-6 py-12 text-center', className)}>
      <div className="mb-3 flex size-10 items-center justify-center rounded-xl border border-line bg-surface-2 text-faint">
        {icon ?? <Inbox className="size-5" />}
      </div>
      <h3 className="text-[14px] font-semibold">{title}</h3>
      {children && <div className="mt-1 max-w-md text-[13px] text-muted">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const msg = error instanceof Error ? error.message : 'Something went wrong'
  return (
    <EmptyState
      icon={<AlertTriangle className="size-5 text-warn" />}
      title="Couldn't load this"
      action={retry && <Button onClick={retry}>Try again</Button>}
    >
      {msg}
    </EmptyState>
  )
}

/* Layout helpers */
export function PageHeader({
  title,
  description,
  actions,
  children,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  children?: ReactNode
}) {
  return (
    <div className="mb-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[20px] font-semibold tracking-[-0.015em]">{title}</h1>
          {description && <p className="mt-1 max-w-3xl text-[13px] text-muted">{description}</p>}
        </div>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>
      {children}
    </div>
  )
}

export function KeyValue({ items, className }: { items: [ReactNode, ReactNode][]; className?: string }) {
  return (
    <dl className={clsx('grid grid-cols-[minmax(96px,auto)_1fr] gap-x-4 gap-y-2 text-[13px]', className)}>
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-faint">{k}</dt>
          <dd className="min-w-0 break-words text-fg">{v ?? <span className="text-faint">—</span>}</dd>
        </div>
      ))}
    </dl>
  )
}

export function SectionTitle({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-2 flex items-center justify-between">
      <h4 className="text-[11.5px] font-medium tracking-[0.04em] text-faint uppercase">{children}</h4>
      {action}
    </div>
  )
}

