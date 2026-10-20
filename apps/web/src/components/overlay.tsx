import clsx from 'clsx'
import { X } from 'lucide-react'
import { useEffect, useRef, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { IconButton } from './ui'

function useEscape(onClose: () => void, active: boolean) {
  useEffect(() => {
    if (!active) return
    const h = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose, active])
}

function useRestoreFocus(active: boolean, ref: React.RefObject<HTMLElement | null>) {
  useEffect(() => {
    if (!active) return
    const prev = document.activeElement as HTMLElement | null
    ref.current?.focus()
    return () => prev?.focus?.()
  }, [active, ref])
}

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  width = 560,
}: {
  open: boolean
  onClose: () => void
  title: ReactNode
  subtitle?: ReactNode
  children: ReactNode
  footer?: ReactNode
  width?: number
}) {
  const ref = useRef<HTMLDivElement>(null)
  useEscape(onClose, open)
  useRestoreFocus(open, ref)
  if (!open) return null
  return createPortal(
    <div className="fixed inset-0 z-50">
      <div className="animate-overlay absolute inset-0 bg-[var(--overlay)]" onClick={onClose} />
      <div
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        style={{ width: `min(${width}px, 100vw)` }}
        className="animate-drawer absolute top-0 right-0 bottom-0 flex flex-col border-l border-line bg-surface shadow-2xl outline-none"
      >
        <div className="flex items-start justify-between gap-3 border-b border-line px-5 py-3.5">
          <div className="min-w-0">
            <div className="text-[15px] font-semibold tracking-[-0.01em]">{title}</div>
            {subtitle && <div className="mt-0.5 text-[12.5px] text-muted">{subtitle}</div>}
          </div>
          <IconButton label="Close" onClick={onClose}>
            <X className="size-4" />
          </IconButton>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="border-t border-line px-5 py-3">{footer}</div>}
      </div>
    </div>,
    document.body,
  )
}

export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = 'md',
}: {
  open: boolean
  onClose: () => void
  title: ReactNode
  description?: ReactNode
  children?: ReactNode
  footer?: ReactNode
  size?: 'sm' | 'md' | 'lg'
}) {
  const ref = useRef<HTMLDivElement>(null)
  useEscape(onClose, open)
  useRestoreFocus(open, ref)
  if (!open) return null
  return createPortal(
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 pt-[12vh]">
      <div className="animate-overlay fixed inset-0 bg-[var(--overlay)]" onClick={onClose} />
      <div
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        className={clsx(
          'animate-modal relative w-full rounded-2xl border border-line bg-surface shadow-2xl outline-none',
          size === 'sm' ? 'max-w-sm' : size === 'lg' ? 'max-w-2xl' : 'max-w-lg',
        )}
      >
        <div className="px-5 pt-4.5 pb-2">
          <h2 className="text-[15px] font-semibold tracking-[-0.01em]">{title}</h2>
          {description && <p className="mt-1 text-[13px] text-muted">{description}</p>}
        </div>
        {children && <div className="px-5 py-3">{children}</div>}
        {footer && <div className="flex justify-end gap-2 px-5 pt-2 pb-4.5">{footer}</div>}
      </div>
    </div>,
    document.body,
  )
}
