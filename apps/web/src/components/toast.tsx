import clsx from 'clsx'
import { CheckCircle2, Info, XCircle } from 'lucide-react'
import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'

type Tone = 'success' | 'error' | 'info'
interface Toast {
  id: number
  tone: Tone
  message: string
}

let listeners: ((t: Toast[]) => void)[] = []
let toasts: Toast[] = []
let seq = 0

function emit() {
  listeners.forEach((l) => l(toasts))
}

export function toast(message: string, tone: Tone = 'success') {
  const t = { id: ++seq, tone, message }
  toasts = [...toasts.slice(-3), t]
  emit()
  window.setTimeout(() => {
    toasts = toasts.filter((x) => x.id !== t.id)
    emit()
  }, tone === 'error' ? 6000 : 3200)
}

export const toastError = (e: unknown) => toast(e instanceof Error ? e.message : String(e), 'error')

export function Toaster() {
  const [items, setItems] = useState<Toast[]>([])
  useEffect(() => {
    listeners.push(setItems)
    return () => {
      listeners = listeners.filter((l) => l !== setItems)
    }
  }, [])
  return createPortal(
    <div className="pointer-events-none fixed right-4 bottom-4 z-[60] flex w-[360px] max-w-[calc(100vw-2rem)] flex-col gap-2" aria-live="polite">
      {items.map((t) => (
        <div
          key={t.id}
          className={clsx(
            'animate-in pointer-events-auto flex items-start gap-2.5 rounded-xl border bg-surface px-3.5 py-3 text-[13px] shadow-xl',
            t.tone === 'error' ? 'border-danger/30' : 'border-line',
          )}
        >
          {t.tone === 'success' && <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-ok" />}
          {t.tone === 'error' && <XCircle className="mt-0.5 size-4 shrink-0 text-danger" />}
          {t.tone === 'info' && <Info className="mt-0.5 size-4 shrink-0 text-accent" />}
          <span className="text-fg">{t.message}</span>
        </div>
      ))}
    </div>,
    document.body,
  )
}
