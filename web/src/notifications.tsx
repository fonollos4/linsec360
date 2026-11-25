import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { Link } from 'react-router-dom'
import { Bell, Check, CheckCircle2, Info, Trash2, TriangleAlert, X, XCircle } from 'lucide-react'
import { NotificationContext, useNotifications, type Notification, type NotificationInput } from './notification-context'

const MAX_HISTORY = 30
const MAX_VISIBLE = 4
const DEFAULT_DURATION = 7000

const toneIcons = {
  success: CheckCircle2,
  error: XCircle,
  warning: TriangleAlert,
  info: Info,
}

function formatTime(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}

function Toast({ notification, onDismiss }: { notification: Notification; onDismiss: (id: number) => void }) {
  const [paused, setPaused] = useState(false)
  const duration = notification.duration ?? DEFAULT_DURATION
  const Icon = toneIcons[notification.tone]

  useEffect(() => {
    if (paused) return
    const timer = window.setTimeout(() => onDismiss(notification.id), duration)
    return () => window.clearTimeout(timer)
  }, [notification.id, duration, onDismiss, paused])

  return (
    <div
      className={`notification-toast tone-${notification.tone}`}
      role={notification.tone === 'error' || notification.tone === 'warning' ? 'alert' : 'status'}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
    >
      <span className="notification-icon"><Icon /></span>
      <div className="notification-copy">
        <strong>{notification.title}</strong>
        {notification.message && <p>{notification.message}</p>}
        {notification.href && <Link to={notification.href} onClick={() => onDismiss(notification.id)}>Voir le détail →</Link>}
      </div>
      <button className="notification-close" aria-label="Fermer la notification" onClick={() => onDismiss(notification.id)}><X /></button>
      <span
        className="notification-progress"
        style={{ animationDuration: `${duration}ms`, animationPlayState: paused ? 'paused' : 'running' }}
      />
    </div>
  )
}

function NotificationStack({ toasts, dismiss }: { toasts: Notification[]; dismiss: (id: number) => void }) {
  if (!toasts.length) return null
  return createPortal(
    <div className="notification-stack" aria-label="Notifications récentes">
      {toasts.map((notification) => <Toast key={notification.id} notification={notification} onDismiss={dismiss} />)}
    </div>,
    document.body,
  )
}

export function NotificationMenu() {
  const { notifications, unread, markAllRead, clear } = useNotifications()
  const [open, setOpen] = useState(false)
  const wrapperRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!open) return
    const handlePointer = (event: MouseEvent) => {
      if (!wrapperRef.current?.contains(event.target as Node)) setOpen(false)
    }
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', handlePointer)
    document.addEventListener('keydown', handleKey)
    return () => {
      document.removeEventListener('mousedown', handlePointer)
      document.removeEventListener('keydown', handleKey)
    }
  }, [open])

  return (
    <div className="notification-menu" ref={wrapperRef}>
      <button
        className="icon-button"
        aria-label="Notifications"
        aria-expanded={open}
        aria-controls="notification-history"
        onClick={() => {
          const next = !open
          setOpen(next)
          if (next) markAllRead()
        }}
      >
        <Bell />
        {unread > 0 && <span className="notif-dot">{unread > 9 ? '9+' : unread}</span>}
      </button>
      {open && (
        <div className="notification-panel" id="notification-history" role="dialog" aria-label="Historique des notifications">
          <div className="notification-panel-head">
            <strong>Notifications</strong>
            <div>
              <button className="secondary" onClick={markAllRead}><Check /> Lu</button>
              <button className="secondary" onClick={clear}><Trash2 /> Effacer</button>
            </div>
          </div>
          <div className="notification-panel-list">
            {!notifications.length && (
              <div className="notification-empty"><CheckCircle2 /> Aucune notification récente</div>
            )}
            {notifications.map((notification) => {
              const Icon = toneIcons[notification.tone]
              return (
                <div key={notification.id} className={`notification-item tone-${notification.tone}${notification.read ? '' : ' unread'}`}>
                  <Icon />
                  <div>
                    <strong>{notification.title}</strong>
                    {notification.message && <p>{notification.message}</p>}
                    <span>{formatTime(notification.createdAt)}</span>
                    {notification.href && <Link to={notification.href} onClick={() => setOpen(false)}>Ouvrir →</Link>}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [toastIds, setToastIds] = useState<number[]>([])
  const nextId = useRef(1)

  const dismissToast = useCallback((id: number) => {
    setToastIds((current) => current.filter((value) => value !== id))
  }, [])

  const notify = useCallback((input: NotificationInput) => {
    const id = nextId.current
    nextId.current += 1
    const notification: Notification = { ...input, id, createdAt: Date.now(), read: false }
    setNotifications((current) => [notification, ...current].slice(0, MAX_HISTORY))
    setToastIds((current) => [...current, id].slice(-MAX_VISIBLE))
    return id
  }, [])

  const markAllRead = useCallback(() => {
    setNotifications((current) => current.map((notification) => ({ ...notification, read: true })))
  }, [])

  const clear = useCallback(() => {
    setNotifications([])
    setToastIds([])
  }, [])

  const toasts = useMemo(
    () => toastIds.map((id) => notifications.find((notification) => notification.id === id)).filter((item): item is Notification => Boolean(item)),
    [toastIds, notifications],
  )

  const value = useMemo(() => ({
    notifications,
    toasts,
    unread: notifications.filter((notification) => !notification.read).length,
    notify,
    dismissToast,
    markAllRead,
    clear,
  }), [notifications, toasts, notify, dismissToast, markAllRead, clear])

  return (
    <NotificationContext.Provider value={value}>
      {children}
      <NotificationStack toasts={toasts} dismiss={dismissToast} />
    </NotificationContext.Provider>
  )
}
