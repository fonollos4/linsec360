import { createContext, useContext } from 'react'

export type NotificationTone = 'success' | 'error' | 'warning' | 'info'

export type NotificationInput = {
  tone: NotificationTone
  title: string
  message?: string
  href?: string
  duration?: number
}

export type Notification = NotificationInput & {
  id: number
  createdAt: number
  read: boolean
}

export type NotificationContextValue = {
  notifications: Notification[]
  toasts: Notification[]
  unread: number
  notify: (input: NotificationInput) => number
  dismissToast: (id: number) => void
  markAllRead: () => void
  clear: () => void
}

export const NotificationContext = createContext<NotificationContextValue | null>(null)

export function useNotifications(): NotificationContextValue {
  const value = useContext(NotificationContext)
  if (!value) throw new Error('useNotifications must be used inside NotificationProvider')
  return value
}
