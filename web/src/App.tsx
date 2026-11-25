import { useId, useEffect, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  ArrowUpRight,
  Boxes,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Cpu,
  Database,
  FileCode2,
  Gauge,
  HardDrive,
  LogOut,
  Maximize2,
  Minimize2,
  Play,
  Plus,
  Radar,
  RefreshCw,
  ScanLine,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
  TriangleAlert,
  X,
  type LucideIcon,
} from 'lucide-react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Link, Navigate, NavLink, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  api,
  type Alert,
  type Deployment,
  type Host,
  type PatchFinding,
  type PlaybookDetail,
  type IntegrationState,
  type NativeToolSecretKey,
  type StackConfiguration,
} from './api'
import { useNotifications, type NotificationInput } from './notification-context'
import { NotificationMenu } from './notifications'
import { CommandPalette } from './command-palette'
import { navGroups } from './nav-items'

const SIDEBAR_STORAGE_KEY = 'linsec:sidebar-collapsed'
const hostIdentifier = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/

type PatchTarget = { package: string; cve: string; fixed_version: string }

function buildPatchTargets(findings: Array<{ package: string; cve: string; fixed_version?: string | null }>): PatchTarget[] {
  const seen = new Set<string>()
  const targets: PatchTarget[] = []
  for (const finding of findings) {
    const target: PatchTarget = {
      package: finding.package,
      cve: finding.cve ?? '',
      fixed_version: finding.fixed_version ?? '',
    }
    const key = `${target.package}|${target.cve}|${target.fixed_version}`
    if (seen.has(key)) continue
    seen.add(key)
    targets.push(target)
  }
  return targets
}

function buildPatchExtraVars(findings: Array<{ package: string; cve: string; fixed_version?: string | null }>): Record<string, string> {
  const targets = buildPatchTargets(findings)
  return targets.length ? { patch_targets: JSON.stringify(targets) } : {}
}

const statusLabels: Record<string, string> = {
  success: 'Succès',
  succeeded: 'Réussi',
  secured: 'Sécurisé',
  deploying: 'Déploiement',
  reachable: 'Joignable',
  enrolling: 'Enrôlement',
  pending: 'En attente',
  queued: 'En file',
  running: 'En cours',
  failed: 'Échoué',
  cancelled: 'Annulé',
  completed: 'Terminé',
  open: 'Ouvert',
  resolved: 'Résolu',
  reboot_required: 'Redémarrage requis',
  pass: 'Conforme',
  fail: 'Non conforme',
  warn: 'Avertissement',
  warning: 'Avertissement',
  critical: 'Critique',
  high: 'Élevé',
  medium: 'Moyen',
  low: 'Faible',
  info: 'Info',
  unknown: 'Inconnu',
  stale: 'Obsolète',
  unverified: 'Non vérifié',
  agent_detected: 'Agent détecté',
  available: 'Disponible',
}

function humanize(value?: string | null): string {
  if (!value) return '—'
  const key = value.toLowerCase()
  return statusLabels[key] ?? key.replace(/[_-]+/g, ' ').replace(/^\w/, (character) => character.toUpperCase())
}

function statusTone(value?: string | null): string {
  const key = (value ?? '').toLowerCase()
  if (['success', 'succeeded', 'secured', 'reachable', 'ok', 'pass', 'compliant', 'active', 'connected', 'resolved', 'completed', 'available'].includes(key)) return 'success'
  if (['failed', 'cancelled', 'canceled', 'error', 'critical', 'fail', 'unreachable', 'open'].includes(key)) return 'danger'
  if (['running', 'queued', 'deploying', 'enrolling', 'pending', 'info', 'medium'].includes(key)) return 'info'
  if (['warning', 'warn', 'stale', 'high', 'reboot_required'].includes(key)) return 'warning'
  return 'muted'
}

function scoreTone(score: number | null | undefined): string {
  if (score == null) return 'muted'
  if (score >= 85) return 'success'
  if (score >= 65) return 'warning'
  return 'danger'
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat('fr-FR', { maximumFractionDigits: 1 }).format(value)
}

function initials(name?: string | null): string {
  if (!name) return '?'
  return name
    .split(/[\s._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part.charAt(0))
    .join('')
    .toUpperCase()
}

function relativeTime(value?: string | null): string {
  if (!value) return '—'
  const timestamp = new Date(value).getTime()
  if (Number.isNaN(timestamp)) return value
  const diff = timestamp - Date.now()
  const absolute = Math.abs(diff)
  const formatter = new Intl.RelativeTimeFormat('fr-FR', { numeric: 'auto' })
  if (absolute < 60_000) return formatter.format(Math.round(diff / 1000), 'second')
  if (absolute < 3_600_000) return formatter.format(Math.round(diff / 60_000), 'minute')
  if (absolute < 86_400_000) return formatter.format(Math.round(diff / 3_600_000), 'hour')
  if (absolute < 2_592_000_000) return formatter.format(Math.round(diff / 86_400_000), 'day')
  return new Date(value).toLocaleDateString('fr-FR')
}

function formatDateTime(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString('fr-FR', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })
}

function formatDuration(milliseconds: number): string {
  if (milliseconds < 1000) return `${Math.max(0, Math.round(milliseconds))} ms`
  const seconds = Math.round(milliseconds / 1000)
  if (seconds < 60) return `${seconds} s`
  const minutes = Math.floor(seconds / 60)
  const rest = seconds % 60
  if (minutes < 60) return rest ? `${minutes} min ${rest} s` : `${minutes} min`
  const hours = Math.floor(minutes / 60)
  return `${hours} h ${minutes % 60} min`
}

function parseCsv(text: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let cell = ''
  let quoted = false
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') {
        cell += '"'
        index += 1
      } else if (character === '"') {
        quoted = false
      } else {
        cell += character
      }
    } else if (character === '"') {
      if (cell.length) throw new Error('Guillemet CSV inattendu.')
      quoted = true
    } else if (character === ',') {
      row.push(cell)
      cell = ''
    } else if (character === '\n') {
      row.push(cell)
      if (row.some((value) => value.trim())) rows.push(row)
      row = []
      cell = ''
    } else if (character !== '\r') {
      cell += character
    }
  }
  if (quoted) throw new Error('Champ CSV entre guillemets non terminé.')
  row.push(cell)
  if (row.some((value) => value.trim())) rows.push(row)
  return rows
}

type BulkHostRow = {
  key: string
  name: string
  ip: string
  environment: string
  security_level: string
  groups: string[]
  ansible_user: string
  ansible_port: number
  ssh_key_reference: string
  valid: boolean
  selected: boolean
  error: string
}

type BulkSummary = {
  imported: Array<{ name: string; environment: string; message: string }>
  failed: Array<{ name: string; environment: string; message: string }>
  deployments: Array<{ environment: string; id?: string; error?: string }>
}

const defaultBulkOptions = {
  environment: 'production',
  security_level: 'high',
  ansible_user: 'linsec-ansible',
  ansible_port: 22,
  ssh_key_reference: 'linsec-ansible',
}

function asGroupList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((group) => String(group).trim()).filter(Boolean)
  if (typeof value !== 'string') return []
  return value.split(/[;,]/).map((group) => group.trim()).filter(Boolean)
}

function validateBulkRow(row: BulkHostRow, seen: Set<string>): string {
  const errors: string[] = []
  if (!hostIdentifier.test(row.name)) errors.push('nom invalide')
  if (!/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(row.ip)) errors.push('IPv4 invalide')
  if (!hostIdentifier.test(row.environment)) errors.push('environnement invalide')
  if (!hostIdentifier.test(row.ansible_user)) errors.push('utilisateur SSH invalide')
  if (!['low', 'medium', 'high', 'critical'].includes(row.security_level)) errors.push('niveau invalide')
  if (!Number.isInteger(row.ansible_port) || row.ansible_port < 1 || row.ansible_port > 65535) errors.push('port SSH invalide')
  if (row.groups.some((group) => !hostIdentifier.test(group))) errors.push('groupe invalide')
  const uniqueKey = `${row.environment}\0${row.name}`
  if (seen.has(uniqueKey)) errors.push('doublon')
  seen.add(uniqueKey)
  return errors.length ? errors.join(', ') : ''
}

function parseBulkHosts(text: string, defaults: typeof defaultBulkOptions): BulkHostRow[] {
  const trimmed = text.trim()
  if (!trimmed) return []
  const candidates: Array<Record<string, unknown>> = []

  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    const parsed = JSON.parse(trimmed) as unknown
    const entries = Array.isArray(parsed)
      ? parsed
      : (parsed as { hosts?: unknown }).hosts ?? []
    if (!Array.isArray(entries)) throw new Error('Le JSON doit contenir une liste d’hôtes.')
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object') throw new Error('Entrée JSON invalide.')
      candidates.push(entry as Record<string, unknown>)
    }
  } else if (trimmed.includes(',')) {
    const rows = parseCsv(trimmed)
    const first = rows[0].map((value, index) =>
      (index === 0 ? value.replace(/^\uFEFF/, '') : value).trim().toLowerCase(),
    )
    const hasHeader = first.includes('name') || first.includes('ip') || first.includes('hostname')
    if (hasHeader) {
      for (const cells of rows.slice(1)) {
        const values = Object.fromEntries(first.map((header, index) => [header, (cells[index] ?? '').trim()]))
        candidates.push(values)
      }
    } else {
      for (const cells of rows) {
        candidates.push({
          hostname: (cells[0] ?? '').trim(),
          ip: (cells[1] ?? '').trim(),
          ansible_user: (cells[2] ?? '').trim() || defaults.ansible_user,
          groups: (cells[3] ?? '').trim(),
          environment: (cells[4] ?? '').trim() || defaults.environment,
        })
      }
    }
  } else {
    for (const line of trimmed.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)) {
      candidates.push({ hostname: line, ip: line, environment: defaults.environment })
    }
  }

  if (candidates.length > 200) throw new Error('Maximum 200 hôtes par import.')
  const seen = new Set<string>()
  return candidates.map((item, index) => {
    const rawName = String(item.name ?? item.hostname ?? item.host ?? '').trim()
    const row: BulkHostRow = {
      key: `bulk-${index}-${rawName}`,
      name: rawName,
      ip: String(item.ip ?? item.address ?? '').trim(),
      environment: String(item.environment ?? item.group ?? item.groups ?? defaults.environment).trim() || defaults.environment,
      security_level: String(item.security_level ?? defaults.security_level).trim(),
      groups: asGroupList(item.groups ?? item.tags ?? []),
      ansible_user: String(item.ansible_user ?? item.ssh_user ?? defaults.ansible_user).trim() || defaults.ansible_user,
      ansible_port: Number(item.ansible_port ?? item.ssh_port ?? defaults.ansible_port),
      ssh_key_reference: String(item.ssh_key_reference ?? item.ssh_key ?? defaults.ssh_key_reference).trim() || defaults.ssh_key_reference,
      valid: true,
      selected: true,
      error: '',
    }
    row.error = validateBulkRow(row, seen)
    row.valid = !row.error
    row.selected = row.valid
    return row
  })
}

type MetricValue = { value: number | null; status: string; source?: string }

/* ------------------------------------------------------------------ */
/* Shared UI primitives                                                */
/* ------------------------------------------------------------------ */

function StatusBadge({ value, label }: { value?: string | null; label?: string }) {
  return <span className={`badge ${statusTone(value)}`}><span className="dot" />{label ?? humanize(value)}</span>
}

function PageHeader({ eyebrow, title, description, actions }: { eyebrow: string; title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="page-heading">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        {description && <p className="page-sub">{description}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </div>
  )
}

function StatCard({ label, item, icon: Icon, tone = 'cyan', suffix = '', hint }: {
  label: string
  item: MetricValue
  icon: LucideIcon
  tone?: 'cyan' | 'violet' | 'success' | 'warning' | 'danger'
  suffix?: string
  hint?: string
}) {
  const ready = item.status === 'ok' && item.value !== null
  return (
    <article className="metric">
      <div className="metric-top">
        <span className="metric-label">{label}</span>
        <span className={`metric-icon tone-${tone}`}><Icon /></span>
      </div>
      <strong className="metric-value">{ready ? `${formatNumber(item.value as number)}${suffix}` : '—'}</strong>
      <div className="metric-foot">
        <span className={`badge ${item.status === 'ok' ? 'success' : 'muted'}`}>
          <span className="dot" />{item.status === 'ok' ? 'À jour' : humanize(item.status)}
        </span>
        {hint && <span className="metric-hint">{hint}</span>}
      </div>
    </article>
  )
}

function DataTable({ headers, rows, empty = 'Aucune donnée' }: { headers: string[]; rows: ReactNode[][]; empty?: string }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>{headers.map((header) => <th key={header}>{header}</th>)}</tr>
        </thead>
        <tbody>
          {rows.length ? rows.map((row, index) => (
            <tr key={index}>{row.map((value, cell) => <td key={cell}>{value}</td>)}</tr>
          )) : (
            <tr><td colSpan={headers.length} className="empty">{empty}</td></tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function EmptyState({ icon: Icon = Database, title, description }: { icon?: LucideIcon; title: string; description?: string }) {
  return (
    <div className="empty-state">
      <Icon />
      <strong>{title}</strong>
      {description && <span>{description}</span>}
    </div>
  )
}

function Loading({ label = 'Chargement…' }: { label?: string }) {
  return <div className="loading"><span className="spinner" />{label}</div>
}

function Modal({ eyebrow, title, description, onClose, children }: {
  eyebrow: string
  title: string
  description?: string
  onClose: () => void
  children: ReactNode
}) {
  const titleId = useId()
  const dialogRef = useRef<HTMLDivElement | null>(null)
  const onCloseRef = useRef(onClose)
  useEffect(() => { onCloseRef.current = onClose }, [onClose])

  useEffect(() => {
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCloseRef.current()
    }
    document.addEventListener('keydown', handleKeyDown)
    dialogRef.current?.querySelector<HTMLElement>('input, select, textarea, button, a[href]')?.focus()
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      document.body.style.overflow = previousOverflow
      previouslyFocused?.focus()
    }
  }, [])

  return createPortal(
    <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onCloseRef.current() }}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={titleId} ref={dialogRef}>
        <div className="panel-heading">
          <div><p className="eyebrow">{eyebrow}</p><h2 id={titleId}>{title}</h2></div>
          <button className="icon-button" aria-label="Fermer la fenêtre" onClick={onClose}><X /></button>
        </div>
        <div className="modal-body">
          {description && <p className="host-import-note">{description}</p>}
          {children}
        </div>
      </div>
    </div>,
    document.body,
  )
}

type TaskFeedbackState = {
  label: string
  id?: string
  state: 'pending' | 'queued' | 'succeeded' | 'failed' | 'cancelled' | 'error'
  message: string
}

function TaskFeedback({ task }: { task: TaskFeedbackState | null }) {
  if (!task) return null
  const tone = task.state === 'succeeded' ? 'success'
    : ['failed', 'cancelled', 'error'].includes(task.state) ? 'error'
      : 'info'
  return (
    <div className={`task-feedback ${tone}`} role="status" aria-live="polite">
      {['pending', 'queued'].includes(task.state) && <span className="spinner" />}
      <div className="task-feedback-copy">
        <strong>{task.label}</strong>
        <span>{task.message}</span>
        {task.id && <Link to={`/deployments/${task.id}`}>Suivre l’exécution <ArrowUpRight /></Link>}
      </div>
    </div>
  )
}

function taskFromDeployment(label: string, job: Deployment | undefined, id: string): TaskFeedbackState {
  if (!job) return { label, id, state: 'error', message: 'Statut indisponible ; consultez le déploiement.' }
  if (job.status === 'succeeded') return { label, id, state: 'succeeded', message: 'Terminé avec succès.' }
  if (job.status === 'failed') return { label, id, state: 'failed', message: job.error_message || 'Échec du déploiement.' }
  if (job.status === 'cancelled') return { label, id, state: 'cancelled', message: 'Déploiement annulé.' }
  return { label, id, state: 'queued', message: `Tâche ${id} en cours (${humanize(job.status)}).` }
}

const TERMINAL_DEPLOYMENT_STATUSES = new Set(['succeeded', 'failed', 'cancelled'])

async function refreshAfterDeployment(
  client: ReturnType<typeof useQueryClient>,
  deploymentId: string,
  queryKeys: Array<Array<string | number>>,
  notify?: (input: NotificationInput) => void,
  label = 'Déploiement',
): Promise<Deployment | undefined> {
  let job: Deployment | undefined
  for (let attempt = 0; attempt < 180; attempt += 1) {
    try {
      job = await api.deployment(deploymentId)
      if (TERMINAL_DEPLOYMENT_STATUSES.has(job.status)) break
    } catch {
      break
    }
    await new Promise((resolve) => setTimeout(resolve, 2000))
  }
  await Promise.all(queryKeys.map((queryKey) => client.invalidateQueries({ queryKey })))
  if (job?.status === 'succeeded') {
    notify?.({ tone: 'success', title: `${label} terminé`, message: `Tâche ${deploymentId} : exécution réussie.`, href: `/deployments/${deploymentId}` })
  } else if (job?.status === 'failed') {
    notify?.({ tone: 'error', title: `${label} échoué`, message: job.error_message || 'Consultez le journal du déploiement.', href: `/deployments/${deploymentId}` })
  } else if (job?.status === 'cancelled') {
    notify?.({ tone: 'warning', title: `${label} annulé`, message: `Tâche ${deploymentId}.`, href: `/deployments/${deploymentId}` })
  }
  return job
}

function Login({ onLogin }: { onLogin: () => void }) {
  const { notify } = useNotifications()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const login = useMutation({
    mutationFn: () => api.login(username, password),
    onSuccess: () => {
      notify({ tone: 'success', title: 'Session ouverte', message: `Bienvenue, ${username}.` })
      onLogin()
    },
    onError: (cause) => {
      setError(cause instanceof Error ? cause.message : 'Connexion impossible')
      notify({ tone: 'error', title: 'Connexion refusée', message: cause instanceof Error ? cause.message : 'Vérifiez vos identifiants.' })
    },
  })
  return (
    <main className="login-page">
      <div className="login-shell">
        <aside className="login-visual">
          <div className="login-brand">
            <span className="brand-mark"><ShieldCheck /></span>
            <span className="brand-text"><strong>LinSec<em>360</em></strong><span>Security operations</span></span>
          </div>
          <div>
            <p className="eyebrow">Plateforme de sécurité Linux</p>
            <h2>Orchestration, durcissement et supervision depuis un seul poste de commande.</h2>
            <p>Pilotez la posture de vos serveurs, tracez chaque déploiement et gardez une longueur d’avance sur les menaces.</p>
            <ul className="login-features">
              <li><Play /> Déploiements Ansible traçables</li>
              <li><ShieldCheck /> Durcissement SELinux et OpenSCAP</li>
              <li><Boxes /> Correctifs de sécurité et live patching</li>
              <li><Radar /> Détection et réponse Wazuh</li>
            </ul>
          </div>
          <div className="login-visual-foot"><span className="live-dot" /> Console SOC · LinSec360 v2</div>
        </aside>
        <form className="login-card" onSubmit={(event) => { event.preventDefault(); setError(''); login.mutate() }}>
          <div>
            <p className="eyebrow">Accès sécurisé</p>
            <h1>Connexion</h1>
            <p className="login-sub">Authentifiez-vous pour accéder au centre de sécurité.</p>
          </div>
          {error && <div className="alert error">{error}</div>}
          <label>Utilisateur<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required /></label>
          <label>Mot de passe<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required /></label>
          <button className="primary" disabled={login.isPending}>{login.isPending ? 'Connexion…' : 'Se connecter'}</button>
          <div className="login-foot"><ScanLine /> Session chiffrée · Accès journalisé</div>
        </form>
      </div>
    </main>
  )
}

/* ------------------------------------------------------------------ */
/* Overview                                                            */
/* ------------------------------------------------------------------ */

function Overview() {
  const navigate = useNavigate()
  const kpis = useQuery({ queryKey: ['kpis'], queryFn: api.kpis })
  const hosts = useQuery({ queryKey: ['hosts'], queryFn: () => api.hosts({ limit: 500 }) })
  const deployments = useQuery({ queryKey: ['deployments', 'overview'], queryFn: () => api.deployments({ limit: 6 }) })
  const history = useQuery({ queryKey: ['kpi-history', 'compliance_score'], queryFn: () => api.kpiHistory('compliance_score') })
  const alertSummary = useQuery({ queryKey: ['alert-summary'], queryFn: api.alertSummary, retry: false })

  if (kpis.isLoading) return <Loading label="Chargement des métriques…" />
  if (kpis.isError || !kpis.data) return <div className="alert error">Impossible de charger le tableau de bord.</div>

  const data = kpis.data
  const totalHosts = data.hosts_total.value ?? 0
  const securedHosts = data.hosts_secured.value ?? 0
  const securedShare = data.hosts_total.status === 'ok' && totalHosts > 0 ? (securedHosts / totalHosts) * 100 : null
  const series = (history.data ?? []).map((item) => ({
    date: item.captured_at.slice(0, 10),
    value: item.status === 'ok' ? item.value : null,
  }))
  const severitySource = alertSummary.data?.unacknowledged ?? data.alerts_by_severity ?? {}
  const severityOrder = ['critical', 'high', 'medium', 'low']
  const severityRows = severityOrder
    .filter((severity) => typeof severitySource[severity] === 'number')
    .map((severity) => ({ severity, count: severitySource[severity] }))
  const severityMax = Math.max(1, ...severityRows.map((row) => row.count))
  const unacknowledged = severityRows.length ? severityRows.reduce((sum, row) => sum + row.count, 0) : null
  const recentHosts = (hosts.data ?? []).slice(0, 6)
  const recentDeployments = deployments.data?.items ?? []

  return (
    <div className="page">
      <section className="hero">
        <div className="hero-content">
          <div>
            <p className="eyebrow">Centre de sécurité</p>
            <h1>Pilotage de la posture Linux</h1>
            <p>Une vue unifiée de votre parc : inventaire, conformité, correctifs, détection et réponse.</p>
            <div className="hero-pills">
              <span className="hero-pill"><span className="live-dot success" /> Console opérationnelle</span>
              <span className="hero-pill">Hôtes sécurisés <strong>{data.hosts_secured.status === 'ok' ? formatNumber(securedHosts) : '—'}/{data.hosts_total.status === 'ok' ? formatNumber(totalHosts) : '—'}</strong></span>
              <span className="hero-pill">Actualisé <strong>{relativeTime(data.generated_at)}</strong></span>
            </div>
          </div>
          <div className="hero-actions">
            <button className="secondary" onClick={() => void kpis.refetch()}><RefreshCw /> Actualiser</button>
            <button className="primary" onClick={() => navigate('/deployments')}><Plus /> Nouveau déploiement</button>
          </div>
        </div>
      </section>

      <section className="metrics-grid">
        <StatCard label="Hôtes" item={data.hosts_total} icon={Server} hint="inventaire" />
        <StatCard label="Hôtes sécurisés" item={data.hosts_secured} icon={ShieldCheck} tone="success" hint={securedShare === null ? undefined : `${Math.round(securedShare)}% du parc`} />
        <StatCard label="Déploiements actifs" item={data.active_deployments} icon={Play} tone="violet" hint={data.hosts_deploying.status === 'ok' ? `${formatNumber(data.hosts_deploying.value ?? 0)} hôte(s)` : undefined} />
        <StatCard label="Vulnérabilités ouvertes" item={data.open_vulnerabilities} icon={ShieldAlert} tone="danger" hint={data.open_critical_vulnerabilities.status === 'ok' ? `${formatNumber(data.open_critical_vulnerabilities.value ?? 0)} critiques` : undefined} />
        <StatCard label="Score conformité" item={data.compliance_score} icon={Gauge} suffix="%" hint={data.hardening_drift.status === 'ok' ? `${formatNumber(data.hardening_drift.value ?? 0)} dérives` : undefined} />
        <StatCard label="Agents déconnectés" item={data.disconnected_agents} icon={Radar} tone="warning" hint={data.agent_coverage.status === 'ok' ? `${Math.round(data.agent_coverage.value ?? 0)}% couverture` : undefined} />
      </section>

      <section className="dashboard-grid three">
        <article className="panel">
          <div className="panel-heading">
            <div><p className="eyebrow">30 derniers jours</p><h2>Évolution du score de conformité</h2></div>
            <div className="chart-legend"><span className="swatch" style={{ background: 'linear-gradient(90deg,#22d3ee,#6366f1)' }} /> score OpenSCAP</div>
          </div>
          {series.length ? (
            <div className="chart-pad">
              <ResponsiveContainer width="100%" height={248}>
                <AreaChart data={series} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
                  <defs>
                    <linearGradient id="complianceFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.32} />
                      <stop offset="100%" stopColor="#6366f1" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#eef2f8" strokeDasharray="4 4" vertical={false} />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} minTickGap={28} />
                  <YAxis domain={[0, 100]} tickLine={false} axisLine={false} width={38} />
                  <Tooltip formatter={(value) => [`${value ?? '—'} %`, 'Score']} />
                  <Area type="monotone" dataKey="value" stroke="#0ea5e9" strokeWidth={2.4} fill="url(#complianceFill)" dot={false} connectNulls activeDot={{ r: 5, strokeWidth: 2 }} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState icon={Activity} title="Aucun historique disponible" description="Les instantanés KPI apparaîtront après le premier scan OpenSCAP." />
          )}
        </article>

        <article className="panel">
          <div className="panel-heading"><div><p className="eyebrow">Posture</p><h2>Couverture du parc</h2></div><StatusBadge value={securedShare === null ? 'unknown' : 'secured'} /></div>
          <div className="ring-wrap">
            <div className="ring" style={{ background: `conic-gradient(#0ea5e9 ${(securedShare ?? 0) * 3.6}deg, rgba(148,163,184,.16) 0deg)` }}>
              <div className="ring-inner"><strong>{securedShare === null ? '—' : `${Math.round(securedShare)}%`}</strong><span>sécurisé</span></div>
            </div>
            <div className="legend">
              <div className="legend-item"><span className="swatch" style={{ background: '#0ea5e9' }} />Sécurisés<strong>{data.hosts_secured.status === 'ok' ? formatNumber(securedHosts) : '—'}</strong></div>
              <div className="legend-item"><span className="swatch" style={{ background: '#f59e0b' }} />En déploiement<strong>{data.hosts_deploying.status === 'ok' ? formatNumber(data.hosts_deploying.value ?? 0) : '—'}</strong></div>
              <div className="legend-item"><span className="swatch" style={{ background: '#cbd5e1' }} />Total inventaire<strong>{data.hosts_total.status === 'ok' ? formatNumber(totalHosts) : '—'}</strong></div>
            </div>
          </div>
          <div className="panel-body tight" style={{ borderTop: '1px solid var(--line-2)' }}>
            <div className="stat-lines">
              <div className="stat-line"><span>Correctifs ouverts</span><strong>{data.open_vulnerabilities.status === 'ok' ? formatNumber(data.open_vulnerabilities.value ?? 0) : '—'}</strong></div>
              <div className="stat-line"><span>Redémarrages requis</span><strong>{data.reboot_required.status === 'ok' ? formatNumber(data.reboot_required.value ?? 0) : '—'}</strong></div>
              <div className="stat-line"><span>SELinux non conforme</span><strong>{data.selinux_non_compliant.status === 'ok' ? formatNumber(data.selinux_non_compliant.value ?? 0) : '—'}</strong></div>
            </div>
          </div>
        </article>
      </section>

      <section className="dashboard-grid">
        <article className="panel">
          <div className="panel-heading"><div><p className="eyebrow">Inventaire</p><h2>Hôtes récents</h2></div><NavLink to="/hosts">Tout voir <ArrowUpRight /></NavLink></div>
          {recentHosts.length ? (
            <DataTable
              headers={['Hôte', 'Environnement', 'Statut', '']}
              rows={recentHosts.map((host: Host) => [
                <div className="cell-title" key={`host-${host.id}`}>
                  <span className="avatar-sm">{initials(host.name)}</span>
                  <div className="cell-stack"><strong>{host.name}</strong><small className="mono">{host.ip}</small></div>
                </div>,
                <span className="badge muted" key={`env-${host.id}`}>{host.environment}</span>,
                <StatusBadge value={host.status} key={`status-${host.id}`} />,
                <button className="link-button" key={`open-${host.id}`} onClick={() => navigate(`/hosts/${host.id}`)}>Posture</button>,
              ])}
            />
          ) : <EmptyState icon={HardDrive} title="Aucun hôte enregistré" description="Ajoutez un serveur depuis l’inventaire pour commencer." />}
        </article>

        <article className="panel">
          <div className="panel-heading"><div><p className="eyebrow">Automatisation</p><h2>Déploiements récents</h2></div><NavLink to="/deployments">Tout voir <ArrowUpRight /></NavLink></div>
          {recentDeployments.length ? (
            <DataTable
              headers={['Playbook', 'Cibles', 'Statut', 'Quand']}
              rows={recentDeployments.map((job: Deployment) => [
                <div className="cell-stack" key={`job-${job.id}`}><button className="link-button strong" onClick={() => navigate(`/deployments/${job.id}`)}>{job.playbook}</button><small>{job.environment}</small></div>,
                `${job.target_hosts.length}`,
                <StatusBadge value={job.status} key={`job-status-${job.id}`} />,
                <span className="cell-stack" key={`job-time-${job.id}`}><small>{relativeTime(job.created_at)}</small></span>,
              ])}
            />
          ) : <EmptyState icon={Play} title="Aucun déploiement" description="Lancez un playbook pour voir son exécution ici." />}
        </article>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div><p className="eyebrow">Détection Wazuh</p><h2>Alertes non acquittées</h2></div>
          <span className={`badge ${unacknowledged === null ? 'muted' : unacknowledged > 0 ? 'danger' : 'success'}`}>
            <span className="dot" />{unacknowledged === null ? 'Source non connectée' : `${formatNumber(unacknowledged)} alerte(s)`}
          </span>
        </div>
        {severityRows.length ? (
          <div className="bars">
            {severityRows.map((row) => (
              <div className="bar-row" key={row.severity}>
                <span>{humanize(row.severity)}</span>
                <div className="bar-track"><div className={`bar-fill ${row.severity}`} style={{ width: `${(row.count / severityMax) * 100}%` }} /></div>
                <strong>{formatNumber(row.count)}</strong>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState icon={ShieldAlert} title="Aucune alerte synchronisée" description="La détection reste explicite tant que Wazuh n’est pas configuré et synchronisé." />
        )}
      </section>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Hosts                                                               */
/* ------------------------------------------------------------------ */

function launchDeploymentsForHosts(
  hosts: Host[],
  playbook: string,
  extraVars: Record<string, string> = {},
): Promise<Deployment[]> {
  const byEnvironment = new Map<string, string[]>()
  for (const host of hosts) {
    const names = byEnvironment.get(host.environment) ?? []
    names.push(host.name)
    byEnvironment.set(host.environment, names)
  }
  return Promise.all(
    [...byEnvironment].map(([environment, names]) =>
      api.createDeployment({ environment, playbook, hosts: names, extra_vars: extraVars }),
    ),
  )
}

function Hosts() {
  const client = useQueryClient()
  const navigate = useNavigate()
  const { notify } = useNotifications()
  const currentUser = useQuery({ queryKey: ['me'], queryFn: api.me })
  const canManageHosts = currentUser.data?.role === 'admin' || currentUser.data?.role === 'operator'
  const kpis = useQuery({ queryKey: ['kpis'], queryFn: api.kpis, refetchInterval: 30_000 })
  const { data = [], isLoading, error } = useQuery({ queryKey: ['hosts'], queryFn: () => api.hosts({ limit: 500 }) })
  const playbooks = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks })
  const authorizedPlaybooks = (playbooks.data ?? []).filter((item) => item.is_allowlisted)
  const defaultPlaybook = authorizedPlaybooks.find((item) => item.filename === 'site.yml')?.filename
    ?? authorizedPlaybooks[0]?.filename ?? ''

  const [showForm, setShowForm] = useState(false)
  const [showImport, setShowImport] = useState(false)
  const [editingHost, setEditingHost] = useState<Host | null>(null)
  const [terminalHost, setTerminalHost] = useState<Host | null>(null)
  const [bootstrapAfterAdd, setBootstrapAfterAdd] = useState(false)
  const [bulkOptions, setBulkOptions] = useState(defaultBulkOptions)
  const [form, setForm] = useState({ ...defaultBulkOptions, groups: '', name: '', ip: '', security_level: 'high', ansible_password: '' })
  const [editForm, setEditForm] = useState({ ip: '', security_level: 'high', groups: '', ansible_user: 'linsec-ansible', ansible_port: 22, ssh_key_reference: 'linsec-ansible' })
  const [testResult, setTestResult] = useState<{ state: 'idle' | 'testing' | 'ok' | 'failed'; message: string }>({ state: 'idle', message: '' })
  const [notice, setNotice] = useState('')
  const [search, setSearch] = useState('')
  const [environmentFilter, setEnvironmentFilter] = useState('')
  const [osFilter, setOsFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [selectedIds, setSelectedIds] = useState<number[]>([])
  const [actionStates, setActionStates] = useState<Record<string, string>>({})
  const [bulkText, setBulkText] = useState('')
  const [bulkRows, setBulkRows] = useState<BulkHostRow[]>([])
  const [bulkError, setBulkError] = useState('')
  const [bulkSummary, setBulkSummary] = useState<BulkSummary | null>(null)

  const createHost = useMutation({
    mutationFn: () => api.createHost({
      name: form.name,
      ip: form.ip,
      environment: form.environment,
      security_level: form.security_level,
      groups: form.groups.split(',').map((value) => value.trim()).filter(Boolean),
      ansible_user: form.ansible_user,
      ansible_port: form.ansible_port,
      ssh_key_reference: form.ssh_key_reference,
      ansible_password: form.ansible_password.trim() || undefined,
    }),
    onSuccess: async (host) => {
      setNotice(`${host.name} ajouté à l’inventaire Ansible.`)
      notify({ tone: 'success', title: 'Hôte ajouté', message: `${host.name} est dans l’inventaire Ansible.` })
      setShowForm(false)
      setForm({ ...defaultBulkOptions, groups: '', name: '', ip: '', security_level: 'high', ansible_password: '' })
      setTestResult({ state: 'idle', message: '' })
      if (bootstrapAfterAdd && defaultPlaybook) {
        try {
          await api.createDeployment({
            environment: host.environment,
            playbook: defaultPlaybook,
            hosts: [host.name],
          })
          setNotice(`${host.name} ajouté ; déploiement ${defaultPlaybook} mis en file.`)
        } catch (cause) {
          setNotice(`${host.name} ajouté ; déploiement impossible : ${cause instanceof Error ? cause.message : 'erreur inconnue'}`)
        }
      }
      void client.invalidateQueries({ queryKey: ['hosts'] })
      void client.invalidateQueries({ queryKey: ['deployments'] })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Ajout impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const testConnection = useMutation({
    mutationFn: () => api.testHostConnection({
      name: form.name || 'candidate',
      ip: form.ip,
      ansible_user: form.ansible_user,
      ansible_port: form.ansible_port,
    }),
    onMutate: () => setTestResult({ state: 'testing', message: 'Connexion et détection OS en cours…' }),
    onSuccess: (result) => setTestResult({
      state: result.reachable ? 'ok' : 'failed',
      message: result.reachable
        ? `Connexion OK${result.detected_os ? ` · ${result.detected_os} détecté` : ' · OS non détecté'}`
        : result.message,
    }),
    onError: (cause) => setTestResult({ state: 'failed', message: cause instanceof Error ? cause.message : 'Test impossible.' }),
  })
  const updateHost = useMutation({
    mutationFn: (change: { id: number; body: Record<string, unknown> }) => api.updateHost(change.id, change.body),
    onSuccess: (host) => {
      setEditingHost(null)
      void client.invalidateQueries({ queryKey: ['hosts'] })
      notify({ tone: 'success', title: 'Hôte mis à jour', message: host.name })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Mise à jour impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const deleteHost = useMutation({
    mutationFn: api.deleteHost,
    onSuccess: () => {
      setSelectedIds([])
      void client.invalidateQueries({ queryKey: ['hosts'] })
      notify({ tone: 'warning', title: 'Hôte supprimé de l’inventaire' })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Suppression impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const bulkImport = useMutation({
    mutationFn: async (): Promise<BulkSummary> => {
      const chosen = bulkRows.filter((row) => row.valid && row.selected)
      const result = await api.importHosts(chosen.map((row) => ({
        name: row.name,
        ip: row.ip,
        environment: row.environment,
        security_level: row.security_level,
        groups: row.groups,
        ansible_user: row.ansible_user,
        ansible_port: row.ansible_port,
        ssh_key_reference: row.ssh_key_reference,
      })))
      const deployments: BulkSummary['deployments'] = []
      if (bootstrapAfterAdd && defaultPlaybook && result.imported.length) {
        const byEnvironment = new Map<string, Host[]>()
        for (const host of result.imported) {
          const group = byEnvironment.get(host.environment) ?? []
          group.push(host)
          byEnvironment.set(host.environment, group)
        }
        for (const [environment, hosts] of byEnvironment) {
          try {
            const deployment = await api.createDeployment({
              environment,
              playbook: defaultPlaybook,
              hosts: hosts.map((host) => host.name),
            })
            deployments.push({ environment, id: deployment.id })
          } catch (cause) {
            deployments.push({ environment, error: cause instanceof Error ? cause.message : 'Déploiement impossible.' })
          }
        }
      }
      return {
        imported: result.imported.map((host) => ({ name: host.name, environment: host.environment, message: 'Ajouté à l’inventaire' })),
        failed: result.failed.map((failure) => ({ name: failure.name, environment: '', message: failure.detail })),
        deployments,
      }
    },
    onSuccess: (summary) => {
      setBulkSummary(summary)
      void client.invalidateQueries({ queryKey: ['hosts'] })
      void client.invalidateQueries({ queryKey: ['deployments'] })
      notify({
        tone: summary.failed.length ? 'warning' : 'success',
        title: 'Import terminé',
        message: `${formatNumber(summary.imported.length)} hôte(s) ajouté(s), ${formatNumber(summary.failed.length)} échec(s).`,
      })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Import impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const groupedAction = useMutation({
    mutationFn: ({ playbook, label, extraVars }: { playbook: string; label: string; extraVars?: Record<string, string> }) =>
      launchDeploymentsForHosts(data.filter((host) => selectedIds.includes(host.id)), playbook, extraVars)
        .then((deployments) => ({ deployments, label })),
    onMutate: (_variables) => {
      const key = `${_variables.label}:${selectedIds.length}`
      setActionStates((current) => ({ ...current, [key]: 'En cours…' }))
    },
    onSuccess: ({ deployments }, variables) => {
      const key = `${variables.label}:${selectedIds.length}`
      setActionStates((current) => ({ ...current, [key]: `${deployments.length} tâche(s) en file` }))
      void client.invalidateQueries({ queryKey: ['deployments'] })
      notify({
        tone: 'info',
        title: `${variables.label} lancé`,
        message: `${formatNumber(deployments.length)} tâche(s) en file.`,
        href: '/deployments',
      })
    },
    onError: (cause, variables) => {
      const key = `${variables.label}:${selectedIds.length}`
      setActionStates((current) => ({ ...current, [key]: cause instanceof Error ? cause.message : 'Échec' }))
      notify({ tone: 'error', title: `${variables.label} impossible`, message: cause instanceof Error ? cause.message : 'Erreur inconnue' })
    },
  })

  const applyBulkText = (text: string) => {
    setBulkText(text)
    setBulkSummary(null)
    setBulkError('')
    try {
      setBulkRows(parseBulkHosts(text, bulkOptions))
    } catch (cause) {
      setBulkRows([])
      setBulkError(cause instanceof Error ? cause.message : 'Format non reconnu.')
    }
  }
  const readBulkFile = (file?: File) => {
    if (!file) return
    if (file.size > 1_000_000) {
      setBulkError('Le fichier dépasse la limite de 1 Mo.')
      return
    }
    void file.text().then(applyBulkText).catch((cause: unknown) => {
      setBulkError(cause instanceof Error ? cause.message : 'Lecture du fichier impossible.')
    })
  }
  const toggleBulkRow = (key: string) => setBulkRows((current) => current.map((row) => row.key === key ? { ...row, selected: !row.selected } : row))

  if (isLoading) return <Loading label="Chargement de l’inventaire…" />
  if (error) return <div className="alert error">Impossible de charger les hôtes.</div>

  const environments = [...new Set(data.map((host) => host.environment))].sort()
  const operatingSystems = [...new Set(data.map((host) => host.os).filter((value): value is string => Boolean(value)))].sort()
  const filtered = data.filter((host) => {
    const query = search.trim().toLowerCase()
    return (!query || `${host.name} ${host.ip} ${host.groups.join(' ')} ${host.os ?? ''}`.toLowerCase().includes(query))
      && (!environmentFilter || host.environment === environmentFilter)
      && (!osFilter || host.os === osFilter)
      && (!statusFilter || host.ssh_status === statusFilter || host.status === statusFilter)
  })
  const reachableCount = data.filter((host) => host.ssh_status === 'reachable').length
  const compliantCount = data.filter((host) => host.status === 'secured').length
  const selectedCount = filtered.filter((host) => selectedIds.includes(host.id)).length

  return (
    <div className="page">
      <PageHeader
        eyebrow="Inventaire"
        title="Hôtes"
        description={`${formatNumber(data.length)} serveur(s) · ${formatNumber(reachableCount)} joignable(s) · ${formatNumber(compliantCount)} sécurisé(s)`}
        actions={canManageHosts && (
          <>
            <button className="secondary" onClick={() => { setShowImport((visible) => !visible); setNotice('') }}><ScanLine /> Import en masse</button>
            <button className="primary" onClick={() => { setNotice(''); setEditingHost(null); setShowForm(true) }}><Plus /> Ajouter un hôte</button>
          </>
        )}
      />
      <div className="metrics-grid three">
        <StatCard label="Hôtes" item={{ value: kpis.data?.hosts_total.value ?? data.length, status: 'ok' }} icon={Server} tone="cyan" hint="inventaire Ansible" />
        <StatCard label="Conformité" item={{ value: kpis.data?.compliance_score.value ?? null, status: kpis.data?.compliance_score.status ?? 'unknown' }} icon={ShieldCheck} tone="success" suffix="%" hint="OpenSCAP" />
        <StatCard label="Correctifs" item={{ value: kpis.data?.patch_coverage.value ?? null, status: kpis.data?.patch_coverage.status ?? 'unknown' }} icon={Boxes} tone="violet" suffix="%" hint="livepatch / sécurité" />
      </div>
      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Vue du parc</p><h2>État opérationnel</h2></div><span className="badge info"><span className="dot" />{formatNumber(reachableCount)} agent(s) joignable(s)</span></div>
        <div className="parc-summary">
          <span className={`badge ${statusTone(kpis.data?.agent_coverage.status)}`}>Agents : {kpis.data?.agent_coverage.value ?? '—'}%</span>
          <span className={`badge ${statusTone(kpis.data?.reboot_required.status)}`}>Redémarrage requis : {kpis.data?.reboot_required.value ?? '—'}</span>
          <span className={`badge ${statusTone(kpis.data?.alerts_by_severity ? 'critical' : 'unknown')}`}>Alertes : {Object.values(kpis.data?.alerts_by_severity ?? {}).reduce((sum, value) => sum + value, 0)}</span>
          <span className="badge muted">Durcissement : {formatNumber(compliantCount)} hôte(s)</span>
        </div>
      </article>
      {notice && <div className="alert success">{notice}</div>}

      {showImport && canManageHosts && (
        <Modal
          eyebrow="Import en masse"
          title="Prévisualiser puis ajouter les hôtes"
          description="Validation avant ajout : les lignes en erreur ou désélectionnées ne sont pas importées."
          onClose={() => { setShowImport(false); setNotice('') }}
        >
          <p className="host-import-note">Collez une liste d’IP/noms, un CSV avec en-têtes (<code>name,ip,environment,groups,ansible_user,ansible_port,ssh_key_reference</code>) ou un JSON. Format court : <code>hostname,ip,ssh_user,group,environment</code>. Les lignes en erreur ou désélectionnées ne sont pas importées. Le compte de service SSH doit déjà exister sur les cibles.</p>
          <div className="form-grid three">
            <label>Environnement par défaut<select value={bulkOptions.environment} onChange={(event) => setBulkOptions({ ...bulkOptions, environment: event.target.value })}><option>production</option><option>staging</option><option>development</option></select></label>
            <label>Utilisateur de service<input value={bulkOptions.ansible_user} onChange={(event) => setBulkOptions({ ...bulkOptions, ansible_user: event.target.value })} /></label>
            <label>Référence de clé SSH<input value={bulkOptions.ssh_key_reference} onChange={(event) => setBulkOptions({ ...bulkOptions, ssh_key_reference: event.target.value })} /></label>
          </div>
          <label className="host-csv-file">Fichier CSV / JSON<input type="file" accept=".csv,.json,text/csv,application/json" disabled={bulkImport.isPending} onChange={(event) => { readBulkFile(event.target.files?.[0]); event.target.value = '' }} /></label>
          <label className="field">Ou coller la liste<textarea rows={6} value={bulkText} placeholder={'web01,10.0.0.11,linsec-ansible,linux,production\nweb02,10.0.0.12'} onChange={(event) => applyBulkText(event.target.value)} /></label>
          {bulkError && <div className="alert error">{bulkError}</div>}
          {bulkRows.length > 0 && (
            <>
              <p className="host-import-note">{bulkRows.filter((row) => row.valid).length} ligne(s) valide(s) sur {bulkRows.length}. Doublons et erreurs de format signalés avant confirmation.</p>
              <div className="table-wrap"><table><thead><tr><th>✓</th><th>Hôte</th><th>Adresse</th><th>Environnement</th><th>Groupes</th><th>Utilisateur / clé</th><th>Validation</th></tr></thead><tbody>
                {bulkRows.map((row) => <tr key={row.key} className={row.valid ? '' : 'row-invalid'}>
                  <td><input type="checkbox" aria-label={`Sélectionner ${row.name}`} checked={row.selected} disabled={!row.valid || bulkImport.isPending} onChange={() => toggleBulkRow(row.key)} /></td>
                  <td><strong>{row.name || '—'}</strong></td>
                  <td><span className="mono">{row.ip || '—'}</span></td>
                  <td>{row.environment}</td>
                  <td>{row.groups.join(', ') || '—'}</td>
                  <td><small>{row.ansible_user} · {row.ssh_key_reference}:{row.ansible_port}</small></td>
                  <td>{row.valid ? <StatusBadge value="pass" label="Valide" /> : <span className="badge danger">{row.error}</span>}</td>
                </tr>)}
              </tbody></table></div>
              {bulkSummary && (
                <div className={bulkSummary.failed.length || bulkSummary.deployments.some((deployment) => deployment.error) ? 'alert error batch-summary' : 'alert success batch-summary'}>
                  <strong>Résultat de l’import</strong>
                  {bulkSummary.imported.map((host) => <div key={`${host.environment}-${host.name}`}>{host.name} ({host.environment}) — {host.message}</div>)}
                  {bulkSummary.failed.map((host, index) => <div key={`failed-${index}`}>{host.name || 'ligne'} — {host.message}</div>)}
                  {bulkSummary.deployments.map((deployment) => <div key={deployment.environment}>{deployment.environment}: {deployment.id ? <>déploiement <code>{deployment.id}</code> en file</> : `non lancé — ${deployment.error}`}</div>)}
                </div>
              )}
            </>
          )}
          <div className="form-actions">
            <label className="checkbox-field"><input type="checkbox" checked={bootstrapAfterAdd} onChange={(event) => setBootstrapAfterAdd(event.target.checked)} /> Lancer le déploiement / bootstrap agent après ajout ({defaultPlaybook || 'aucun playbook autorisé'})</label>
            <button className="primary" disabled={bulkImport.isPending || !bulkRows.some((row) => row.valid && row.selected)} onClick={() => bulkImport.mutate()}>{bulkImport.isPending ? 'Ajout en cours…' : `Ajouter ${bulkRows.filter((row) => row.valid && row.selected).length} hôte(s)`}</button>
          </div>
          {bulkImport.isError && <div className="alert error">{bulkImport.error instanceof Error ? bulkImport.error.message : 'Import impossible.'}</div>}
        </Modal>
      )}

      {showForm && canManageHosts && (
        <Modal
          eyebrow="Nouvel hôte"
          title="Ajout unitaire"
          description="Le compte de service SSH doit déjà exister sur la cible."
          onClose={() => setShowForm(false)}
        >
          <div className="form-grid">
            <label>Nom / alias<input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></label>
            <label>Adresse IP<input value={form.ip} onChange={(event) => { setForm({ ...form, ip: event.target.value }); setTestResult({ state: 'idle', message: '' }) }} /></label>
            <label>Environnement<select value={form.environment} onChange={(event) => setForm({ ...form, environment: event.target.value })}><option>production</option><option>staging</option><option>development</option></select></label>
            <label>Niveau<select value={form.security_level} onChange={(event) => setForm({ ...form, security_level: event.target.value })}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
            <label>Groupes<input value={form.groups} onChange={(event) => setForm({ ...form, groups: event.target.value })} placeholder="linux,servers" /></label>
            <label>Utilisateur SSH (service)<input value={form.ansible_user} onChange={(event) => setForm({ ...form, ansible_user: event.target.value })} /></label>
            <label>Port SSH<input type="number" min="1" max="65535" value={form.ansible_port} onChange={(event) => setForm({ ...form, ansible_port: Number(event.target.value) })} /></label>
            <label>Référence de clé SSH<input value={form.ssh_key_reference} onChange={(event) => setForm({ ...form, ssh_key_reference: event.target.value })} placeholder="linsec-ansible" /></label>
            <label>Mot de passe Ansible
              <input
                type="password"
                autoComplete="new-password"
                maxLength={256}
                value={form.ansible_password}
                onChange={(event) => setForm({ ...form, ansible_password: event.target.value })}
                placeholder="Optionnel — chiffré à l’ajout"
              />
            </label>
          </div>
          <p className="host-import-note">Le mot de passe est chiffré avant stockage et n’est jamais réaffiché. Laissez le champ vide pour utiliser uniquement la clé SSH.</p>
          <div className="form-actions">
            <button className="secondary" disabled={testConnection.isPending || !form.ip} onClick={() => testConnection.mutate()}>{testConnection.isPending ? 'Test…' : 'Tester la connexion / détecter l’OS'}</button>
            <label className="checkbox-field"><input type="checkbox" checked={bootstrapAfterAdd} onChange={(event) => setBootstrapAfterAdd(event.target.checked)} /> Déployer après ajout</label>
          </div>
          {testResult.state !== 'idle' && <div className={`alert ${testResult.state === 'ok' ? 'success' : testResult.state === 'failed' ? 'error' : ''}`}>{testResult.message}</div>}
          {createHost.isError && <div className="alert error">{createHost.error instanceof Error ? createHost.error.message : 'Ajout impossible.'}</div>}
          <div className="form-actions"><button className="secondary" onClick={() => setShowForm(false)}>Annuler</button><button className="primary" disabled={createHost.isPending || !form.name || !form.ip || !form.ansible_user} onClick={() => createHost.mutate()}>{createHost.isPending ? 'Ajout…' : 'Ajouter l’hôte'}</button></div>
        </Modal>
      )}

      {editingHost && (
        <Modal eyebrow="Édition" title={`Modifier ${editingHost.name}`} onClose={() => setEditingHost(null)}>
          <div className="form-grid">
            <label>Adresse IP<input value={editForm.ip} onChange={(event) => setEditForm({ ...editForm, ip: event.target.value })} /></label>
            <label>Niveau de sécurité<select value={editForm.security_level} onChange={(event) => setEditForm({ ...editForm, security_level: event.target.value })}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
            <label>Groupes<input value={editForm.groups} onChange={(event) => setEditForm({ ...editForm, groups: event.target.value })} /></label>
            <label>Utilisateur SSH<input value={editForm.ansible_user} onChange={(event) => setEditForm({ ...editForm, ansible_user: event.target.value })} /></label>
            <label>Port SSH<input type="number" min="1" max="65535" value={editForm.ansible_port} onChange={(event) => setEditForm({ ...editForm, ansible_port: Number(event.target.value) })} /></label>
            <label>Référence de clé SSH<input value={editForm.ssh_key_reference} onChange={(event) => setEditForm({ ...editForm, ssh_key_reference: event.target.value })} /></label>
          </div>
          {updateHost.isError && <div className="alert error">{updateHost.error instanceof Error ? updateHost.error.message : 'Modification impossible.'}</div>}
          <div className="form-actions"><button className="secondary" onClick={() => setEditingHost(null)}>Annuler</button><button className="primary" disabled={updateHost.isPending || !editForm.ip} onClick={() => updateHost.mutate({ id: editingHost.id, body: { ...editForm, groups: editForm.groups.split(',').map((group) => group.trim()).filter(Boolean) } })}>Enregistrer</button></div>
        </Modal>
      )}

      {terminalHost && <HostTerminal host={terminalHost} onClose={() => setTerminalHost(null)} />}

      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Parc</p><h2>Serveurs enregistrés</h2></div><span className="badge muted">{formatNumber(data.length)} hôte(s)</span></div>
        <div className="filter-bar">
          <label><Search /> <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Rechercher hôte, IP, groupe, OS…" /></label>
          <select value={environmentFilter} onChange={(event) => setEnvironmentFilter(event.target.value)}><option value="">Tous les environnements</option>{environments.map((value) => <option key={value}>{value}</option>)}</select>
          <select value={osFilter} onChange={(event) => setOsFilter(event.target.value)}><option value="">Tous les OS</option>{operatingSystems.map((value) => <option key={value}>{value}</option>)}</select>
          <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}><option value="">Tous les statuts</option><option value="reachable">Joignable</option><option value="failed">En échec</option><option value="secured">Sécurisé</option><option value="pending">En attente</option></select>
        </div>
        {canManageHosts && selectedCount > 0 && (
          <div className="bulk-actions">
            <span className="badge info">{selectedCount} sélectionné(s)</span>
            <button className="secondary" onClick={() => groupedAction.mutate({ playbook: 'wazuh-agent.yml', label: 'Agent Wazuh' })}>Installer / mettre à jour l’agent</button>
            <button className="secondary" onClick={() => groupedAction.mutate({ playbook: 'verify.yml', label: 'Contrôle baseline' })}>Vérifier la baseline</button>
            <button className="secondary" onClick={() => groupedAction.mutate({ playbook: 'site.yml', label: 'Baseline' })}>Appliquer la baseline</button>
            <button className="secondary" onClick={() => groupedAction.mutate({ playbook: 'openscap-scan.yml', label: 'Audit OpenSCAP' })}>Auditer (OpenSCAP)</button>
            <button className="secondary" onClick={() => groupedAction.mutate({ playbook: 'openscap-remediate.yml', label: 'Remédiation OpenSCAP' })}>Remédier</button>
          </div>
        )}
        {Object.entries(actionStates).map(([key, value]) => <div className="task-progress" key={key}><span className="spinner" />{key} — {value}</div>)}
        <DataTable
          headers={['', 'Hôte', 'Adresse IP', 'OS', 'Environnement', 'Statut', 'SSH', 'Actions']}
          empty="Aucun hôte enregistré"
          rows={filtered.map((host) => [
            <input key={`check-${host.id}`} type="checkbox" aria-label={`Sélectionner ${host.name}`} checked={selectedIds.includes(host.id)} onChange={() => setSelectedIds((current) => current.includes(host.id) ? current.filter((id) => id !== host.id) : [...current, host.id])} />,
            <div className="cell-title" key={`name-${host.id}`}><span className="avatar-sm">{initials(host.name)}</span><div className="cell-stack"><strong>{host.name}</strong><small>{host.groups.join(', ') || 'sans groupe'}</small></div></div>,
            <span className="mono" key={`ip-${host.id}`}>{host.ip}</span>,
            <span className="badge muted" key={`os-${host.id}`}>{host.os ?? 'Non détecté'}</span>,
            <span className={`badge ${host.environment === 'production' ? 'warning' : 'muted'}`} key={`env-${host.id}`}>{host.environment}{host.environment === 'production' && ' · sensible'}</span>,
            <StatusBadge value={host.status} key={`status-${host.id}`} />,
            <div className="cell-stack" key={`ssh-${host.id}`} title={host.ssh_error ?? ''}><StatusBadge value={host.ssh_status} />{host.ssh_error && <small className="host-ssh-error">{host.ssh_error}</small>}</div>,
            <div className="actions" key={`actions-${host.id}`}>
              <button className="link-button" onClick={() => setTerminalHost(host)}><Terminal /> Terminal</button>
              {canManageHosts && <button className="link-button" onClick={() => { setShowForm(false); setEditingHost(host); setEditForm({ ip: host.ip, security_level: host.security_level, groups: host.groups.join(','), ansible_user: host.ansible_user, ansible_port: host.ansible_port, ssh_key_reference: host.ssh_key_reference }) }}>Modifier</button>}
              <button className="link-button" onClick={() => navigate(`/hosts/${host.id}`)}>Posture</button>
              {currentUser.data?.role === 'admin' && <button className="link-button danger-link" disabled={deleteHost.isPending} onClick={() => { if (window.confirm(`Supprimer ${host.name} ? Cette action met aussi à jour l’inventaire Ansible.`)) deleteHost.mutate(host.id) }}>Supprimer</button>}
            </div>,
          ])}
        />
        {deleteHost.isError && <div className="alert error">{deleteHost.error instanceof Error ? deleteHost.error.message : 'Suppression impossible.'}</div>}
      </article>
    </div>
  )
}

function HostTerminal({ host, onClose }: { host: Host; onClose: () => void }) {
  const [connected, setConnected] = useState(false)
  const [status, setStatus] = useState('Connexion au terminal…')
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)
  const surfaceRef = useRef<HTMLDivElement | null>(null)
  const termRef = useRef<XTerm | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const socketRef = useRef<WebSocket | null>(null)

  const sendResize = () => {
    const term = termRef.current
    const socket = socketRef.current
    if (!term || socket?.readyState !== WebSocket.OPEN) return
    const { cols, rows } = term
    socket.send(JSON.stringify({ type: 'resize', cols, rows }))
  }

  useEffect(() => {
    const surface = surfaceRef.current
    if (!surface) return

    const term = new XTerm({
      cursorBlink: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize: 13,
      lineHeight: 1.4,
      scrollback: 5000,
      theme: {
        background: '#08111f',
        foreground: '#d7e6f7',
        cursor: '#7dd3fc',
        cursorAccent: '#08111f',
        selectionBackground: 'rgba(125, 211, 252, 0.28)',
        black: '#0b1220',
        red: '#f87171',
        green: '#4ade80',
        yellow: '#fbbf24',
        blue: '#60a5fa',
        magenta: '#c084fc',
        cyan: '#22d3ee',
        white: '#e2e8f0',
        brightBlack: '#64748b',
        brightRed: '#fca5a5',
        brightGreen: '#86efac',
        brightYellow: '#fde68a',
        brightBlue: '#93c5fd',
        brightMagenta: '#d8b4fe',
        brightCyan: '#67e8f9',
        brightWhite: '#f8fafc',
      },
    })
    const fitAddon = new FitAddon()
    term.loadAddon(fitAddon)
    term.open(surface)
    termRef.current = term
    fitRef.current = fitAddon

    const socket = new WebSocket(api.terminalUrl(host.id))
    socketRef.current = socket
    socket.onopen = () => {
      setConnected(true)
      setStatus('Connecté')
      term.writeln('\x1b[32mSession connectée.\x1b[0m')
    }
    socket.onmessage = (event) => {
      try {
        const message = JSON.parse(String(event.data)) as { type: string; data?: string; message?: string }
        if (message.type === 'output') {
          term.write(message.data ?? '')
        } else if (message.type === 'status') {
          setStatus(message.message ?? 'Session ouverte')
          term.writeln(`\x1b[36m${message.message ?? ''}\x1b[0m`)
        } else if (message.message) {
          term.writeln(`\x1b[33m${message.message}\x1b[0m`)
        }
      } catch {
        term.write(String(event.data))
      }
    }
    socket.onerror = () => setStatus('Erreur de connexion')
    socket.onclose = () => {
      setConnected(false)
      setStatus('Session fermée')
      term.writeln('\r\n\x1b[33mSession terminée.\x1b[0m')
    }

    const input = term.onData((data) => {
      if (socket.readyState !== WebSocket.OPEN) return
      socket.send(JSON.stringify({ type: 'input', data }))
    })

    try {
      fitAddon.fit()
      sendResize()
    } catch {
      // The drawer may still be hidden while it animates in.
    }
    term.focus()

    const observer = new ResizeObserver(() => {
      try {
        fitAddon.fit()
        sendResize()
      } catch {
        // Ignore transient zero-sized layouts.
      }
    })
    observer.observe(surface)

    return () => {
      observer.disconnect()
      input.dispose()
      socket.close()
      socketRef.current = null
      term.dispose()
      termRef.current = null
      fitRef.current = null
    }
  }, [host.id])

  useEffect(() => {
    try {
      fitRef.current?.fit()
      sendResize()
    } catch {
      // Ignore transient zero-sized layouts.
    }
  }, [expanded])

  useEffect(() => {
    if (!copied) return
    const timer = window.setTimeout(() => setCopied(false), 1600)
    return () => window.clearTimeout(timer)
  }, [copied])

  const copySelection = async () => {
    const selection = termRef.current?.getSelection() ?? ''
    if (!selection) return
    await navigator.clipboard.writeText(selection)
    setCopied(true)
    termRef.current?.focus()
  }

  return (
    <div className="drawer-backdrop" role="presentation" onClick={onClose}>
      <aside className={`terminal-drawer${expanded ? ' expanded' : ''}`} onClick={(event) => event.stopPropagation()}>
        <header className="terminal-header">
          <div className="terminal-title">
            <Terminal size={19} />
            <div><p className="eyebrow">Terminal interactif</p><h2>{host.name} <span className="mono">{host.ansible_user}@{host.ip}</span></h2></div>
          </div>
          <div className="terminal-tools">
            <button className="icon-button" title={copied ? 'Copié' : 'Copier la sélection'} aria-label="Copier la sélection" onClick={() => void copySelection()}>{copied ? <Check /> : <Copy />}</button>
            <button className="icon-button" title="Effacer l’affichage" aria-label="Effacer l’affichage" onClick={() => { termRef.current?.clear(); termRef.current?.focus() }}><Trash2 /></button>
            <button className="icon-button" title={expanded ? 'Réduire' : 'Agrandir'} aria-label={expanded ? 'Réduire' : 'Agrandir'} onClick={() => setExpanded((value) => !value)}>{expanded ? <Minimize2 /> : <Maximize2 />}</button>
            <button className="secondary" onClick={onClose}><X /> Fermer</button>
          </div>
        </header>
        <div className="terminal-meta">
          <StatusBadge value={connected ? 'connected' : 'pending'} label={connected ? 'Connecté' : 'Connexion…'} />
          {host.environment === 'production' && <span className="badge warning">Hôte sensible / production</span>}
          <span className="terminal-meta-hint">Saisissez directement dans le terminal · Copiez avec la souris</span>
        </div>
        <div className="terminal-surface" ref={surfaceRef} onClick={() => termRef.current?.focus()} />
        <footer className="terminal-statusbar">
          <span className={`terminal-dot${connected ? ' online' : ''}`} />
          <span>{status}</span>
          <span className="terminal-status-spacer" />
          <span className="mono">{host.ansible_user}@{host.ip}</span>
          <span>Session authentifiée et journalisée · aucune vérification d’empreinte SSH</span>
        </footer>
      </aside>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Host detail                                                         */
/* ------------------------------------------------------------------ */

function HostDetail() {
  const { hostId = '' } = useParams()
  const id = Number(hostId)
  const navigate = useNavigate()
  const client = useQueryClient()
  const { notify } = useNotifications()
  const host = useQuery({ queryKey: ['host', id], queryFn: () => api.host(id), enabled: Number.isInteger(id) })
  const posture = useQuery({ queryKey: ['host-posture', id], queryFn: () => api.hostPosture(id), enabled: Number.isInteger(id) })
  const stack = useQuery({ queryKey: ['stack-configuration'], queryFn: api.stackConfiguration })
  const [terminalOpen, setTerminalOpen] = useState(false)
  const [actionTask, setActionTask] = useState<TaskFeedbackState | null>(null)
  const [actionBusy, setActionBusy] = useState(false)
  const [testMessage, setTestMessage] = useState('')

  if (host.isLoading) return <Loading label="Chargement de la fiche hôte…" />
  if (host.isError || !host.data) return <div className="alert error">Hôte introuvable.</div>

  const current = host.data
  const currentPosture = posture.data
  const launch = async (playbook: string, label: string, extraVars: Record<string, string> = {}) => {
    if (actionBusy) return
    setActionBusy(true)
    setActionTask({ label, state: 'pending', message: 'Mise en file…' })
    try {
      const deployment = await api.createDeployment({
        environment: current.environment,
        playbook,
        hosts: [current.name],
        extra_vars: extraVars,
      })
      setActionTask({ label, id: deployment.id, state: 'queued', message: `Tâche ${deployment.id} en file` })
      void client.invalidateQueries({ queryKey: ['deployments'] })
      const job = await refreshAfterDeployment(client, deployment.id, [
        ['host-posture', id],
        ['hosts'],
        ['kpis'],
        ['deployments'],
      ], notify, label)
      setActionTask(taskFromDeployment(label, job, deployment.id))
    } catch (cause) {
      setActionTask({ label, state: 'error', message: cause instanceof Error ? cause.message : 'Échec' })
    } finally {
      setActionBusy(false)
    }
  }
  const pendingFindings = currentPosture?.patch_findings.filter((finding) => finding.status !== 'resolved') ?? []
  const rebootRequired = pendingFindings.some((finding) => finding.reboot_required)
  const openscapExtraVars: Record<string, string> = currentPosture?.compliance?.profile
    ? { openscap_profile: currentPosture.compliance.profile }
    : {}
  const patchExtraVars = buildPatchExtraVars(pendingFindings)

  return (
    <div className="page">
      <PageHeader
        eyebrow="Fiche serveur"
        title={current.name}
        description={`${current.ip} · ${current.environment} · ${current.os ?? 'OS non détecté'} · utilisateur de service ${current.ansible_user}`}
        actions={<>
          <button className="secondary" onClick={() => setTerminalOpen(true)}><Terminal /> Terminal</button>
          {stack.data?.wazuh_dashboard_url && <a className="secondary button-link" href={stack.data.wazuh_dashboard_url} target="_blank" rel="noreferrer">Wazuh <ArrowUpRight /></a>}
          <button className="secondary" onClick={() => navigate('/hosts')}>Retour</button>
        </>}
      />
      {current.environment === 'production' && <div className="alert warning"><TriangleAlert /> Hôte de production : toute remédiation peut impacter SSH, le pare-feu ou des services métier.</div>}
      {current.credential_status === 'undecryptable' && <div className="alert warning"><TriangleAlert /> Mot de passe Ansible stocké illisible : les déploiements utilisent la clé SSH. Saisissez à nouveau le mot de passe via l’API si l’authentification par mot de passe est requise.</div>}
      <div className="metrics-grid three">
        <StatCard label="Conformité OpenSCAP" item={{ value: currentPosture?.compliance?.score ?? null, status: currentPosture?.compliance ? 'ok' : 'unknown' }} icon={ShieldCheck} tone="success" suffix="%" />
        <StatCard label="Agent Wazuh" item={{ value: currentPosture?.agent ? 1 : 0, status: currentPosture?.agent?.status === 'active' ? 'ok' : 'unknown' }} icon={Radar} tone="cyan" hint={currentPosture?.agent?.status ?? 'aucun agent'} />
        <StatCard label="Correctifs en attente" item={{ value: pendingFindings.length, status: pendingFindings.length ? 'stale' : 'ok' }} icon={Boxes} tone={pendingFindings.length ? 'warning' : 'success'} hint={rebootRequired ? 'redémarrage requis' : 'pas de redémarrement'} />
      </div>

      {terminalOpen && <HostTerminal host={current} onClose={() => setTerminalOpen(false)} />}

      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Agents & prérequis</p><h2>Connectivité et prerequisites</h2></div><StatusBadge value={current.ssh_status} /></div>
        <div className="detail-grid">
          <div><span>Utilisateur Ansible</span><strong>{current.ansible_user}</strong></div>
          <div><span>Référence de clé</span><strong>{current.ssh_key_reference}</strong></div>
          <div><span>Port SSH</span><strong>{current.ansible_port}</strong></div>
          <div><span>Dernier test</span><strong>{formatDateTime(current.last_ssh_test_at)}</strong></div>
        </div>
        <div className="form-actions">
          <button className="secondary" onClick={async () => {
            setTestMessage('Test en cours…')
            try {
              const result = await api.testHostSSH(id)
              setTestMessage(result.reachable ? `Connexion OK${result.detected_os ? ` · ${result.detected_os}` : ''}` : result.message)
              void client.invalidateQueries({ queryKey: ['host', id] })
            } catch (cause) {
              setTestMessage(cause instanceof Error ? cause.message : 'Test impossible.')
            }
          }}>Tester la connexion / détecter l’OS</button>
          <button className="secondary" disabled={actionBusy} onClick={() => void launch('wazuh-agent.yml', 'Agent Wazuh')}>Installer / mettre à jour l’agent Wazuh</button>
          <button className="secondary" disabled={actionBusy} onClick={() => void launch('verify.yml', 'Baseline')}>Vérifier la baseline</button>
          <button className="secondary" disabled={actionBusy} onClick={() => void launch('site.yml', 'Baseline')}>Appliquer la baseline</button>
        </div>
        {testMessage && <p className="host-import-note">{testMessage}</p>}
      </article>

      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Durcissement</p><h2>OpenSCAP — audit, remédiation, re-contrôle</h2></div><StatusBadge value={currentPosture?.compliance?.status ?? 'unknown'} /></div>
        <p className="host-import-note">Les rapports avant/après sont générés dans <code>/var/log/linsec360/</code>. La remédiation filtre les règles qui coupent SSH et n’ouvre pas les ports Wazuh 1514/1515.</p>
        <div className="form-actions">
          <button className="secondary" disabled={actionBusy} onClick={() => void launch('openscap-scan.yml', 'Audit', openscapExtraVars)}>1. Auditer (Scan)</button>
          <button className="danger" disabled={actionBusy} onClick={() => {
            if (window.confirm('La remédiation peut modifier SSH, le pare-feu ou des services. Les règles SSH et Wazuh sont exclues. Continuer ?')) void launch('openscap-remediate.yml', 'Remédiation', openscapExtraVars)
          }}>2. Remédier</button>
          <button className="secondary" disabled={actionBusy} onClick={() => void launch('compliance-verify.yml', 'Re-contrôle', openscapExtraVars)}>3. Re-contrôler</button>
        </div>
        {currentPosture?.compliance && <div className="detail-grid">
          <div><span>Profil</span><strong>{currentPosture.compliance.profile}</strong></div>
          <div><span>Score</span><strong>{currentPosture.compliance.score ?? '—'}%</strong></div>
          <div><span>Dernier scan</span><strong>{formatDateTime(currentPosture.compliance.created_at)}</strong></div>
        </div>}
        {currentPosture?.hardening.length ? <DataTable headers={['Contrôle', 'Catégorie', 'Statut']} rows={currentPosture.hardening.map((check) => [<strong key={check.id}>{check.control}</strong>, <span key={`cat-${check.id}`}>{check.category}</span>, <StatusBadge key={`st-${check.id}`} value={check.status} />])} /> : null}
      </article>

      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Patching natif</p><h2>Livepatch et correctifs de sécurité</h2></div>{rebootRequired && <StatusBadge value="warning" label="Redémarrage requis" />}</div>
        <div className="detail-grid">
          <div><span>Livepatch</span><strong>{currentPosture?.livepatch?.livepatch_state ?? 'Non détecté'}</strong></div>
          <div><span>Correctifs en attente</span><strong>{pendingFindings.length}</strong></div>
          <div><span>Exposition noyau</span><strong>{currentPosture?.livepatch?.exposure_days ?? '—'} jour(s)</strong></div>
        </div>
        <div className="form-actions">
          <button className="secondary" disabled={actionBusy} onClick={() => void launch('livepatch-check.yml', 'Livepatch')}>Vérifier le livepatch</button>
          <button className="secondary" disabled={actionBusy || !patchExtraVars.patch_targets || patchExtraVars.patch_targets === '[]'} onClick={() => void launch('patch-security.yml', 'Correctifs', patchExtraVars)}>Appliquer les correctifs ciblés</button>
          <button className="secondary" disabled={actionBusy || !patchExtraVars.patch_targets || patchExtraVars.patch_targets === '[]'} onClick={() => void launch('patch-verify.yml', 'Vérification correctifs', patchExtraVars)}>Vérifier les correctifs</button>
        </div>
        {pendingFindings.length > 0 && <DataTable headers={['Paquet', 'CVE', 'Sévérité', 'Redémarrage']} rows={pendingFindings.slice(0, 20).map((finding) => [<strong key={finding.id}>{finding.package}</strong>, <span className="mono" key={`cve-${finding.id}`}>{finding.cve}</span>, <StatusBadge key={`sev-${finding.id}`} value={finding.severity} />, <span key={`reboot-${finding.id}`}>{finding.reboot_required ? 'Oui' : 'Non'}</span>])} />}
      </article>

      <TaskFeedback task={actionTask} />
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Deployments                                                         */
/* ------------------------------------------------------------------ */

const DEPLOYMENT_PAGE_SIZE = 25

function Deployments() {
  const client = useQueryClient()
  const navigate = useNavigate()
  const currentUser = useQuery({ queryKey: ['me'], queryFn: api.me })
  const canOperate = currentUser.data?.role === 'admin' || currentUser.data?.role === 'operator'
  const { notify } = useNotifications()
  const [environment, setEnvironment] = useState('')
  const [targetHosts, setTargetHosts] = useState<string[]>([])
  const [selectedPlaybook, setSelectedPlaybook] = useState('')
  const [checkMode, setCheckMode] = useState(false)
  const [filter, setFilter] = useState<'all' | 'active' | 'finished'>('all')
  const [offset, setOffset] = useState(0)
  const [createOpen, setCreateOpen] = useState(false)
  const statusParam = filter === 'active' ? 'queued,running' : filter === 'finished' ? 'succeeded,failed,cancelled' : undefined
  const deployments = useQuery({
    queryKey: ['deployments', 'list', { filter, offset }],
    queryFn: () => api.deployments({ limit: DEPLOYMENT_PAGE_SIZE, offset, status: statusParam }),
    placeholderData: keepPreviousData,
    refetchInterval: (query) => query.state.data?.items.some((job) => ['queued', 'running'].includes(job.status)) ? 5000 : false,
  })
  const statusTotals = useQuery({
    queryKey: ['deployments', 'totals'],
    queryFn: async () => {
      const [active, succeeded, failed] = await Promise.all([
        api.deployments({ limit: 1, status: 'queued,running' }),
        api.deployments({ limit: 1, status: 'succeeded' }),
        api.deployments({ limit: 1, status: 'failed,cancelled' }),
      ])
      return { active: active.total, succeeded: succeeded.total, failed: failed.total }
    },
  })
  const hosts = useQuery({ queryKey: ['hosts'], queryFn: () => api.hosts({ limit: 500 }) })
  const playbooks = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks })
  const cancel = useMutation({
    mutationFn: api.cancelDeployment,
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['deployments'] })
      notify({ tone: 'warning', title: 'Déploiement annulé' })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Annulation impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const retry = useMutation({
    mutationFn: api.retryDeployment,
    onSuccess: (deployment) => {
      void client.invalidateQueries({ queryKey: ['deployments'] })
      notify({ tone: 'info', title: 'Nouvelle tentative lancée', message: `Tâche ${deployment.id} en file.`, href: `/deployments/${deployment.id}` })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Relance impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const create = useMutation({
    mutationFn: () => api.createDeployment({ environment, playbook: selectedPlaybook, hosts: targetHosts, check_mode: checkMode }),
    onSuccess: (deployment) => {
      void client.invalidateQueries({ queryKey: ['deployments'] })
      notify({ tone: 'info', title: 'Déploiement mis en file', message: `Tâche ${deployment.id} · ${selectedPlaybook}`, href: `/deployments/${deployment.id}` })
      void refreshAfterDeployment(client, deployment.id, [
        ['deployments'],
        ['kpis'],
        ['hosts'],
      ], notify, selectedPlaybook)
      navigate(`/deployments/${deployment.id}`)
    },
    onError: (cause) => notify({ tone: 'error', title: 'Lancement impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const environments = [...new Set((hosts.data ?? []).map((host) => host.environment))].sort()
  const environmentHosts = (hosts.data ?? []).filter((host) => host.environment === environment)
  const allowedPlaybooks = (playbooks.data ?? []).filter((item) => item.is_allowlisted)
  const changeFilter = (next: typeof filter) => { setFilter(next); setOffset(0) }
  if (deployments.isLoading) return <Loading label="Chargement des déploiements…" />
  const rows = deployments.data?.items ?? []
  const total = deployments.data?.total ?? 0
  const pageCount = Math.max(1, Math.ceil(total / DEPLOYMENT_PAGE_SIZE))
  const page = Math.floor(offset / DEPLOYMENT_PAGE_SIZE) + 1
  const goToPage = (next: number) => setOffset(Math.max(0, Math.min(next - 1, pageCount - 1)) * DEPLOYMENT_PAGE_SIZE)
  return (
    <div className="page">
      <PageHeader
        eyebrow="Automatisation"
        title="Déploiements"
        description={`${formatNumber(total)} exécution(s) · ${formatNumber(statusTotals.data?.active ?? 0)} en cours · ${formatNumber(statusTotals.data?.succeeded ?? 0)} réussie(s) · ${formatNumber(statusTotals.data?.failed ?? 0)} échouée(s)`}
        actions={canOperate && <button className="primary" onClick={() => setCreateOpen(true)}><Plus /> Nouvelle exécution</button>}
      />
      {(deployments.isError || hosts.isError) && <div className="alert error">Impossible de charger les déploiements ou les hôtes cibles. Vérifiez la session puis réessayez.</div>}
      {canOperate && createOpen && (
        <Modal eyebrow="Nouvelle exécution" title="Lancer un playbook" onClose={() => setCreateOpen(false)}>
          <div className="form-grid">
            <label>Environnement<select value={environment} onChange={(event) => { setEnvironment(event.target.value); setTargetHosts([]) }}><option value="">Sélectionner</option>{environments.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
            <label>Playbook<select value={selectedPlaybook} onChange={(event) => setSelectedPlaybook(event.target.value)}><option value="">Sélectionner</option>{allowedPlaybooks.map((item) => <option key={item.filename} value={item.filename}>{item.filename}</option>)}</select></label>
            <label>Hôtes cibles<select multiple value={targetHosts} onChange={(event) => setTargetHosts(Array.from(event.target.selectedOptions, (option) => option.value))}>{environmentHosts.map((host) => <option key={host.id} value={host.name}>{host.name}</option>)}</select></label>
            <label className="check-control"><input type="checkbox" checked={checkMode} onChange={(event) => setCheckMode(event.target.checked)} /> Check mode</label>
          </div>
          {create.isError && <div className="alert error">{create.error instanceof Error ? create.error.message : 'Création du déploiement impossible.'}</div>}
          <div className="form-actions"><button className="primary" disabled={create.isPending || !environment || !selectedPlaybook || targetHosts.length === 0} onClick={() => create.mutate()}>{create.isPending ? 'Mise en file…' : checkMode ? 'Prévisualiser' : 'Lancer'}</button></div>
        </Modal>
      )}
      {(cancel.isError || retry.isError) && <div className="alert error">{cancel.isError ? (cancel.error instanceof Error ? cancel.error.message : 'Annulation impossible.') : (retry.error instanceof Error ? retry.error.message : 'Relance impossible.')}</div>}
      <article className="panel">
        <div className="panel-heading">
          <div><p className="eyebrow">Historique</p><h2>Exécutions Ansible</h2></div>
          <div className="segmented">
            <button className={filter === 'all' ? 'active' : ''} onClick={() => changeFilter('all')}>Toutes</button>
            <button className={filter === 'active' ? 'active' : ''} onClick={() => changeFilter('active')}>En cours</button>
            <button className={filter === 'finished' ? 'active' : ''} onClick={() => changeFilter('finished')}>Terminées</button>
          </div>
        </div>
        <DataTable
          headers={['Playbook', 'Environnement', 'Cibles', 'Lancé', 'Statut', 'Actions']}
          empty="Aucun déploiement"
          rows={rows.map((job) => [
            <div className="cell-stack" key={`job-${job.id}`}><button className="link-button strong" onClick={() => navigate(`/deployments/${job.id}`)}>{job.playbook}</button><small className="mono">{job.id.slice(0, 12)}</small></div>,
            <span className="badge muted" key={`env-${job.id}`}>{job.environment}</span>,
            `${job.target_hosts.length}`,
            <span className="cell-stack" key={`time-${job.id}`}><span>{formatDateTime(job.created_at)}</span><small>{relativeTime(job.created_at)}</small></span>,
            <StatusBadge value={job.status} key={`status-${job.id}`} />,
            canOperate && (job.status === 'running' || job.status === 'queued'
              ? <button className="link-button danger-link" key={`action-${job.id}`} disabled={cancel.isPending} onClick={() => cancel.mutate(job.id)}>Annuler</button>
              : <button className="link-button" key={`action-${job.id}`} disabled={retry.isPending} onClick={() => retry.mutate(job.id)}>Réexécuter</button>),
          ])}
        />
        {pageCount > 1 && (
          <div className="pagination">
            <span>Page {page} / {pageCount} · {formatNumber(total)} exécution(s)</span>
            <div>
              <button className="secondary btn sm" disabled={page <= 1} onClick={() => goToPage(page - 1)}>Précédent</button>
              <button className="secondary btn sm" disabled={page >= pageCount} onClick={() => goToPage(page + 1)}>Suivant</button>
            </div>
          </div>
        )}
      </article>
    </div>
  )
}

function DeploymentDetail() {
  const { deploymentId = '' } = useParams()
  const [copied, setCopied] = useState(false)
  const { data: job, isLoading, isError } = useQuery({ queryKey: ['deployment', deploymentId], queryFn: () => api.deployment(deploymentId), refetchInterval: (query) => ['queued', 'running'].includes(query.state.data?.status ?? '') ? 2000 : false })
  const events = useQuery({ queryKey: ['deployment-events', deploymentId], queryFn: () => api.deploymentEvents(deploymentId), refetchInterval: job?.status === 'running' || job?.status === 'queued' ? 2000 : false })
  const log = useQuery({ queryKey: ['deployment-log', deploymentId], queryFn: () => api.deploymentLog(deploymentId), refetchInterval: job?.status === 'running' || job?.status === 'queued' ? 2000 : false })
  if (isLoading) return <Loading label="Chargement du déploiement…" />
  if (isError || !job) return <div className="alert error">Impossible de charger ce déploiement.</div>
  const duration = job.started_at && job.finished_at
    ? new Date(job.finished_at).getTime() - new Date(job.started_at).getTime()
    : null
  const copyLog = () => {
    const text = log.data ?? ''
    if (!navigator.clipboard) return
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    }).catch(() => undefined)
  }
  return (
    <div className="page">
      <PageHeader
        eyebrow="Déploiement"
        title={job.playbook}
        description={`${job.environment} · ${formatNumber(job.target_hosts.length)} cible(s) · créé ${relativeTime(job.created_at)}`}
        actions={<StatusBadge value={job.status} />}
      />
      <section className="detail-grid">
        <article className="panel detail-card"><p className="eyebrow">Environnement</p><strong>{job.environment}</strong><small>{job.target_hosts.join(', ') || 'Aucune cible'}</small></article>
        <article className="panel detail-card"><p className="eyebrow">Cibles</p><strong>{job.target_hosts.length}</strong><small>hôte(s) ciblé(s)</small></article>
        <article className="panel detail-card"><p className="eyebrow">Durée</p><strong>{duration == null ? (job.started_at ? 'En cours…' : '—') : formatDuration(duration)}</strong><small>{job.started_at ? `Démarré ${relativeTime(job.started_at)}` : 'En attente de démarrage'}</small></article>
        <article className="panel detail-card"><p className="eyebrow">Terminé</p><strong>{job.finished_at ? relativeTime(job.finished_at) : '—'}</strong><small>{job.error_message ?? 'Aucune erreur signalée'}</small></article>
      </section>
      <article className="panel log-panel">
        <div className="panel-heading"><div><p className="eyebrow">Sortie</p><h2>Journal Ansible</h2></div><button className="secondary btn sm" onClick={copyLog}>{copied ? 'Copié' : 'Copier'}</button></div>
        <pre>{log.data || 'Aucune sortie disponible.'}</pre>
      </article>
      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Journal d’exécution</p><h2>Événements</h2></div><span className="badge muted">{events.data?.length ?? 0}</span></div>
        {events.data?.length ? (
          <div className="timeline">
            {events.data.map((event, index) => (
              <div className="timeline-item" key={`${event.created_at}-${index}`}>
                <span className={`timeline-dot ${statusTone(event.level)}`} />
                <div className="timeline-body">
                  <strong>{event.event}</strong>
                  <span>{formatDateTime(event.created_at)} · {humanize(event.level)}</span>
                  {event.message && <p>{event.message}</p>}
                </div>
              </div>
            ))}
          </div>
        ) : <EmptyState icon={Activity} title="Aucun événement" description="Les événements de déploiement apparaîtront ici." />}
      </article>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Compliance                                                          */
/* ------------------------------------------------------------------ */

function Compliance() {
  const { data = [], isLoading, error } = useQuery({ queryKey: ['compliance'], queryFn: api.complianceScans })
  const hosts = useQuery({ queryKey: ['hosts'], queryFn: () => api.hosts({ limit: 500 }) })
  const profiles = useQuery({ queryKey: ['compliance-profiles'], queryFn: api.complianceProfiles })
  const summary = useQuery({ queryKey: ['compliance-summary'], queryFn: api.complianceSummary })
  const client = useQueryClient()
  const navigate = useNavigate()
  const { notify } = useNotifications()
  const [hostName, setHostName] = useState('')
  const [profile, setProfile] = useState('')
  const [scanOpen, setScanOpen] = useState(false)
  const [launchError, setLaunchError] = useState('')
  const [stepTask, setStepTask] = useState<TaskFeedbackState | null>(null)
  const [stepBusy, setStepBusy] = useState(false)
  const launchStep = async (playbook: string, label: string) => {
    if (stepBusy) return
    if (label === 'Remédier' && !window.confirm('La remédiation peut impacter SSH, le pare-feu et des services. Les règles SSH et les ports Wazuh 1514/1515 sont exclus. Continuer ?')) return
    setStepBusy(true)
    setStepTask({ label, state: 'pending', message: 'Mise en file…' })
    try {
      const deployment = await api.createDeployment({
        environment: (hosts.data ?? []).find((host) => host.name === hostName)?.environment ?? '',
        playbook,
        hosts: [hostName],
        extra_vars: profile ? { openscap_profile: profile } : {},
      })
      setStepTask({ label, id: deployment.id, state: 'queued', message: `Tâche ${deployment.id} en file` })
      void client.invalidateQueries({ queryKey: ['deployments'] })
      const job = await refreshAfterDeployment(client, deployment.id, [
        ['compliance'],
        ['compliance-summary'],
        ['kpis'],
        ['deployments'],
      ], notify, label)
      setStepTask(taskFromDeployment(label, job, deployment.id))
    } catch (cause) {
      setStepTask({ label, state: 'error', message: cause instanceof Error ? cause.message : 'Échec' })
    } finally {
      setStepBusy(false)
    }
  }
  const launch = useMutation({
    mutationFn: () => api.createDeployment({ environment: (hosts.data ?? []).find((host) => host.name === hostName)?.environment ?? '', playbook: 'openscap-scan.yml', hosts: [hostName], extra_vars: profile ? { openscap_profile: profile } : {} }),
    onSuccess: (deployment) => {
      setLaunchError('')
      setScanOpen(false)
      void client.invalidateQueries({ queryKey: ['deployments'] })
      void refreshAfterDeployment(client, deployment.id, [
        ['compliance'],
        ['compliance-summary'],
        ['kpis'],
        ['deployments'],
      ], notify, 'Audit OpenSCAP')
      navigate(`/deployments/${deployment.id}`)
    },
    onError: (cause) => setLaunchError(cause instanceof Error ? cause.message : 'Lancement impossible'),
  })
  if (isLoading) return <Loading label="Chargement des résultats OpenSCAP…" />
  if (error) return <div className="alert error">Impossible de charger la conformité.</div>
  const worst = summary.data?.worst_hosts[0]
  return (
    <div className="page">
      <PageHeader
        eyebrow="OpenSCAP"
        title="Conformité"
        description="Derniers résultats de scans, profils appliqués et score par hôte."
        actions={(
          <>
            <button className="secondary" onClick={() => void api.exportCompliance('csv')}>Exporter CSV</button>
            <button className="secondary" onClick={() => void api.exportCompliance('json')}>Exporter JSON</button>
            <button className="primary" onClick={() => setScanOpen(true)}><Plus /> Nouveau scan</button>
          </>
        )}
      />
      <section className="metrics-grid three">
        <StatCard label="Hôtes scannés" item={{ value: summary.data?.hosts_scanned ?? null, status: summary.data ? 'ok' : 'unknown' }} icon={Server} />
        <StatCard label="Score moyen" item={{ value: summary.data?.average_score ?? null, status: summary.data?.average_score != null ? 'ok' : 'unknown' }} icon={Gauge} tone="success" suffix="%" />
        <StatCard label="Hôte le plus faible" item={{ value: worst?.score ?? null, status: worst ? 'ok' : 'unknown' }} icon={TriangleAlert} tone="warning" suffix="%" hint={worst?.host} />
      </section>
      {scanOpen && (
        <Modal
          eyebrow="Nouveau scan"
          title="Lancer OpenSCAP"
          description="Audit, remédiation puis re-contrôle : suivez chaque étape depuis le déploiement correspondant."
          onClose={() => setScanOpen(false)}
        >
        <div className="form-grid three">
          <label>Hôte<select value={hostName} onChange={(event) => setHostName(event.target.value)}><option value="">Sélectionner</option>{(hosts.data ?? []).map((host) => <option key={host.id} value={host.name}>{host.name}</option>)}</select></label>
          <label>Profil<select value={profile} onChange={(event) => setProfile(event.target.value)}><option value="">Défaut du playbook</option>{(profiles.data ?? []).map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
          <div className="form-spacer"><button className="primary" disabled={!hostName || launch.isPending} onClick={() => launch.mutate()}>{launch.isPending ? 'Lancement…' : '1. Auditer (Scan)'}</button></div>
        </div>
        <p className="host-import-note">Rapports avant/après sous <code>/var/log/linsec360/</code>. La remédiation exclut les règles SSH et les ports Wazuh 1514/1515.</p>
        <div className="form-actions">
          <button className="danger" disabled={!hostName || stepBusy} onClick={() => void launchStep('openscap-remediate.yml', 'Remédier')}>2. Remédier</button>
          <button className="secondary" disabled={!hostName || stepBusy} onClick={() => void launchStep('compliance-verify.yml', 'Re-contrôle')}>3. Re-contrôler</button>
        </div>
        <TaskFeedback task={stepTask} />
        {launchError && <div className="alert error">{launchError}</div>}
        </Modal>
      )}
      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Résultats</p><h2>Scans récents</h2></div><span className="badge muted">{data.length}</span></div>
        <DataTable
          headers={['Hôte', 'Profil', 'Statut', 'Score', 'Terminé']}
          empty="Aucun scan OpenSCAP"
          rows={data.map((item) => [
            <span className="strong" key={`h-${item.id}`}>{item.host_name}</span>,
            <span className="mono" key={`p-${item.id}`}>{item.profile}</span>,
            <StatusBadge value={item.status} key={`s-${item.id}`} />,
            <span className={`badge ${scoreTone(item.score)}`} key={`score-${item.id}`}><span className="dot" />{item.score == null ? '—' : `${Math.round(item.score)}%`}</span>,
            <span className="cell-stack" key={`t-${item.id}`}><span>{formatDateTime(item.finished_at ?? item.created_at)}</span><small>{relativeTime(item.finished_at ?? item.created_at)}</small></span>,
          ])}
        />
      </article>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Patching                                                            */
/* ------------------------------------------------------------------ */

function Patching() {
  const client = useQueryClient()
  const { notify } = useNotifications()
  const { data = [], isLoading, error } = useQuery({ queryKey: ['patch-findings'], queryFn: api.patchFindings })
  const hosts = useQuery({ queryKey: ['hosts'], queryFn: () => api.hosts({ limit: 500 }) })
  const kpis = useQuery({ queryKey: ['kpis'], queryFn: api.kpis, refetchInterval: 30_000 })
  const [hostName, setHostName] = useState('')
  const [selectedFindingIds, setSelectedFindingIds] = useState<number[]>([])
  const [showActions, setShowActions] = useState(false)
  const [patchBusy, setPatchBusy] = useState(false)
  const [patchTask, setPatchTask] = useState<TaskFeedbackState | null>(null)
  const refreshQueries = () => Promise.all([
    client.invalidateQueries({ queryKey: ['patch-findings'] }),
    client.invalidateQueries({ queryKey: ['kpis'] }),
    client.invalidateQueries({ queryKey: ['deployments'] }),
  ])
  const syncWazuh = useMutation({
    mutationFn: api.syncWazuhPatches,
    onSuccess: (result) => {
      void refreshQueries()
      notify({ tone: 'info', title: 'Synchronisation Wazuh terminée', message: `${formatNumber(Number(result.updated ?? result.created ?? 0))} finding(s) mis à jour.` })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Synchronisation Wazuh impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const resolve = useMutation({
    mutationFn: api.resolvePatch,
    onSuccess: () => {
      void refreshQueries()
      notify({ tone: 'success', title: 'Correctif marqué comme résolu' })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Mise à jour impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const patchAction = async (playbook: string, label: string, extraVars: Record<string, string> = {}) => {
    if (patchBusy) return
    const target = (hosts.data ?? []).find((host) => host.name === hostName)
    if (!target) return
    setPatchBusy(true)
    setPatchTask({ label, state: 'pending', message: 'Mise en file…' })
    try {
      const deployment = await api.createDeployment({ environment: target.environment, playbook, hosts: [target.name], extra_vars: extraVars })
      setPatchTask({ label, id: deployment.id, state: 'queued', message: `Tâche ${deployment.id} en file` })
      void client.invalidateQueries({ queryKey: ['deployments'] })
      const job = await refreshAfterDeployment(client, deployment.id, [
        ['patch-findings'],
        ['kpis'],
        ['deployments'],
      ], notify, label)
      setPatchTask(taskFromDeployment(label, job, deployment.id))
    } catch (cause) {
      setPatchTask({ label, state: 'error', message: cause instanceof Error ? cause.message : 'Échec' })
    } finally {
      setPatchBusy(false)
    }
  }
  if (isLoading) return <Loading label="Chargement des correctifs…" />
  if (error) return <div className="alert error">Impossible de charger les correctifs.</div>
  const open = data.filter((finding) => finding.status === 'open')
  const critical = open.filter((finding) => finding.severity === 'critical').length
  const high = open.filter((finding) => finding.severity === 'high').length
  const reboots = open.filter((finding) => finding.reboot_required).length
  const hostFindings = data.filter((finding) => finding.host_name === hostName && finding.status !== 'resolved')
  const selectedFindings = selectedFindingIds.length
    ? hostFindings.filter((finding) => selectedFindingIds.includes(finding.id))
    : hostFindings
  const patchExtraVars = buildPatchExtraVars(selectedFindings)
  return (
    <div className="page">
      <PageHeader
        eyebrow="Patching"
        title="Correctifs"
        description="Vulnérabilités Wazuh et état du live patching noyau."
        actions={(
          <>
            <button className="secondary" disabled={syncWazuh.isPending} onClick={() => syncWazuh.mutate()}><RefreshCw /> Synchroniser Wazuh</button>
            <button className="primary" onClick={() => setShowActions(true)}><Play /> Actions correctifs</button>
          </>
        )}
      />
      {syncWazuh.isError && <div className="alert error">{syncWazuh.error instanceof Error ? syncWazuh.error.message : 'Synchronisation Wazuh impossible.'}</div>}
      <section className="metrics-grid">
        <StatCard label="Correctifs ouverts" item={{ value: open.length, status: 'ok' }} icon={Boxes} tone="danger" hint="findings" />
        <StatCard label="Critiques" item={{ value: critical, status: 'ok' }} icon={ShieldAlert} tone="danger" />
        <StatCard label="Élevés" item={{ value: high, status: 'ok' }} icon={TriangleAlert} tone="warning" />
        <StatCard label="Redémarrages requis" item={{ value: reboots, status: 'ok' }} icon={RefreshCw} tone="violet" />
        <StatCard label="Total findings" item={{ value: data.length, status: 'ok' }} icon={Database} hint="toutes sources" />
      </section>
      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Patching natif</p><h2>Livepatch & correctifs ciblés</h2></div><StatusBadge value={reboots ? 'warning' : 'success'} label={reboots ? `${formatNumber(reboots)} redémarrage(s) requis` : 'Aucun redémarrage requis'} /></div>
        <p className="host-import-note">Exposition noyau : {kpis.data?.kernel_exposure_days.value ?? '—'} jour(s). Trois actions distinctes : vérifier l’état du livepatch, appliquer les correctifs paquet, puis re-contrôler qu’ils sont installés. Le redémarrage reste manuel.</p>
        <div className="form-actions">
          <button className="secondary" onClick={() => setShowActions(true)}>Ouvrir les actions correctifs</button>
        </div>
        <TaskFeedback task={patchTask} />
      </article>
      {showActions && (
        <Modal
          eyebrow="Patching natif"
          title="Actions correctifs"
          description="Chaque action crée un déploiement Ansible traçable : vous pouvez suivre sa progression et consulter son journal."
          onClose={() => setShowActions(false)}
        >
          <div className="form-grid three">
            <label>Hôte<select value={hostName} onChange={(event) => { setHostName(event.target.value); setSelectedFindingIds([]) }}><option value="">Sélectionner</option>{(hosts.data ?? []).map((host) => <option key={host.id} value={host.name}>{host.name}</option>)}</select></label>
            <div className="detail-card"><p className="eyebrow">Exposition noyau</p><strong>{kpis.data?.kernel_exposure_days.value ?? '—'} jour(s)</strong></div>
            <div className="form-spacer"><StatusBadge value={reboots ? 'warning' : 'success'} label={reboots ? `${formatNumber(reboots)} redémarrage(s) requis` : 'Aucun redémarrage requis'} /></div>
          </div>
          <p className="host-import-note">Sélectionnez les correctifs à traiter dans le tableau ci-dessous. Sans sélection, tous les correctifs en attente de l’hôte sont ciblés.</p>
          <div className="patch-actions">
            <div className="patch-action-card">
              <strong>Vérifier le livepatch</strong>
              <p>Vérification en lecture seule de l’état du livepatch du noyau. Cette action n’applique aucun correctif paquet et ne remplace pas la vérification des correctifs.</p>
              <button className="secondary" disabled={!hostName || patchBusy} onClick={() => void patchAction('livepatch-check.yml', 'Vérifier le livepatch')}>Vérifier le livepatch</button>
            </div>
            <div className="patch-action-card">
              <strong>Appliquer les correctifs ciblés</strong>
              <p>Installe les paquets correctifs (playbook <code>patch-security.yml</code>) pour les paquets et CVE sélectionnés.</p>
              <button className="primary" disabled={!hostName || !selectedFindings.length || patchBusy} onClick={() => void patchAction('patch-security.yml', 'Appliquer les correctifs', patchExtraVars)}>Appliquer les correctifs ciblés</button>
            </div>
            <div className="patch-action-card">
              <strong>Vérifier les correctifs</strong>
              <p>Re-contrôle après application (playbook <code>patch-verify.yml</code>) : compare la version installée à la version corrigée attendue.</p>
              <button className="secondary" disabled={!hostName || !selectedFindings.length || patchBusy} onClick={() => void patchAction('patch-verify.yml', 'Vérifier les correctifs', patchExtraVars)}>Vérifier les correctifs</button>
            </div>
          </div>
          <TaskFeedback task={patchTask} />
        </Modal>
      )}
      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Vulnérabilités</p><h2>Correctifs détectés</h2></div><span className="badge muted">{data.length}</span></div>
        <DataTable
          headers={['', 'Hôte', 'Paquet', 'CVE', 'Errata', 'Sévérité', 'Source', 'Statut', 'Action']}
          empty="Aucun correctif connu"
          rows={data.map((finding: PatchFinding) => [
            finding.status !== 'resolved'
              ? <input
                  key={`sel-${finding.id}`}
                  type="checkbox"
                  aria-label={`Sélectionner ${finding.package} sur ${finding.host_name}`}
                  disabled={finding.host_name !== hostName}
                  checked={selectedFindingIds.includes(finding.id)}
                  onChange={() => setSelectedFindingIds((current) => current.includes(finding.id) ? current.filter((id) => id !== finding.id) : [...current, finding.id])}
                />
              : <span key={`sel-${finding.id}`}>—</span>,
            <span className="strong" key={`h-${finding.id}`}>{finding.host_name}</span>,
            <span className="mono" key={`p-${finding.id}`}>{finding.package}</span>,
            <span className="mono" key={`c-${finding.id}`}>{finding.cve || '—'}</span>,
            <span key={`e-${finding.id}`}>{finding.errata || '—'}</span>,
            <StatusBadge value={finding.severity} key={`sev-${finding.id}`} />,
            <span className="badge muted" key={`src-${finding.id}`}>{finding.source}</span>,
            <StatusBadge value={finding.status} key={`st-${finding.id}`} />,
            finding.status !== 'resolved'
              ? <button className="link-button" key={`a-${finding.id}`} disabled={resolve.isPending} onClick={() => resolve.mutate(finding.id)}>Résoudre</button>
              : <span key={`a-${finding.id}`}>—</span>,
          ])}
        />
      </article>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Detection                                                           */
/* ------------------------------------------------------------------ */

function Detection() {
  const client = useQueryClient()
  const { notify } = useNotifications()
  const { data = [], isLoading, error } = useQuery({
    queryKey: ['alerts'],
    queryFn: api.alerts,
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  })
  const summary = useQuery({
    queryKey: ['alert-summary'],
    queryFn: api.alertSummary,
    retry: false,
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  })
  const refreshDetection = () => {
    void client.invalidateQueries({ queryKey: ['alerts'] })
    void client.invalidateQueries({ queryKey: ['patch-findings'] })
    void client.invalidateQueries({ queryKey: ['alert-summary'] })
  }
  const sync = useMutation({
    mutationFn: api.syncAllWazuh,
    onSuccess: () => {
      refreshDetection()
      notify({ tone: 'info', title: 'Synchronisation Wazuh terminée', message: 'Alertes et correctifs rafraîchis.' })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Synchronisation impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const ack = useMutation({
    mutationFn: api.acknowledgeAlert,
    onSuccess: () => {
      refreshDetection()
      notify({ tone: 'success', title: 'Alerte acquittée' })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Acquittement impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const response = useMutation({
    mutationFn: ({ id, action }: { id: number; action: 'firewall-drop' | 'disable-account' }) => api.activeResponse(id, action),
    onSuccess: (_result, variables) => {
      refreshDetection()
      notify({ tone: 'warning', title: 'Réponse active envoyée', message: variables.action === 'firewall-drop' ? 'Blocage IP demandé.' : 'Compte désactivé.' })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Réponse active impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const [severity, setSeverity] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all')
  if (isLoading) return <Loading label="Chargement des alertes…" />
  if (error) return <div className="alert error">Impossible de charger les alertes.</div>
  const severityRows = summary.data?.by_severity ?? {}
  const totalBySeverity = Object.values(severityRows).reduce((sum, count) => sum + count, 0)
  const unacknowledged = summary.data ? Object.values(summary.data.unacknowledged).reduce((sum, count) => sum + count, 0) : null
  const visible = data.filter((alert) => severity === 'all' || alert.severity === severity)
  return (
    <div className="page">
      <PageHeader
        eyebrow="Wazuh"
        title="Détection"
        description="Alertes Wazuh, acquittement et réponse active. La synchronisation récupère les agents via l’API Wazuh et les alertes via l’Indexer."
        actions={<button className="secondary" disabled={sync.isPending} onClick={() => sync.mutate()}><RefreshCw />{sync.isPending ? 'Récupération…' : 'Récupérer depuis Wazuh'}</button>}
      />
      {sync.isError && <div className="alert error">{sync.error instanceof Error ? sync.error.message : 'Synchronisation Wazuh impossible'}</div>}
      {sync.data && <div className="alert success">Récupération terminée : {sync.data.agents.agents} agent(s), {sync.data.alerts.fetched} alerte(s), {sync.data.vulnerabilities.created + sync.data.vulnerabilities.updated} vulnérabilité(s) actualisée(s).</div>}
      <section className="metrics-grid">
        <StatCard label="Alertes totales" item={{ value: summary.data ? totalBySeverity : null, status: summary.data ? 'ok' : 'unknown' }} icon={Radar} />
        <StatCard label="Non acquittées" item={{ value: unacknowledged, status: summary.data ? 'ok' : 'unknown' }} icon={ShieldAlert} tone="danger" />
        <StatCard label="Critiques" item={{ value: severityRows.critical ?? null, status: summary.data ? 'ok' : 'unknown' }} icon={TriangleAlert} tone="danger" />
        <StatCard label="MTTD" item={{ value: summary.data?.mean_time_to_detect_hours ?? null, status: summary.data?.mean_time_to_detect_hours != null ? 'ok' : 'unknown' }} icon={Gauge} suffix=" h" tone="violet" />
        <StatCard label="MTTR" item={{ value: summary.data?.mean_time_to_respond_hours ?? null, status: summary.data?.mean_time_to_respond_hours != null ? 'ok' : 'unknown' }} icon={RefreshCw} suffix=" h" tone="warning" />
        <StatCard label="Agents actifs" item={{ value: data.length ? new Set(data.map((alert) => alert.agent_id).filter(Boolean)).size : null, status: data.length ? 'ok' : 'unknown' }} icon={Server} hint="dans les alertes" />
      </section>
      <article className="panel">
        <div className="panel-heading">
          <div><p className="eyebrow">Flux d’alertes</p><h2>Détections récentes</h2></div>
          <div className="segmented">
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((value) => (
              <button key={value} className={severity === value ? 'active' : ''} onClick={() => setSeverity(value)}>{value === 'all' ? 'Toutes' : humanize(value)}</button>
            ))}
          </div>
        </div>
        <DataTable
          headers={['Horodatage', 'Agent', 'Sévérité', 'Règle', 'Description', 'Statut', 'Actions']}
          empty="Aucune alerte synchronisée"
          rows={visible.map((alert: Alert) => [
            <span className="cell-stack" key={`t-${alert.id}`}><span>{formatDateTime(alert.timestamp)}</span><small>{relativeTime(alert.timestamp)}</small></span>,
            <div className="cell-title" key={`a-${alert.id}`}><span className="avatar-sm">{initials(alert.agent_name ?? alert.agent_id ?? 'agent')}</span><div className="cell-stack"><strong>{alert.agent_name || alert.agent_id || '—'}</strong><small>{alert.agent_id ?? 'sans identifiant'}</small></div></div>,
            <StatusBadge value={alert.severity} key={`sev-${alert.id}`} />,
            <span className="mono" key={`r-${alert.id}`}>{alert.rule_id || '—'} · niv. {alert.rule_level ?? '—'}</span>,
            <span key={`d-${alert.id}`}>{alert.description || '—'}</span>,
            <span className={`badge ${alert.acknowledged ? 'success' : 'danger'}`} key={`ack-${alert.id}`}><span className="dot" />{alert.acknowledged ? 'Acquittée' : 'Nouvelle'}</span>,
            <div className="actions" key={`act-${alert.id}`}>
              {!alert.acknowledged && <button className="link-button" onClick={() => ack.mutate(alert.id)}>Acquitter</button>}
              <button className="link-button danger-link" disabled={response.isPending || !alert.agent_id} onClick={() => { if (window.confirm('Envoyer firewall-drop à cet agent Wazuh ?')) response.mutate({ id: alert.id, action: 'firewall-drop' }) }}>Bloquer</button>
            </div>,
          ])}
        />
      </article>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Audit                                                               */
/* ------------------------------------------------------------------ */

function Audit() {
  const { data = [], isLoading, error } = useQuery({ queryKey: ['audit'], queryFn: api.audit })
  if (isLoading) return <Loading label="Chargement de l’audit…" />
  if (error) return <div className="alert error">Impossible de charger l’audit.</div>
  return (
    <div className="page">
      <PageHeader eyebrow="Traçabilité" title="Audit" description="Journal des actions opérateur et système sur la plateforme." actions={<span className="badge muted">{data.length} événement(s)</span>} />
      <article className="panel">
        <DataTable
          headers={['Horodatage', 'Acteur', 'Action', 'Type', 'Cible']}
          empty="Aucun événement audité"
          rows={data.map((item) => [
            <span className="cell-stack" key={`t-${item.id}`}><span>{formatDateTime(item.created_at)}</span><small>{relativeTime(item.created_at)}</small></span>,
            <div className="cell-title" key={`a-${item.id}`}><span className="avatar-sm">{initials(item.actor_username ?? 'système')}</span><span className="strong">{item.actor_username || 'Système'}</span></div>,
            <span className="badge info" key={`act-${item.id}`}>{item.action}</span>,
            <span className="badge muted" key={`type-${item.id}`}>{item.target_type}</span>,
            <span className="mono" key={`cible-${item.id}`}>{item.target_id || '—'}</span>,
          ])}
        />
      </article>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Playbooks                                                           */
/* ------------------------------------------------------------------ */

function PlaybookEditor({ creating, selected, playbook, canEdit, onSaved }: {
  creating: boolean
  selected: string
  playbook?: PlaybookDetail
  canEdit: boolean
  onSaved: (saved: PlaybookDetail) => void
}) {
  const client = useQueryClient()
  const { notify } = useNotifications()
  const [filename, setFilename] = useState(playbook?.filename ?? '')
  const [description, setDescription] = useState(playbook?.description ?? '')
  const [content, setContent] = useState(playbook?.content ?? '')
  const [validation, setValidation] = useState<{ valid: boolean; detail: string } | null>(null)

  const validate = useMutation({
    mutationFn: () => api.validatePlaybook(content),
    onSuccess: (result) => {
      setValidation(result)
      notify({
        tone: result.valid ? 'success' : 'error',
        title: result.valid ? 'YAML valide' : 'YAML invalide',
        message: result.detail,
      })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Validation impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const save = useMutation({
    mutationFn: async () => {
      const result = await api.validatePlaybook(content)
      setValidation(result)
      if (!result.valid) throw new Error(result.detail)
      return creating
        ? api.createPlaybook({ filename, description, content })
        : api.updatePlaybook(selected, { description, content })
    },
    onSuccess: (saved) => {
      void client.invalidateQueries({ queryKey: ['playbooks'] })
      void client.setQueryData(['playbook', saved.filename], saved)
      onSaved(saved)
      notify({ tone: 'success', title: 'Playbook enregistré', message: saved.filename })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Enregistrement impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })

  const resetFeedback = () => {
    setValidation(null)
    validate.reset()
    save.reset()
  }
  const filenameValid = /^[A-Za-z0-9][A-Za-z0-9_.-]*\.ya?ml$/.test(filename)
  return (
    <article className="panel form-panel playbook-editor">
      <div className="panel-heading"><div><p className="eyebrow">{creating ? 'Nouveau playbook' : 'Édition'}</p><h2>{creating ? 'Créer un playbook' : filename}</h2></div>{!creating && <span className="badge success"><span className="dot" />Allowlisté</span>}</div>
      <div className="form-grid playbook-meta">
        <label>Nom du fichier{creating ? <input value={filename} onChange={(event) => { setFilename(event.target.value); resetFeedback() }} placeholder="mon-playbook.yml" disabled={!canEdit} /> : <input value={filename} readOnly />}</label>
        <label className="description-field">Description<input value={description} onChange={(event) => { setDescription(event.target.value); resetFeedback() }} readOnly={!canEdit} /></label>
      </div>
      <label className="playbook-content">Contenu YAML<textarea spellCheck={false} value={content} onChange={(event) => { setContent(event.target.value); resetFeedback() }} readOnly={!canEdit} /></label>
      <p className="validation-note">La vérification contrôle la syntaxe YAML et que la racine est une liste de plays. Elle ne lance pas Ansible et ne vérifie pas les plugins, rôles ou variables.</p>
      {validation && <div className={`alert ${validation.valid ? 'success' : 'error'}`} role="status">{validation.detail}</div>}
      {validate.isError && <div className="alert error">{validate.error instanceof Error ? validate.error.message : 'Validation impossible'}</div>}
      {save.isError && <div className="alert error">{save.error instanceof Error ? save.error.message : 'Enregistrement impossible'}</div>}
      {canEdit && <div className="form-actions playbook-actions">
        <button className="secondary" disabled={validate.isPending || !content.trim()} onClick={() => validate.mutate()}>{validate.isPending ? 'Vérification…' : 'Vérifier YAML'}</button>
        <button className="primary" disabled={save.isPending || !filenameValid} onClick={() => save.mutate()}>{save.isPending ? 'Enregistrement…' : 'Enregistrer'}</button>
      </div>}
    </article>
  )
}

function Playbooks() {
  const client = useQueryClient()
  const { notify } = useNotifications()
  const list = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks })
  const currentUser = useQuery({ queryKey: ['me'], queryFn: api.me })
  const canEdit = currentUser.data?.role === 'admin' || currentUser.data?.role === 'operator'
  const [selected, setSelected] = useState('')
  const [creating, setCreating] = useState(false)
  const detail = useQuery({
    queryKey: ['playbook', selected],
    queryFn: () => api.playbook(selected),
    enabled: Boolean(selected) && !creating,
  })
  const remove = useMutation({
    mutationFn: api.deletePlaybook,
    onSuccess: (_result, filename) => {
      setSelected('')
      setCreating(false)
      void client.invalidateQueries({ queryKey: ['playbooks'] })
      void client.invalidateQueries({ queryKey: ['playbook'] })
      notify({ tone: 'warning', title: 'Playbook supprimé', message: filename })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Suppression impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })

  const startNew = () => {
    setSelected('')
    setCreating(true)
  }
  const selectPlaybook = (name: string) => {
    setCreating(false)
    setSelected(name)
  }

  if (list.isLoading) return <Loading label="Chargement des playbooks…" />
  if (list.isError) return <div className="alert error">Impossible de charger les playbooks.</div>
  return (
    <div className="page">
      <PageHeader
        eyebrow="Automatisation"
        title="Playbooks"
        description={`${list.data?.length ?? 0} playbook(s) · validation YAML avant exécution`}
        actions={(
          <>
            {currentUser.data?.role === 'admin' && selected && !creating && <button className="danger" disabled={remove.isPending} onClick={() => { if (window.confirm(`Supprimer le playbook ${selected} ? Cette action est irréversible.`)) remove.mutate(selected) }}>Supprimer</button>}
            {canEdit && <button className="primary" onClick={startNew}><Plus /> Créer un playbook</button>}
          </>
        )}
      />
      {remove.isError && <div className="alert error">{remove.error instanceof Error ? remove.error.message : 'Suppression du playbook impossible.'}</div>}
      <div className="playbook-workspace">
        <article className="panel playbook-library">
          <div className="panel-heading"><div><p className="eyebrow">Bibliothèque</p><h2>Sélectionner un playbook</h2></div></div>
          <div className="playbook-list">
            {!list.data?.length && <span className="empty">Aucun playbook enregistré</span>}
            {(list.data ?? []).map((item) => (
              <button key={item.filename} className={`playbook-choice ${selected === item.filename && !creating ? 'selected' : ''}`} onClick={() => selectPlaybook(item.filename)}>
                <strong>{item.filename}</strong>
                <small>{item.description || 'Aucune description'}</small>
                <span className="badge muted" style={{ alignSelf: 'flex-start', marginTop: 4 }}>{item.is_allowlisted ? 'Autorisé' : 'Non autorisé'}</span>
              </button>
            ))}
          </div>
        </article>
        <div className="playbook-editor-area">
          {creating && <PlaybookEditor key="new-playbook" creating selected="" canEdit={canEdit} onSaved={(saved) => { setCreating(false); setSelected(saved.filename) }} />}
          {!creating && selected && detail.isLoading && <Loading label="Chargement du playbook…" />}
          {!creating && selected && detail.isError && <div className="alert error">Impossible de charger ce playbook.</div>}
          {!creating && detail.data && <PlaybookEditor key={selected} creating={false} selected={selected} playbook={detail.data} canEdit={canEdit} onSaved={(saved) => { setSelected(saved.filename) }} />}
          {!creating && !selected && (
            <article className="panel">
              <EmptyState icon={FileCode2} title="Sélectionnez un playbook" description="L’éditeur s’ouvre à droite de la liste, sans défilement." />
            </article>
          )}
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Settings                                                            */
/* ------------------------------------------------------------------ */

function useIntegrationTest(
  name: 'wazuh' | 'ansible',
  onSuccess: (state: IntegrationState) => void,
) {
  return useMutation({
    mutationFn: () => api.testIntegration(name),
    onSuccess,
  })
}

function StackConfigurationEditor({ onSaved }: { onSaved: () => Promise<void> }) {
  const client = useQueryClient()
  const { notify } = useNotifications()
  const configuration = useQuery({
    queryKey: ['integration-config'],
    queryFn: api.stackConfiguration,
  })
  const [edited, setEdited] = useState<StackConfiguration | null>(null)
  const form = edited ?? configuration.data

  const save = useMutation({
    mutationFn: api.updateStackConfiguration,
    onSuccess: (updated) => {
      client.setQueryData(['integration-config'], updated)
      setEdited(updated)
      void onSaved()
      notify({ tone: 'success', title: 'Configuration enregistrée', message: 'Les nouvelles valeurs sont appliquées.' })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Enregistrement impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const reset = useMutation({
    mutationFn: api.resetStackConfiguration,
    onSuccess: (updated) => {
      client.setQueryData(['integration-config'], updated)
      setEdited(updated)
      void onSaved()
      notify({ tone: 'info', title: 'Configuration restaurée', message: 'Valeurs reloadées depuis .env.' })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Restauration impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })
  const update = <K extends keyof StackConfiguration>(key: K, value: StackConfiguration[K]) => {
    if (form) {
      save.reset()
      reset.reset()
      setEdited({ ...form, [key]: value })
    }
  }
  const error = save.error ?? reset.error

  if (configuration.isError) return <div className="alert error">Impossible de charger la configuration de la stack.</div>
  if (configuration.isLoading || !form) return <Loading label="Chargement de la configuration…" />

  return (
    <section className="panel form-panel">
      <div className="panel-heading">
        <div><h3>Configuration de la stack</h3><p className="muted">Les adresses et ports sont enregistrés en base et appliqués sans redémarrage.</p></div>
      </div>
      <form onSubmit={(event) => { event.preventDefault(); save.mutate(form) }}>
        <div className="form-grid three">
          <label>Adresse Wazuh Manager (agents)
            <input type="text" value={form.wazuh_manager_address} placeholder="Détection depuis l’URL API si vide" onChange={(event) => update('wazuh_manager_address', event.target.value)} />
          </label>
          <label>Port publié pour les agents
            <input type="number" min={1} max={65535} required value={form.wazuh_manager_agent_port} onChange={(event) => update('wazuh_manager_agent_port', Number(event.target.value))} />
          </label>
          <label>Port publié pour l’enrôlement
            <input type="number" min={1} max={65535} required value={form.wazuh_manager_enrollment_port} onChange={(event) => update('wazuh_manager_enrollment_port', Number(event.target.value))} />
          </label>
          <label>URL de l’API Wazuh
            <input type="url" value={form.wazuh_api_url} placeholder="https://wazuh.manager:55000" onChange={(event) => update('wazuh_api_url', event.target.value)} />
          </label>
          <label>URL de l’Indexer Wazuh
            <input type="url" value={form.wazuh_indexer_url} placeholder="https://wazuh.indexer:9200" onChange={(event) => update('wazuh_indexer_url', event.target.value)} />
          </label>
          <label>URL du Dashboard Wazuh
            <input type="url" value={form.wazuh_dashboard_url} placeholder="https://wazuh.dashboard:5601" onChange={(event) => update('wazuh_dashboard_url', event.target.value)} />
          </label>
        </div>
        {error && <div className="alert error">{error instanceof Error ? error.message : 'Impossible d’enregistrer la configuration.'}</div>}
        {(save.isSuccess || reset.isSuccess) && <div className="alert success" role="status">Configuration enregistrée et appliquée par LinSec360.</div>}
        <p className="integration-help">Les identifiants restent dans l’environnement sécurisé du serveur. Les réglages sont appliqués par LinSec360 sans redémarrage. Si vous modifiez les ports, faites-les aussi correspondre à <code>WAZUH_MANAGER_PORT</code> et <code>WAZUH_MANAGER_ENROLLMENT_PORT</code> dans <code>.env</code>, puis recréez le conteneur Manager : cette page ne change pas le mappage des ports Docker. Vider une URL désactive son endpoint personnalisé ; « Restaurer » reprend les valeurs de `.env`.</p>
        <div className="form-actions pad-top">
          <button type="button" className="secondary" disabled={reset.isPending || save.isPending} onClick={() => reset.mutate()}>{reset.isPending ? 'Restauration…' : 'Restaurer .env'}</button>
          <button type="submit" className="primary" disabled={save.isPending || reset.isPending}>{save.isPending ? 'Enregistrement…' : 'Enregistrer la configuration'}</button>
        </div>
      </form>
    </section>
  )
}

function OpenScapProfilesEditor() {
  const client = useQueryClient()
  const { notify } = useNotifications()
  const catalog = useQuery({ queryKey: ['openscap-profile-catalog'], queryFn: api.openscapProfileCatalog })
  const [busyProfile, setBusyProfile] = useState<string | null>(null)

  const refresh = useMutation({
    mutationFn: (profiles: string[]) => api.refreshOpenSCAPProfiles(profiles),
    onMutate: (profiles) => setBusyProfile(profiles[0] ?? null),
    onSettled: () => setBusyProfile(null),
    onSuccess: (updated) => {
      client.setQueryData(['openscap-profile-catalog'], (current: unknown) =>
        (current as Array<{ name: string }> | undefined)?.map((item) =>
          updated.find((entry) => entry.name === item.name) ?? item,
        ) ?? updated,
      )
      void client.invalidateQueries({ queryKey: ['compliance-scans'] })
      notify({
        tone: 'success',
        title: 'Profils OpenSCAP actualisés',
        message: `${updated.length} data stream(s) téléchargé(s) et validé(s) depuis la distro.`,
      })
    },
    onError: (cause) => notify({
      tone: 'error',
      title: 'Téléchargement impossible',
      message: cause instanceof Error ? cause.message : 'Erreur inconnue',
    }),
  })

  if (catalog.isError) return <div className="alert error">Impossible de charger le catalogue des profils OpenSCAP.</div>
  if (catalog.isLoading || !catalog.data) return <Loading label="Chargement des profils OpenSCAP…" />

  return (
    <section className="panel form-panel">
      <div className="panel-heading">
        <div>
          <h3>Profils CIS OpenSCAP</h3>
          <p className="muted">Data streams officiels des dépôts Ubuntu et CentOS Stream, vérifiés par empreinte puis écrits dans le dossier des profils.</p>
        </div>
      </div>
      <div className="integration-grid">
        {catalog.data.map((profile) => (
          <article className="panel" key={profile.name}>
            <div className="panel-heading">
              <div className="cell-stack"><strong>{profile.name}</strong><small>{profile.archive.toUpperCase()} · {profile.profile_id}</small></div>
              <span className="badge success"><span className="dot" />{profile.updated_at ? 'Actualisé' : 'Empreinte figée'}</span>
            </div>
            <div className="panel-body">
              <div className="stat-lines">
                <div className="stat-line"><span>Archive source</span><strong className="hash-line">{profile.source_url.split('/').pop()}</strong></div>
                <div className="stat-line"><span>SHA256</span><strong className="hash-line">{profile.sha256.slice(0, 16)}…</strong></div>
                <div className="stat-line"><span>Taille</span><strong>{profile.size_bytes.toLocaleString('fr-FR')} octets</strong></div>
              </div>
              <div className="form-actions pad-top">
                <button
                  className="secondary"
                  disabled={refresh.isPending}
                  onClick={() => refresh.mutate([profile.name])}
                >
                  {busyProfile === profile.name ? 'Téléchargement…' : 'Télécharger depuis la distro'}
                </button>
              </div>
            </div>
          </article>
        ))}
      </div>
      {refresh.isError && <div className="alert error">{refresh.error instanceof Error ? refresh.error.message : 'Téléchargement impossible.'}</div>}
      <p className="integration-help">Les fichiers remplacent <code>config/openscap/profiles/cis_ubuntu.xml</code> et <code>cis_rhel.xml</code>. Le scan utilise directement le data stream ; les anciens fichiers de tailoring restent acceptés avec <code>openscap_is_tailoring=true</code>.</p>
    </section>
  )
}

const NATIVE_SECRET_LABELS: Record<NativeToolSecretKey, string> = {
  ubuntu_pro_token: 'Token Ubuntu Pro / Livepatch',
  canonical_livepatch_token: 'Token Canonical Livepatch',
}

function NativeToolSecretsEditor() {
  const client = useQueryClient()
  const { notify } = useNotifications()
  const state = useQuery({ queryKey: ['native-tool-secrets'], queryFn: api.nativeToolSecrets })
  const [values, setValues] = useState<Record<NativeToolSecretKey, string>>({
    ubuntu_pro_token: '',
    canonical_livepatch_token: '',
  })

  const save = useMutation({
    mutationFn: (secrets: Partial<Record<NativeToolSecretKey, string | null>>) =>
      api.updateNativeToolSecrets(secrets),
    onSuccess: (updated) => {
      client.setQueryData(['native-tool-secrets'], updated)
      setValues({ ubuntu_pro_token: '', canonical_livepatch_token: '' })
      notify({ tone: 'success', title: 'Clés enregistrées', message: 'Les valeurs sont chiffrées et ne sont plus affichées.' })
    },
    onError: (cause) => notify({
      tone: 'error',
      title: 'Enregistrement impossible',
      message: cause instanceof Error ? cause.message : 'Erreur inconnue',
    }),
  })

  if (state.isError) return <div className="alert error">Impossible de charger le statut des clés natives.</div>
  if (state.isLoading || !state.data) return <Loading label="Chargement des clés natives…" />

  return (
    <section className="panel form-panel">
      <div className="panel-heading">
        <div>
          <h3>Livepatch natif</h3>
          <p className="muted">Clés utilisées par <code>pro</code> et <code>canonical-livepatch</code>. Elles sont chiffrées au repos, jamais renvoyées par l’API ni écrites dans l’audit.</p>
        </div>
      </div>
      <div className="form-grid">
        {state.data.secrets.map((secret) => {
          const key = secret.key as NativeToolSecretKey
          return (
            <label key={secret.key}>
              {NATIVE_SECRET_LABELS[key] ?? secret.key}
              <div className="secret-field">
                <input
                  type="password"
                  autoComplete="off"
                  maxLength={256}
                  value={values[key] ?? ''}
                  placeholder={secret.configured ? 'Remplacer la valeur enregistrée' : 'Coller le token'}
                  onChange={(event) => setValues((current) => ({ ...current, [key]: event.target.value }))}
                />
                <span className={`badge ${secret.configured ? 'success' : 'muted'}`}><span className="dot" />{secret.configured ? 'Configuré' : 'Non configuré'}</span>
              </div>
            </label>
          )
        })}
      </div>
      {save.isError && <div className="alert error">{save.error instanceof Error ? save.error.message : 'Enregistrement impossible.'}</div>}
      <div className="form-actions pad-top">
        <button
          className="primary"
          disabled={save.isPending || !Object.values(values).some((value) => value.trim())}
          onClick={() => {
            const payload: Partial<Record<NativeToolSecretKey, string | null>> = {}
            for (const [key, value] of Object.entries(values) as Array<[NativeToolSecretKey, string]>) {
              if (value.trim()) payload[key] = value
            }
            save.mutate(payload)
          }}
        >
          {save.isPending ? 'Enregistrement…' : 'Enregistrer les clés'}
        </button>
        {state.data.secrets.filter((secret) => secret.configured).map((secret) => (
          <button
            key={secret.key}
            className="secondary"
            disabled={save.isPending}
            onClick={() => save.mutate({ [secret.key as NativeToolSecretKey]: null })}
          >
            Effacer {NATIVE_SECRET_LABELS[secret.key as NativeToolSecretKey] ?? secret.key}
          </button>
        ))}
      </div>
    </section>
  )
}

function Profile() {
  const { notify } = useNotifications()
  const me = useQuery({ queryKey: ['me'], queryFn: api.me, retry: false })
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [formError, setFormError] = useState('')
  const [changed, setChanged] = useState(false)
  const changePassword = useMutation({
    mutationFn: api.changePassword,
    onSuccess: () => {
      setCurrentPassword('')
      setNewPassword('')
      setConfirmation('')
      setFormError('')
      setChanged(true)
      notify({ tone: 'success', title: 'Mot de passe modifié', message: 'Les autres sessions ont été déconnectées.' })
    },
    onError: (cause) => notify({ tone: 'error', title: 'Modification impossible', message: cause instanceof Error ? cause.message : 'Erreur inconnue' }),
  })

  return (
    <div className="page">
      <PageHeader eyebrow="Compte" title="Mon profil" description="Informations du compte et sécurité de la session." />
      {me.isError ? <div className="alert error">Impossible de charger le profil.</div> : (
        <section className="panel form-panel">
          <div className="panel-heading">
            <div><h3>{me.data?.username ?? 'Compte'}</h3><p className="muted">Rôle : {me.data?.role ?? '—'}</p></div>
          </div>
          <form onSubmit={(event) => {
            event.preventDefault()
            setChanged(false)
            setFormError('')
            if (newPassword !== confirmation) {
              setFormError('La confirmation ne correspond pas au nouveau mot de passe.')
              return
            }
            changePassword.mutate({ current_password: currentPassword, new_password: newPassword })
          }}>
            <div className="form-grid three">
              <label>Mot de passe actuel
                <input type="password" autoComplete="current-password" minLength={1} maxLength={256} required value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} />
              </label>
              <label>Nouveau mot de passe
                <input type="password" autoComplete="new-password" minLength={12} maxLength={256} required value={newPassword} onChange={(event) => setNewPassword(event.target.value)} />
              </label>
              <label>Confirmer le nouveau mot de passe
                <input type="password" autoComplete="new-password" minLength={12} maxLength={256} required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} />
              </label>
            </div>
            {formError && <div className="alert error">{formError}</div>}
            {changePassword.isError && <div className="alert error">{changePassword.error instanceof Error ? changePassword.error.message : 'Échec du changement de mot de passe.'}</div>}
            {changed && <div className="alert success">Mot de passe modifié. Les autres sessions ont été déconnectées.</div>}
            <p className="integration-help">Le nouveau mot de passe doit comporter au moins 12 caractères. Votre session actuelle reste active ; les autres sessions sont révoquées.</p>
            <div className="form-actions pad-top">
              <button type="submit" className="primary" disabled={changePassword.isPending}>{changePassword.isPending ? 'Modification…' : 'Changer le mot de passe'}</button>
            </div>
          </form>
        </section>
      )}
    </div>
  )
}

function Settings() {
  const currentUser = useQuery({ queryKey: ['me'], queryFn: api.me })
  const integrationsQuery = useQuery({
    queryKey: ['integrations'],
    queryFn: api.integrations,
    refetchInterval: 60_000,
    refetchOnWindowFocus: true,
  })
  const { data, isLoading, isError } = integrationsQuery
  const [tested, setTested] = useState<Partial<Record<'wazuh' | 'ansible', IntegrationState>>>({})
  const sshKey = useQuery({ queryKey: ['ansible-public-key'], queryFn: api.ansiblePublicKey, retry: false })
  const recordTest = (key: 'wazuh' | 'ansible') => (state: IntegrationState) => {
    setTested((current) => ({ ...current, [key]: state }))
  }
  const testWazuh = useIntegrationTest('wazuh', recordTest('wazuh'))
  const testAnsible = useIntegrationTest('ansible', recordTest('ansible'))
  const { mutate: runWazuhTest } = testWazuh
  const { mutate: runAnsibleTest } = testAnsible
  const refresh = async () => {
    setTested({})
    await integrationsQuery.refetch()
    await Promise.allSettled([
      testWazuh.mutateAsync(),
      testAnsible.mutateAsync(),
    ])
  }
  const autoTestsStarted = useRef(false)
  useEffect(() => {
    if (!data || autoTestsStarted.current) return
    autoTestsStarted.current = true
    runWazuhTest()
    runAnsibleTest()
  }, [data, runWazuhTest, runAnsibleTest])
  if (isLoading) return <Loading label="Chargement des intégrations…" />
  if (isError || !data) return <div className="alert error">Impossible de charger les paramètres.</div>
  const integrations = [
    { name: 'Wazuh', key: 'wazuh' as const, label: 'Détection & SIEM', icon: Radar, state: tested.wazuh ?? data.wazuh, mutation: testWazuh },
    { name: 'Ansible', key: 'ansible' as const, label: 'Orchestration', icon: Cpu, state: tested.ansible ?? data.ansible, mutation: testAnsible },
  ]
  const statusText = (value: boolean | null) => value === null ? 'Non testé' : value ? 'Oui' : 'Non'
  return (
    <div className="page">
      <PageHeader
        eyebrow="Configuration"
        title="Paramètres"
        description="Récapitulatif de la pile, adresses détectées et tests de connectivité."
        actions={<button className="secondary" onClick={() => void refresh()}><RefreshCw /> Actualiser</button>}
      />
      <h2 className="section-title">Récapitulatif de la stack</h2>
      <div className="integration-grid stack-summary">
        {[
          {
            key: 'web',
            name: 'Interface Web',
            configured: true,
            reachable: true,
            endpoint: window.location.origin,
            addresses: window.location.hostname ? [window.location.hostname] : [],
            detail: 'Adresse de l’interface actuellement ouverte.',
          },
          {
            key: 'api',
            name: 'API LinSec360',
            configured: true,
            reachable: true,
            endpoint: `${window.location.origin}/api/v1`,
            addresses: window.location.hostname ? [window.location.hostname] : [],
            detail: 'API utilisée par cette interface.',
          },
          ...data.stack,
        ].map((component) => {
          const testedState = component.key === 'wazuh-api'
            ? tested.wazuh ?? data.wazuh
            : component.key === 'ansible'
              ? tested.ansible ?? data.ansible
              : undefined
          const reachable = testedState?.reachable ?? component.reachable
          const status = !component.configured
            ? 'À configurer'
            : reachable === null
              ? 'Configuré'
              : reachable
                ? 'Disponible'
                : 'Indisponible'
          return (
            <article className="panel" key={component.key}>
              <div className="panel-heading">
                <div className="cell-title"><span className="metric-icon tone-cyan"><Server /></span><div className="cell-stack"><strong>{component.name}</strong><small>{component.endpoint ?? 'Adresse non définie'}</small></div></div>
                <span className={`badge ${!component.configured || reachable === false ? 'danger' : reachable === true ? 'success' : 'muted'}`}><span className="dot" />{status}</span>
              </div>
              <div className="panel-body">
                <div className="stat-lines">
                  <div className="stat-line"><span>Adresse(s) résolue(s)</span><strong>{component.addresses.length ? component.addresses.join(', ') : 'Aucune'}</strong></div>
                </div>
                {component.detail && <p className="integrations-detail">{component.detail}</p>}
              </div>
            </article>
          )
        })}
      </div>
      <p className="integration-help">Les IP sont résolues depuis le conteneur API. Une adresse Docker interne n’est pas nécessairement joignable depuis les serveurs gérés ; pour les agents Wazuh, vérifiez l’adresse visible sur la ligne « Wazuh Manager (agents) ».</p>
      {currentUser.data?.role === 'admin' && <StackConfigurationEditor onSaved={refresh} />}
      <h2 className="section-title">Conformité & livepatch</h2>
      {currentUser.data?.role === 'admin' && (
        <>
          <OpenScapProfilesEditor />
          <NativeToolSecretsEditor />
        </>
      )}
      <h2 className="section-title">Tests de connexion</h2>
      <div className="integration-grid">
        {integrations.map(({ name, label, icon: Icon, key, state, mutation }) => (
          <article className="panel" key={key}>
            <div className="panel-heading">
              <div className="cell-title"><span className="metric-icon tone-cyan"><Icon /></span><div className="cell-stack"><strong>{name}</strong><small>{label}</small></div></div>
              <span className={`badge ${state.configured ? (state.reachable === false ? 'danger' : 'success') : 'muted'}`}>
                <span className="dot" />{state.configured ? statusText(state.reachable) : 'Non configuré'}
              </span>
            </div>
            <div className="panel-body">
              <div className="stat-lines">
                <div className="stat-line"><span>Configuré</span><strong>{statusText(state.configured)}</strong></div>
                {key === 'ansible' && <div className="stat-line"><span>Disponible localement</span><strong>{statusText(state.available)}</strong></div>}
                <div className="stat-line"><span>Joignable</span><strong>{mutation.isPending ? 'Test en cours…' : state.reachable === null ? (state.configured ? 'À tester' : 'Non configuré') : statusText(state.reachable)}</strong></div>
              </div>
              {state.detail && <p className="integrations-detail">{state.detail}</p>}
              {mutation.isError && <div className="alert error" style={{ marginTop: 12 }}>{mutation.error instanceof Error ? mutation.error.message : 'Test impossible.'}</div>}
              <button className="secondary btn sm" style={{ marginTop: 16 }} disabled={mutation.isPending || (key !== 'ansible' && !state.configured)} onClick={() => mutation.mutate()}>
                {mutation.isPending ? 'Test…' : key === 'ansible' ? 'Vérifier Ansible' : 'Tester l’API Wazuh'}
              </button>
            </div>
          </article>
        ))}
        <article className="panel">
          <div className="panel-heading">
            <div className="cell-title"><span className="metric-icon tone-cyan"><Server /></span><div className="cell-stack"><strong>Clé SSH Ansible</strong><small>Clé privée montée depuis l’hôte</small></div></div>
            <span className={`badge ${sshKey.isLoading ? 'muted' : sshKey.isError ? 'danger' : 'success'}`}>
              <span className="dot" />{sshKey.isLoading ? 'Vérification…' : sshKey.isError ? 'Indisponible' : 'Disponible'}
            </span>
          </div>
          <div className="panel-body">
            {sshKey.isError ? (
              <div className="alert error">{sshKey.error instanceof Error ? sshKey.error.message : 'Clé SSH indisponible.'}</div>
            ) : sshKey.data ? (
              <>
                <div className="stat-lines"><div className="stat-line"><span>Chemin privé dans les conteneurs</span><code className="mono">{sshKey.data.private_key_path}</code></div></div>
                <p className="integration-help">La clé privée reste sur l’hôte et est montée en lecture seule. Pour utiliser votre clé, placez-la dans le dossier configuré par <code>LINSEC_SSH_KEY_DIR</code>, puis définissez <code>LINSEC_ANSIBLE_SSH_PRIVATE_KEY_PATH</code> dans <code>.env</code>. Le fichier doit être lisible par l’API/worker et avoir des permissions 600 ou plus strictes ; les clés chiffrées ne sont pas prises en charge.</p>
                <div className="integrations-detail mono">{sshKey.data.public_key}</div>
              </>
            ) : null}
          </div>
        </article>
      </div>
      <p className="integration-help">Ansible est vérifié localement dans l’environnement de l’API (version uniquement, aucun playbook n’est exécuté). Wazuh est testé via son API configurée. Aucune valeur synthétique n’est affichée : une source absente reste explicitement inconnue.</p>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Shell & routing                                                     */
/* ------------------------------------------------------------------ */

function currentNavLabel(pathname: string): string {
  for (const group of navGroups) {
    for (const item of group.items) {
      if (item.to === '/' ? pathname === '/' : pathname.startsWith(item.to)) return item.label
    }
  }
  return 'Vue d’ensemble'
}

function Shell({ onLogout }: { onLogout: () => void }) {
  const me = useQuery({ queryKey: ['me'], queryFn: api.me, retry: false })
  const location = useLocation()
  const label = currentNavLabel(location.pathname)
  const [searchOpen, setSearchOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return window.localStorage.getItem(SIDEBAR_STORAGE_KEY) === 'true'
    } catch {
      return false
    }
  })
  useEffect(() => { window.scrollTo(0, 0) }, [location.pathname])
  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setSearchOpen(true)
      }
    }
    window.addEventListener('keydown', handleShortcut)
    return () => window.removeEventListener('keydown', handleShortcut)
  }, [])
  useEffect(() => {
    try {
      window.localStorage.setItem(SIDEBAR_STORAGE_KEY, String(sidebarCollapsed))
    } catch {
      // Navigation state is cosmetic; a locked-down browser can still use it.
    }
  }, [sidebarCollapsed])
  const role = me.data?.role ? me.data.role.charAt(0).toUpperCase() + me.data.role.slice(1) : 'Session'
  const toggleLabel = sidebarCollapsed ? 'Déplier la navigation' : 'Replier la navigation'
  return (
    <div className="app" data-sidebar={sidebarCollapsed ? 'collapsed' : 'expanded'}>
      <aside className="sidebar">
        <div className="sidebar-top">
          <NavLink to="/" className="brand" title={sidebarCollapsed ? 'Vue d’ensemble' : undefined}>
            <span className="brand-mark"><ShieldCheck /></span>
            <span className="brand-text"><strong>LinSec<em>360</em></strong><span>Security operations</span></span>
          </NavLink>
          <button
            className="sidebar-collapse"
            type="button"
            aria-expanded={!sidebarCollapsed}
            aria-controls="main-nav"
            aria-label={toggleLabel}
            title={toggleLabel}
            onClick={() => setSidebarCollapsed((collapsed) => !collapsed)}
          >
            {sidebarCollapsed ? <ChevronRight /> : <ChevronLeft />}
          </button>
        </div>
        <nav id="main-nav">
          {navGroups.map((group) => (
            <div className="nav-group" key={group.label}>
              <div className="nav-label">{group.label}</div>
              {group.items.map(({ to, label: itemLabel, icon: Icon }) => (
                <NavLink key={to} to={to} end={to === '/'} title={sidebarCollapsed ? itemLabel : undefined}>
                  <Icon /><span>{itemLabel}</span><ChevronRight className="chevron" />
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-status"><span className="live-dot success" /><span>Console SOC <strong>active</strong></span></div>
          <button className="logout" title={sidebarCollapsed ? 'Déconnexion' : undefined} onClick={onLogout}><LogOut /><span>Déconnexion</span></button>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="topbar-left">
            <div className="breadcrumb"><span className="crumb-root">LinSec360</span><ChevronRight /><strong>{label}</strong></div>
          </div>
          <div className="topbar-right">
            <button className="search-trigger" aria-label="Ouvrir la recherche globale" onClick={() => setSearchOpen(true)}>
              <Search />
              <span>Rechercher un hôte, un playbook…</span>
              <kbd>⌘K</kbd>
            </button>
            <NotificationMenu />
            <div className="user-chip">
              <span className="avatar">{initials(me.data?.username ?? 'Session')}</span>
              <div className="user-meta"><strong>{me.data?.username ?? 'Session'}</strong><span>{role}</span></div>
            </div>
          </div>
        </header>
        <div className="content">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/hosts" element={<Hosts />} />
            <Route path="/deployments" element={<Deployments />} />
            <Route path="/hosts/:hostId" element={<HostDetail />} />
            <Route path="/deployments/:deploymentId" element={<DeploymentDetail />} />
            <Route path="/playbooks" element={<Playbooks />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/patching" element={<Patching />} />
            <Route path="/detection" element={<Detection />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </main>
      <CommandPalette key={searchOpen ? 'search-open' : 'search-closed'} open={searchOpen} onClose={() => setSearchOpen(false)} />
    </div>
  )
}

function App() {
  const [authenticated, setAuthenticated] = useState(false)
  const me = useQuery({ queryKey: ['me'], queryFn: api.me, retry: false, enabled: !authenticated })
  const client = useQueryClient()
  const { notify } = useNotifications()
  useEffect(() => {
    const handleUnauthorized = () => {
      client.clear()
      setAuthenticated(false)
      notify({ tone: 'warning', title: 'Session expirée', message: 'Reconnectez-vous pour continuer.' })
    }
    window.addEventListener('linsec:unauthorized', handleUnauthorized)
    return () => window.removeEventListener('linsec:unauthorized', handleUnauthorized)
  }, [client, notify])
  if (!authenticated && me.isLoading) return <div className="login-page"><div className="loading"><span className="spinner" />Vérification de la session…</div></div>
  if (!authenticated && me.isError) return <Login onLogin={() => { setAuthenticated(true); void client.invalidateQueries() }} />
  const logout = async () => {
    try {
      await api.logout()
    } catch {
      // A stale or already-expired browser session must still be removed locally.
    } finally {
      client.clear()
      setAuthenticated(false)
    }
  }
  return <Shell onLogout={() => void logout()} />
}

export default App
