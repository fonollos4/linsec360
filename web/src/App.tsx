import { useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  ArrowUpRight,
  Bell,
  Boxes,
  ChevronRight,
  Cpu,
  Database,
  FileCode2,
  Gauge,
  HardDrive,
  LayoutDashboard,
  LogOut,
  Play,
  Plus,
  Radar,
  RefreshCw,
  ScanLine,
  Search,
  Server,
  Settings as SettingsIcon,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Navigate, NavLink, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  api,
  type Alert,
  type Deployment,
  type Host,
  type HostEnrollmentInput,
  type PatchFinding,
  type Playbook,
  type PlaybookDetail,
} from './api'

type NavItem = { to: string; label: string; icon: LucideIcon }

const navGroups: Array<{ label: string; items: NavItem[] }> = [
  {
    label: 'Pilotage',
    items: [
      { to: '/', label: 'Vue d’ensemble', icon: LayoutDashboard },
      { to: '/hosts', label: 'Hôtes', icon: HardDrive },
    ],
  },
  {
    label: 'Automatisation',
    items: [
      { to: '/deployments', label: 'Déploiements', icon: Play },
      { to: '/playbooks', label: 'Playbooks', icon: FileCode2 },
    ],
  },
  {
    label: 'Sécurité',
    items: [
      { to: '/compliance', label: 'Conformité', icon: ShieldCheck },
      { to: '/patching', label: 'Correctifs', icon: Boxes },
      { to: '/detection', label: 'Détection', icon: Radar },
    ],
  },
  {
    label: 'Système',
    items: [
      { to: '/audit', label: 'Audit', icon: Activity },
      { to: '/settings', label: 'Paramètres', icon: SettingsIcon },
    ],
  },
]

const hostIdentifier = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/
const sshFingerprint = /^SHA256:[A-Za-z0-9+/]{43}$/
const hostCsvColumns = ['name', 'ip', 'environment', 'security_level', 'groups', 'ansible_user', 'ansible_port', 'password']

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
  fingerprint_pending: 'Empreinte à valider',
  fingerprint_changed: 'Empreinte modifiée',
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
  if (['failed', 'cancelled', 'canceled', 'error', 'critical', 'fail', 'unreachable', 'fingerprint_changed', 'open'].includes(key)) return 'danger'
  if (['running', 'queued', 'deploying', 'enrolling', 'pending', 'info', 'medium'].includes(key)) return 'info'
  if (['warning', 'warn', 'stale', 'high', 'fingerprint_pending'].includes(key)) return 'warning'
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

function parseHostCsv(text: string): HostEnrollmentInput[] {
  const rows = parseCsv(text)
  if (!rows.length) throw new Error('Le fichier CSV est vide.')
  if (rows.length > 26) throw new Error('Maximum 25 hôtes par import sécurisé.')
  const headers = rows[0].map((value, index) =>
    (index === 0 ? value.replace(/^\uFEFF/, '') : value).trim().toLowerCase(),
  )
  if (new Set(headers).size !== headers.length) throw new Error('En-têtes CSV dupliqués.')
  const unsupported = headers.filter((header) => !hostCsvColumns.includes(header))
  if (unsupported.length) throw new Error(`Colonnes non acceptées : ${unsupported.join(', ')}.`)
  const required = ['name', 'ip', 'environment', 'password']
  const missing = required.filter((header) => !headers.includes(header))
  if (missing.length) throw new Error(`Colonnes obligatoires manquantes : ${missing.join(', ')}.`)

  const importedKeys = new Set<string>()
  return rows.slice(1).map((cells, rowIndex) => {
    const rowNumber = rowIndex + 2
    if (cells.length !== headers.length) throw new Error(`Ligne ${rowNumber} : nombre de colonnes invalide.`)
    const values = Object.fromEntries(headers.map((header, index) => [header, cells[index].trim()]))
    const name = values.name ?? ''
    const ip = values.ip ?? ''
    const environment = values.environment ?? ''
    const ansibleUser = values.ansible_user || 'linsec-ansible'
    const securityLevel = values.security_level || 'high'
    const password = values.password ?? ''
    const portText = values.ansible_port || '22'
    const port = Number(portText)
    const groups = (values.groups ?? '').split(';').map((group) => group.trim()).filter(Boolean)

    if (!hostIdentifier.test(name) || !hostIdentifier.test(environment) || !hostIdentifier.test(ansibleUser)) {
      throw new Error(`Ligne ${rowNumber} : nom, environnement ou utilisateur SSH invalide.`)
    }
    const octets = ip.split('.')
    if (octets.length !== 4 || octets.some((octet) => !/^(0|[1-9]\d{0,2})$/.test(octet) || Number(octet) > 255)) {
      throw new Error(`Ligne ${rowNumber} : adresse IPv4 invalide.`)
    }
    if (!['low', 'medium', 'high', 'critical'].includes(securityLevel)) {
      throw new Error(`Ligne ${rowNumber} : niveau de sécurité invalide.`)
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Ligne ${rowNumber} : port SSH invalide.`)
    }
    if (!password || password.length > 256 || password.includes('\0') || password.includes('\r') || password.includes('\n')) {
      throw new Error(`Ligne ${rowNumber} : mot de passe vide, trop long ou invalide.`)
    }
    if (groups.some((group) => !hostIdentifier.test(group))) {
      throw new Error(`Ligne ${rowNumber} : groupe invalide.`)
    }
    const uniqueKey = `${environment}\0${name}`
    if (importedKeys.has(uniqueKey)) throw new Error(`Ligne ${rowNumber} : hôte dupliqué dans le CSV.`)
    importedKeys.add(uniqueKey)

    return {
      name,
      ip,
      environment,
      security_level: securityLevel,
      groups,
      ansible_user: ansibleUser,
      ansible_port: port,
      password,
    }
  })
}

type HostEnrollmentRow = HostEnrollmentInput & {
  key: string
  fingerprint: string | null
  verifiedFingerprint: string
  scanError: string
  status: string
  message: string
}

type EnrollmentBatchSummary = {
  hosts: Array<{ name: string; environment: string; status: string; message: string }>
  deployments: Array<{ environment: string; id?: string; error?: string }>
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

function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const login = useMutation({
    mutationFn: () => api.login(username, password),
    onSuccess: onLogin,
    onError: (cause) => setError(cause instanceof Error ? cause.message : 'Connexion impossible'),
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
              <li><Boxes /> Correctifs Uyuni et live patching</li>
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
  const hosts = useQuery({ queryKey: ['hosts'], queryFn: api.hosts })
  const deployments = useQuery({ queryKey: ['deployments'], queryFn: api.deployments })
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
  const recentDeployments = (deployments.data ?? []).slice(0, 6)

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

function Hosts() {
  const client = useQueryClient()
  const navigate = useNavigate()
  const currentUser = useQuery({ queryKey: ['me'], queryFn: api.me })
  const canManageHosts = currentUser.data?.role === 'admin' || currentUser.data?.role === 'operator'
  const [showForm, setShowForm] = useState(false)
  const [showImport, setShowImport] = useState(false)
  const [editingHost, setEditingHost] = useState<Host | null>(null)
  const [editForm, setEditForm] = useState({ ip: '', security_level: 'high', groups: '', ansible_user: 'linsec-ansible', ansible_port: 22 })
  const [importRows, setImportRows] = useState<HostEnrollmentRow[]>([])
  const [importError, setImportError] = useState('')
  const [batchSummary, setBatchSummary] = useState<EnrollmentBatchSummary | null>(null)
  const [selectedPlaybook, setSelectedPlaybook] = useState('')
  const [form, setForm] = useState({ name: '', ip: '', environment: 'production', security_level: 'high', groups: '', ansible_user: 'linsec-ansible', ansible_port: 22 })
  const [sshPassword, setSshPassword] = useState('')
  const [scannedFingerprint, setScannedFingerprint] = useState('')
  const [scannedTarget, setScannedTarget] = useState('')
  const [verifiedFingerprint, setVerifiedFingerprint] = useState('')
  const [enrollmentNotice, setEnrollmentNotice] = useState('')
  const { data = [], isLoading, error } = useQuery({
    queryKey: ['hosts'],
    queryFn: api.hosts,
    refetchInterval: (query) => query.state.data?.some((host) => host.ssh_status === 'enrolling') ? 2000 : false,
  })
  const playbooks = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks })
  const authorizedPlaybooks = (playbooks.data ?? []).filter((item) => item.is_allowlisted)
  const activePlaybook = selectedPlaybook || authorizedPlaybooks[0]?.filename || ''
  const fingerprintScan = useMutation({
    mutationFn: (target: { ip: string; ansible_port: number }) => api.scanHostFingerprint(target),
    onSuccess: (result, target) => {
      setScannedFingerprint(result.fingerprint)
      setScannedTarget(`${target.ip}:${target.ansible_port}`)
      setVerifiedFingerprint('')
    },
  })
  const enroll = useMutation({
    mutationFn: () => api.enrollHost({
      name: form.name,
      ip: form.ip,
      environment: form.environment,
      security_level: form.security_level,
      groups: form.groups.split(',').map((value) => value.trim()).filter(Boolean),
      ansible_user: form.ansible_user,
      ansible_port: form.ansible_port,
      password: sshPassword,
      verified_fingerprint: verifiedFingerprint.trim(),
    }),
    onSuccess: (host) => {
      setShowForm(false)
      setForm({ name: '', ip: '', environment: 'production', security_level: 'high', groups: '', ansible_user: 'linsec-ansible', ansible_port: 22 })
      setScannedFingerprint('')
      setScannedTarget('')
      setVerifiedFingerprint('')
      setEnrollmentNotice(`${host.name} : connexion vérifiée, installation de la clé Ansible en arrière-plan.`)
      void client.invalidateQueries({ queryKey: ['hosts'] })
    },
    onSettled: () => setSshPassword(''),
  })
  const updateHost = useMutation({
    mutationFn: (change: { id: number; body: { ip: string; security_level: string; groups: string[]; ansible_user: string; ansible_port: number } }) =>
      api.updateHost(change.id, change.body),
    onSuccess: (updated) => {
      setEditingHost(null)
      void client.invalidateQueries({ queryKey: ['hosts'] })
      void client.invalidateQueries({ queryKey: ['host', updated.id] })
    },
  })
  const deleteHost = useMutation({
    mutationFn: api.deleteHost,
    onSuccess: () => void client.invalidateQueries({ queryKey: ['hosts'] }),
  })
  const importHosts = useMutation({
    mutationFn: async (): Promise<EnrollmentBatchSummary> => {
      const outcomes: EnrollmentBatchSummary['hosts'] = []
      const deployments: EnrollmentBatchSummary['deployments'] = []
      const enrolledHosts: Array<{ id: number; name: string; environment: string }> = []

      for (const [index, row] of importRows.entries()) {
        if (!row.fingerprint || row.verifiedFingerprint.trim() !== row.fingerprint) {
          outcomes.push({
            name: row.name,
            environment: row.environment,
            status: 'failed',
            message: row.scanError || 'Empreinte non vérifiée hors bande.',
          })
          continue
        }
        setImportRows((current) => current.map((item, itemIndex) =>
          itemIndex === index ? { ...item, status: 'authenticating', message: '' } : item,
        ))
        try {
          const host = await api.enrollHost({
            name: row.name,
            ip: row.ip,
            environment: row.environment,
            security_level: row.security_level,
            groups: row.groups,
            ansible_user: row.ansible_user,
            ansible_port: row.ansible_port,
            password: row.password,
            verified_fingerprint: row.fingerprint,
          })
          enrolledHosts.push({ id: host.id, name: host.name, environment: host.environment })
          outcomes.push({
            name: row.name,
            environment: row.environment,
            status: 'enrolling',
            message: 'Mot de passe accepté; installation de la clé en cours.',
          })
          setImportRows((current) => current.map((item, itemIndex) =>
            itemIndex === index ? { ...item, password: '', status: 'enrolling', message: 'Installation de la clé…' } : item,
          ))
        } catch (cause) {
          outcomes.push({
            name: row.name,
            environment: row.environment,
            status: 'failed',
            message: cause instanceof Error ? cause.message : 'Échec de connexion SSH.',
          })
          setImportRows((current) => current.map((item, itemIndex) =>
            itemIndex === index ? { ...item, password: '', status: 'failed', message: cause instanceof Error ? cause.message : 'Échec de connexion SSH.' } : item,
          ))
        }
      }

      if (enrolledHosts.length) {
        const pending = new Set(enrolledHosts.map((host) => host.id))
        let currentHosts: Host[] = []
        for (let attempt = 0; attempt < 60 && pending.size; attempt += 1) {
          currentHosts = await Promise.all(enrolledHosts.map((host) => api.host(host.id)))
          for (const host of currentHosts) {
            if (host.ssh_status !== 'enrolling') pending.delete(host.id)
          }
          if (pending.size) await new Promise((resolve) => window.setTimeout(resolve, 2000))
        }

        const reachable = currentHosts.filter((host) => host.ssh_status === 'reachable')
        for (const host of currentHosts) {
          const index = importRows.findIndex((row) => row.name === host.name && row.environment === host.environment)
          const status = host.ssh_status === 'reachable'
            ? 'ready'
            : host.ssh_status === 'enrolling' ? 'enrolling' : 'failed'
          const message = host.ssh_status === 'reachable'
            ? 'Clé Ansible installée et testée.'
            : host.ssh_error || (host.ssh_status === 'enrolling' ? 'Installation en cours; relancez le playbook après vérification.' : 'Installation de la clé ou test Ansible échoué.')
          const outcome = outcomes.find((item) => item.name === host.name && item.environment === host.environment)
          if (outcome) {
            outcome.status = status
            outcome.message = message
          }
          if (index >= 0) setImportRows((current) => current.map((item, itemIndex) =>
            itemIndex === index ? { ...item, status, message } : item,
          ))
        }

        const byEnvironment = new Map<string, Host[]>()
        for (const host of reachable) {
          const hosts = byEnvironment.get(host.environment) ?? []
          hosts.push(host)
          byEnvironment.set(host.environment, hosts)
        }
        for (const [environment, hosts] of byEnvironment) {
          try {
            const deployment = await api.createDeployment({
              environment,
              playbook: activePlaybook,
              hosts: hosts.map((host) => host.name),
            })
            deployments.push({ environment, id: deployment.id })
          } catch (cause) {
            deployments.push({
              environment,
              error: cause instanceof Error ? cause.message : 'Échec de création du déploiement.',
            })
          }
        }
      }
      return { hosts: outcomes, deployments }
    },
    onSuccess: (summary) => {
      setBatchSummary(summary)
      void client.invalidateQueries({ queryKey: ['hosts'] })
      void client.invalidateQueries({ queryKey: ['deployments'] })
    },
    onSettled: () => setImportRows((current) => current.map((row) => ({ ...row, password: '' }))),
  })
  const scanImportRows = useMutation({
    mutationFn: async (targets: Array<{ key: string; ip: string; ansible_port: number }>) => {
      const results: Array<{ key: string; fingerprint: string | null; error: string }> = []
      for (const target of targets) {
        try {
          const result = await api.scanHostFingerprint({ ip: target.ip, ansible_port: target.ansible_port })
          results.push({ key: target.key, fingerprint: result.fingerprint, error: '' })
        } catch (cause) {
          results.push({ key: target.key, fingerprint: null, error: cause instanceof Error ? cause.message : 'Scan SSH impossible.' })
        }
      }
      return results
    },
    onSuccess: (results) => setImportRows((current) => current.map((row) => {
      const result = results.find((item) => item.key === row.key)
      return result ? { ...row, fingerprint: result.fingerprint, scanError: result.error } : row
    })),
  })
  const readImportFile = (file?: File) => {
    importHosts.reset()
    scanImportRows.reset()
    setBatchSummary(null)
    setImportRows([])
    setImportError('')
    if (!file) return
    if (file.size > 1_000_000) {
      setImportError('Le fichier dépasse la limite de 1 Mo.')
      return
    }
    void file.text().then((text) => {
      const parsed = parseHostCsv(text)
      if (!parsed.length) throw new Error('Le CSV ne contient aucune ligne de données.')
      const rows = parsed.map((row, index) => ({
        ...row,
        key: `${row.environment}-${row.name}-${index}`,
        fingerprint: null,
        verifiedFingerprint: '',
        scanError: '',
        status: 'pending',
        message: '',
      }))
      setImportRows(rows)
      scanImportRows.mutate(rows.map(({ key, ip, ansible_port }) => ({ key, ip, ansible_port })))
    }).catch((cause: unknown) => {
      setImportError(cause instanceof Error ? cause.message : 'Lecture du CSV impossible.')
    })
  }
  if (isLoading) return <Loading label="Chargement de l’inventaire…" />
  if (error) return <div className="alert error">Impossible de charger les hôtes.</div>

  const reachableCount = data.filter((host) => host.ssh_status === 'reachable').length
  const securedCount = data.filter((host) => host.status === 'secured').length
  const enrollingCount = data.filter((host) => host.ssh_status === 'enrolling' || host.status === 'deploying').length

  return (
    <div className="page">
      <PageHeader
        eyebrow="Inventaire"
        title="Hôtes"
        description={`${formatNumber(data.length)} serveur(s) · ${formatNumber(reachableCount)} joignable(s) · ${formatNumber(securedCount)} sécurisé(s)${enrollingCount ? ` · ${formatNumber(enrollingCount)} en cours` : ''}`}
        actions={canManageHosts && (
          <>
            <button className="secondary" onClick={() => { setShowImport((visible) => !visible); setBatchSummary(null) }}><ScanLine /> Enrôlement CSV</button>
            <button className="primary" onClick={() => { setEnrollmentNotice(''); setEditingHost(null); setShowForm(true) }}><Plus /> Ajouter un hôte</button>
          </>
        )}
      />
      {enrollmentNotice && <div className="alert success">{enrollmentNotice}</div>}

      {showImport && (
        <article className="panel form-panel host-import">
          <div className="panel-heading"><div><p className="eyebrow">Enrôlement SSH</p><h2>Importer et préparer plusieurs hôtes</h2></div><StatusBadge value="pending" label="Vérification hors bande" /></div>
          <p className="host-import-note">CSV limité à 25 hôtes avec la colonne <code>password</code>. Le scan des empreintes ne transmet pas les mots de passe. Pour chaque serveur, comparez le fingerprint à une source de confiance et saisissez-le dans le tableau. Après validation, le mot de passe sert uniquement au test SSH et à l’installation de la clé Ansible; il est ensuite effacé. Choisissez un playbook autorisé à lancer sur les hôtes dont la clé a été testée. Utilisez HTTPS (HTTP est permis uniquement sur localhost).</p>
          <label className="host-csv-file">Fichier CSV<input type="file" accept=".csv,text/csv" disabled={importHosts.isPending} onChange={(event) => { readImportFile(event.target.files?.[0]); event.target.value = '' }} /></label>
          {importError && <div className="alert error">{importError}</div>}
          {importRows.length > 0 && (
            <>
              <p className="host-import-note">Colonnes requises : <code>name,ip,environment,password</code>. Facultatives : <code>security_level</code>, <code>groups</code> séparés par <code>;</code>, <code>ansible_user</code>, <code>ansible_port</code>. Empreintes scannées : {importRows.filter((row) => row.fingerprint).length}/{importRows.length}.</p>
              <div className="batch-playbook">
                <label>Playbook autorisé à lancer après enrôlement
                  <select value={activePlaybook} onChange={(event) => setSelectedPlaybook(event.target.value)} disabled={importHosts.isPending}>
                    {authorizedPlaybooks.map((item: Playbook) => <option key={item.filename} value={item.filename}>{item.filename}</option>)}
                  </select>
                </label>
                {playbooks.isError && <div className="alert error">Impossible de charger les playbooks autorisés.</div>}
                {!authorizedPlaybooks.length && <div className="alert error">Aucun playbook autorisé disponible.</div>}
              </div>
              {scanImportRows.isPending && <p className="host-import-note">Scan des empreintes sans utiliser les mots de passe…</p>}
              <div className="table-wrap"><table><thead><tr><th>Hôte / cible</th><th>Empreinte détectée</th><th>Vérification hors bande</th><th>Mot de passe temporaire</th><th>État</th></tr></thead><tbody>
                {importRows.map((host) => <tr key={host.key}>
                  <td><div className="cell-stack"><strong>{host.name}</strong><small className="host-row-target">{host.ip}:{host.ansible_port} · {host.environment}</small></div></td>
                  <td className="mono">{host.fingerprint ?? (host.scanError || 'Scan en attente…')}</td>
                  <td><input aria-label={`Empreinte vérifiée pour ${host.name}`} value={host.verifiedFingerprint} disabled={importHosts.isPending || !host.fingerprint} onChange={(event) => setImportRows((current) => current.map((item) => item.key === host.key ? { ...item, verifiedFingerprint: event.target.value.trim() } : item))} placeholder="Saisir le fingerprint vérifié" /></td>
                  <td><input aria-label={`Mot de passe temporaire pour ${host.name}`} type="password" autoComplete="new-password" value={host.password} disabled={importHosts.isPending} onChange={(event) => setImportRows((current) => current.map((item) => item.key === host.key ? { ...item, password: event.target.value } : item))} /></td>
                  <td><StatusBadge value={host.status} />{host.message && <small className="host-ssh-error">{host.message}</small>}</td>
                </tr>)}
              </tbody></table></div>
              {batchSummary && (
                <div className={batchSummary.hosts.some((host) => host.status === 'failed') || batchSummary.deployments.some((deployment) => deployment.error) ? 'alert error batch-summary' : 'alert success batch-summary'}>
                  <strong>Résultat d’enrôlement</strong>
                  {batchSummary.hosts.map((host) => <div key={`${host.environment}-${host.name}`}>{host.name} ({host.environment}) — {host.status}: {host.message}</div>)}
                  {batchSummary.deployments.map((deployment) => <div key={deployment.environment}>{deployment.environment}: {deployment.id ? <>playbook mis en file <code>{deployment.id}</code></> : `playbook non lancé — ${deployment.error}`}</div>)}
                </div>
              )}
            </>
          )}
          {importHosts.isError && <div className="alert error">{importHosts.error instanceof Error ? importHosts.error.message : 'Import impossible.'}</div>}
          <div className="form-actions">
            <button className="secondary" disabled={importHosts.isPending || scanImportRows.isPending} onClick={() => { setImportRows([]); setImportError(''); setBatchSummary(null); importHosts.reset(); scanImportRows.reset() }}>Effacer les données et mots de passe</button>
            <button className="primary" disabled={!importRows.some((row) => row.fingerprint && row.verifiedFingerprint.trim() === row.fingerprint && row.password) || importHosts.isPending || scanImportRows.isPending || !activePlaybook} onClick={() => { setBatchSummary(null); importHosts.mutate() }}>{importHosts.isPending ? 'Connexion, enrôlement et préparation…' : 'Enrôler les hôtes vérifiés puis exécuter'}</button>
          </div>
        </article>
      )}

      {showForm && (
        <article className="panel form-panel">
          <div className="panel-heading"><div><p className="eyebrow">Nouvel hôte</p><h2>Enrôlement sécurisé</h2></div></div>
          <div className="form-grid">
            <label>Nom<input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></label>
            <label>Adresse IP<input value={form.ip} onChange={(event) => { setForm({ ...form, ip: event.target.value }); setScannedFingerprint(''); setScannedTarget(''); setVerifiedFingerprint(''); fingerprintScan.reset() }} /></label>
            <label>Environnement<select value={form.environment} onChange={(event) => setForm({ ...form, environment: event.target.value })}><option value="production">production</option><option value="staging">staging</option><option value="development">development</option></select></label>
            <label>Niveau<select value={form.security_level} onChange={(event) => setForm({ ...form, security_level: event.target.value })}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
            <label>Groupes<input value={form.groups} onChange={(event) => setForm({ ...form, groups: event.target.value })} placeholder="linux,servers" /></label>
            <label>Utilisateur SSH<input value={form.ansible_user} onChange={(event) => setForm({ ...form, ansible_user: event.target.value })} /></label>
            <label>Port SSH<input type="number" min="1" max="65535" value={form.ansible_port} onChange={(event) => { setForm({ ...form, ansible_port: Number(event.target.value) }); setScannedFingerprint(''); setScannedTarget(''); setVerifiedFingerprint(''); fingerprintScan.reset() }} /></label>
            <label>Mot de passe SSH (usage unique)<input type="password" autoComplete="new-password" value={sshPassword} onChange={(event) => setSshPassword(event.target.value)} /></label>
          </div>
          <div className="ssh-enrollment-approval">
            <p>Découvrez l’empreinte sans envoyer le mot de passe, puis comparez-la à une console ou à une source de confiance. Le mot de passe n’est envoyé qu’après confirmation, utilisé une seule fois et jamais enregistré. L’enrôlement exige HTTPS, sauf depuis localhost.</p>
            <button className="secondary" disabled={!form.ip || fingerprintScan.isPending} onClick={() => fingerprintScan.mutate({ ip: form.ip, ansible_port: form.ansible_port })}>{fingerprintScan.isPending ? 'Scan…' : 'Découvrir l’empreinte SSH'}</button>
            {fingerprintScan.isError && <div className="alert error">{fingerprintScan.error instanceof Error ? fingerprintScan.error.message : 'Scan SSH impossible.'}</div>}
            {scannedFingerprint && <><p className="mono fingerprint-candidate">{scannedFingerprint}</p><label className="fingerprint-confirm">Empreinte comparée à une source de confiance<input value={verifiedFingerprint} onChange={(event) => setVerifiedFingerprint(event.target.value.trim())} placeholder="Saisir l’empreinte vérifiée" /></label></>}
          </div>
          {enroll.isError && <div className="alert error">{enroll.error instanceof Error ? enroll.error.message : 'Échec de l’enrôlement. Aucun hôte ajouté.'}</div>}
          <div className="form-actions"><button className="secondary" disabled={enroll.isPending} onClick={() => { setShowForm(false); setSshPassword('') }}>Annuler</button><button className="primary" disabled={enroll.isPending || !form.name || !form.ip || !sshPassword || scannedTarget !== `${form.ip}:${form.ansible_port}` || verifiedFingerprint.trim() !== scannedFingerprint || !sshFingerprint.test(verifiedFingerprint.trim())} onClick={() => enroll.mutate()}>{enroll.isPending ? 'Test de connexion…' : 'Tester et enrôler'}</button></div>
        </article>
      )}

      {editingHost && (
        <article className="panel form-panel">
          <div className="panel-heading"><div><p className="eyebrow">Édition</p><h2>Modifier {editingHost.name}</h2></div></div>
          <div className="form-grid">
            <label>Adresse IP<input value={editForm.ip} onChange={(event) => setEditForm({ ...editForm, ip: event.target.value })} /></label>
            <label>Niveau de sécurité<select value={editForm.security_level} onChange={(event) => setEditForm({ ...editForm, security_level: event.target.value })}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
            <label>Groupes<input value={editForm.groups} onChange={(event) => setEditForm({ ...editForm, groups: event.target.value })} placeholder="linux,servers" /></label>
            <label>Utilisateur SSH<input value={editForm.ansible_user} onChange={(event) => setEditForm({ ...editForm, ansible_user: event.target.value })} /></label>
            <label>Port SSH<input type="number" min="1" max="65535" value={editForm.ansible_port} onChange={(event) => setEditForm({ ...editForm, ansible_port: Number(event.target.value) })} /></label>
          </div>
          {editingHost.ip !== editForm.ip || editingHost.ansible_port !== editForm.ansible_port ? <p className="host-import-note">Modifier l’adresse ou le port effacera l’empreinte épinglée et exigera une nouvelle vérification SSH.</p> : null}
          {updateHost.isError && <div className="alert error">{updateHost.error instanceof Error ? updateHost.error.message : 'Modification impossible.'}</div>}
          <div className="form-actions"><button className="secondary" disabled={updateHost.isPending} onClick={() => setEditingHost(null)}>Annuler</button><button className="primary" disabled={updateHost.isPending || !editForm.ip || !editForm.ansible_user} onClick={() => updateHost.mutate({ id: editingHost.id, body: { ip: editForm.ip, security_level: editForm.security_level, groups: editForm.groups.split(',').map((group) => group.trim()).filter(Boolean), ansible_user: editForm.ansible_user, ansible_port: editForm.ansible_port } })}>{updateHost.isPending ? 'Enregistrement…' : 'Enregistrer'}</button></div>
        </article>
      )}

      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Parc</p><h2>Serveurs enregistrés</h2></div><span className="badge muted">{formatNumber(data.length)} hôte(s)</span></div>
        <DataTable
          headers={['Hôte', 'Adresse IP', 'Environnement', 'Sécurité', 'Statut', 'SSH', 'Actions']}
          empty="Aucun hôte enregistré"
          rows={data.map((host) => [
            <div className="cell-title" key={`name-${host.id}`}><span className="avatar-sm">{initials(host.name)}</span><div className="cell-stack"><strong>{host.name}</strong><small>{host.groups.join(', ') || 'sans groupe'}</small></div></div>,
            <span className="mono" key={`ip-${host.id}`}>{host.ip}</span>,
            <span className="badge muted" key={`env-${host.id}`}>{host.environment}</span>,
            <StatusBadge value={host.security_level} key={`level-${host.id}`} />,
            <StatusBadge value={host.status} key={`status-${host.id}`} />,
            <div className="cell-stack" key={`ssh-${host.id}`} title={host.ssh_error ?? ''}><StatusBadge value={host.ssh_status} />{host.ssh_error && <small className="host-ssh-error">{host.ssh_error}</small>}</div>,
            <div className="actions" key={`actions-${host.id}`}>
              {canManageHosts && <button className="link-button" onClick={() => { setShowForm(false); setEditingHost(host); setEditForm({ ip: host.ip, security_level: host.security_level, groups: host.groups.join(','), ansible_user: host.ansible_user, ansible_port: host.ansible_port }) }}>Modifier</button>}
              <button className="link-button" onClick={() => navigate(`/hosts/${host.id}`)}>Posture</button>
              {currentUser.data?.role === 'admin' && <button className="link-button danger-link" disabled={deleteHost.isPending} onClick={() => { if (window.confirm(`Supprimer ${host.name} ? Cette action est irréversible.`)) deleteHost.mutate(host.id) }}>Supprimer</button>}
            </div>,
          ])}
        />
        {deleteHost.isError && <div className="alert error">{deleteHost.error instanceof Error ? deleteHost.error.message : 'Suppression impossible.'}</div>}
      </article>
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
  const currentUser = useQuery({ queryKey: ['me'], queryFn: api.me })
  const host = useQuery({
    queryKey: ['host', id],
    queryFn: () => api.host(id),
    enabled: Number.isInteger(id),
    refetchInterval: (query) => query.state.data?.ssh_status === 'enrolling' ? 2000 : false,
  })
  const posture = useQuery({ queryKey: ['host-posture', id], queryFn: () => api.hostPosture(id), enabled: Number.isInteger(id) })
  const playbooks = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks })
  const publicKey = useQuery({ queryKey: ['ansible-public-key'], queryFn: api.ansiblePublicKey })
  const [playbook, setPlaybook] = useState('openscap-scan.yml')
  const [checkMode, setCheckMode] = useState(false)
  const [expectedFingerprint, setExpectedFingerprint] = useState('')
  const remove = useMutation({ mutationFn: () => api.deleteHost(id), onSuccess: () => { void client.invalidateQueries({ queryKey: ['hosts'] }); navigate('/hosts') } })
  const run = useMutation({ mutationFn: () => api.createDeployment({ environment: host.data?.environment ?? '', playbook, hosts: [host.data?.name ?? ''], check_mode: checkMode }), onSuccess: (deployment) => navigate(`/deployments/${deployment.id}`) })
  const testSSH = useMutation({
    mutationFn: () => api.testHostSSH(id),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['host', id] })
      void client.invalidateQueries({ queryKey: ['hosts'] })
    },
  })
  const acceptFingerprint = useMutation({
    mutationFn: () => api.acceptHostSSHFingerprint(id, expectedFingerprint.trim()),
    onSuccess: () => {
      setExpectedFingerprint('')
      testSSH.reset()
      void client.invalidateQueries({ queryKey: ['host', id] })
    },
  })
  if (host.isLoading || posture.isLoading) return <Loading label="Chargement de la posture…" />
  if (host.isError || posture.isError) return <div className="alert error">Impossible de charger cet hôte.</div>
  const data = posture.data
  const fingerprintNeedsApproval = testSSH.data?.ssh_status === 'fingerprint_pending' || testSSH.data?.ssh_status === 'fingerprint_changed'
  return (
    <div className="page">
      <PageHeader
        eyebrow="Posture unifiée"
        title={host.data?.name ?? 'Hôte'}
        description={`${host.data?.ip ?? ''} · ${host.data?.environment ?? ''} · agent Wazuh ${data?.agent ? data.agent.status : 'non associé'}`}
        actions={(
          <>
            <label className="check-control"><input type="checkbox" checked={checkMode} onChange={(event) => setCheckMode(event.target.checked)} /> Check mode</label>
            <select value={playbook} onChange={(event) => setPlaybook(event.target.value)}>{(playbooks.data ?? []).filter((item) => item.is_allowlisted).map((item) => <option key={item.filename} value={item.filename}>{item.filename}</option>)}</select>
            <button className="primary" disabled={run.isPending || !host.data} onClick={() => run.mutate()}>{checkMode ? 'Prévisualiser' : 'Exécuter'}</button>
            <button className="secondary" disabled={testSSH.isPending} onClick={() => testSSH.mutate()}>{testSSH.isPending ? 'Test en cours…' : 'Tester SSH'}</button>
            {currentUser.data?.role === 'admin' && <button className="danger" disabled={remove.isPending} onClick={() => { if (window.confirm(`Supprimer ${host.data?.name} ?`)) remove.mutate() }}>Supprimer</button>}
          </>
        )}
      />
      <section className="detail-grid five">
        <article className="panel detail-card">
          <p className="eyebrow">Identité</p>
          <dl>
            <dt>IP</dt><dd className="mono">{host.data?.ip}</dd>
            <dt>Environnement</dt><dd>{host.data?.environment}</dd>
            <dt>Sécurité</dt><dd><StatusBadge value={host.data?.security_level} /></dd>
            <dt>Agent Wazuh</dt><dd>{data?.agent ? `${data.agent.name} (${humanize(data.agent.status)})` : 'Non associé'}</dd>
          </dl>
        </article>
        <article className="panel detail-card">
          <p className="eyebrow">Connexion Ansible</p>
          <dl>
            <dt>Utilisateur</dt><dd>{host.data?.ansible_user}</dd>
            <dt>Port</dt><dd>{host.data?.ansible_port}</dd>
            <dt>Statut SSH</dt><dd><StatusBadge value={host.data?.ssh_status} /></dd>
            <dt>Empreinte</dt><dd className="mono">{host.data?.ssh_fingerprint ?? 'Non vérifiée'}</dd>
          </dl>
          {testSSH.data && <small>{testSSH.data.message}</small>}
          {host.data?.ssh_error && <small className="host-ssh-error">{host.data.ssh_error}</small>}
        </article>
        <article className="panel detail-card">
          <p className="eyebrow">Conformité</p>
          <strong className="detail-score">{data?.compliance?.score == null ? '—' : `${Math.round(data.compliance.score)}%`}</strong>
          <small>{data?.compliance ? `${data.compliance.profile} · ${humanize(data.compliance.status)}` : 'Aucun scan disponible'}</small>
          <div className="stat-lines"><div className="stat-line"><span>Contrôles suivis</span><strong>{data?.hardening.length ?? 0}</strong></div></div>
        </article>
        <article className="panel detail-card">
          <p className="eyebrow">Patching</p>
          <strong>{data?.patch_findings.length ?? 0}</strong>
          <small>correctifs suivis</small>
          <div className="stat-lines"><div className="stat-line"><span>Source</span><strong>{data?.patch_findings[0]?.source ?? '—'}</strong></div></div>
        </article>
        <article className="panel detail-card">
          <p className="eyebrow">Live patch</p>
          <strong>{humanize(data?.livepatch?.livepatch_state ?? 'unknown')}</strong>
          <small>{data?.livepatch?.kernel ?? 'Kernel inconnu'}</small>
          <div className="stat-lines"><div className="stat-line"><span>Exposition</span><strong>{data?.livepatch?.exposure_days != null ? `${data.livepatch.exposure_days} j` : 'Inconnue'}</strong></div></div>
        </article>
      </section>

      {fingerprintNeedsApproval && (
        <article className="panel fingerprint-approval">
          <div className="panel-heading"><div><p className="eyebrow">Vérification hors bande requise</p><h2>Empreinte SSH non approuvée</h2></div><StatusBadge value="fingerprint_pending" /></div>
          <p className="host-import-note">Aucune connexion SSH n’a été tentée. Comparez l’empreinte découverte ci-dessous à une source de confiance (console ou inventaire officiel), puis saisissez la valeur vérifiée. Ne l’approuvez pas uniquement parce qu’elle a été détectée par le réseau.</p>
          <p className="mono fingerprint-candidate">{testSSH.data?.fingerprint}</p>
          <label className="fingerprint-confirm">Empreinte vérifiée hors bande<input value={expectedFingerprint} onChange={(event) => setExpectedFingerprint(event.target.value.trim())} placeholder="SHA256:…" /></label>
          {acceptFingerprint.isError && <div className="alert error">{acceptFingerprint.error instanceof Error ? acceptFingerprint.error.message : 'Approbation impossible.'}</div>}
          <div className="form-actions"><button className="primary" disabled={acceptFingerprint.isPending || !sshFingerprint.test(expectedFingerprint)} onClick={() => { if (window.confirm('Avez-vous comparé cette empreinte avec une source de confiance ?')) acceptFingerprint.mutate() }}>{acceptFingerprint.isPending ? 'Vérification…' : 'Enregistrer l’empreinte vérifiée'}</button></div>
        </article>
      )}

      <section className="dashboard-grid">
        <article className="panel">
          <div className="panel-heading"><div><p className="eyebrow">Durcissement</p><h2>Contrôles récents</h2></div><span className="badge muted">{data?.hardening.length ?? 0}</span></div>
          <DataTable
            headers={['Catégorie', 'Contrôle', 'Résultat']}
            empty="Aucun contrôle de durcissement"
            rows={(data?.hardening ?? []).map((check) => [check.category, check.control, <StatusBadge value={check.status} key={check.id} />])}
          />
        </article>
        <article className="panel">
          <div className="panel-heading"><div><p className="eyebrow">Correctifs</p><h2>Findings de l’hôte</h2></div><span className="badge muted">{data?.patch_findings.length ?? 0}</span></div>
          <DataTable
            headers={['Paquet', 'Sévérité', 'Statut']}
            empty="Aucun correctif suivi"
            rows={(data?.patch_findings ?? []).map((finding) => [finding.package, <StatusBadge value={finding.severity} key={`sev-${finding.id}`} />, <StatusBadge value={finding.status} key={`st-${finding.id}`} />])}
          />
        </article>
      </section>

      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Enrôlement SSH</p><h2>Clé publique Ansible</h2></div></div>
        {publicKey.data ? (
          <>
            <textarea className="ssh-key" readOnly value={publicKey.data.public_key} />
            <small>{host.data?.ssh_status === 'reachable' ? 'Connexion par clé vérifiée.' : host.data?.ssh_status === 'enrolling' ? 'Installation de la clé en arrière-plan…' : <>Pour les hôtes importés sans enrôlement par mot de passe, ajoutez cette clé dans <code>~/.ssh/authorized_keys</code> du compte <strong>{host.data?.ansible_user}</strong>, puis lancez « Tester SSH ».</>}</small>
          </>
        ) : <small>Génération de la clé…</small>}
      </article>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Deployments                                                         */
/* ------------------------------------------------------------------ */

function Deployments() {
  const client = useQueryClient()
  const navigate = useNavigate()
  const currentUser = useQuery({ queryKey: ['me'], queryFn: api.me })
  const canOperate = currentUser.data?.role === 'admin' || currentUser.data?.role === 'operator'
  const { data = [], isLoading } = useQuery({ queryKey: ['deployments'], queryFn: api.deployments })
  const hosts = useQuery({ queryKey: ['hosts'], queryFn: api.hosts })
  const playbooks = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks })
  const [environment, setEnvironment] = useState('')
  const [targetHosts, setTargetHosts] = useState<string[]>([])
  const [selectedPlaybook, setSelectedPlaybook] = useState('')
  const [checkMode, setCheckMode] = useState(false)
  const [filter, setFilter] = useState<'all' | 'active' | 'finished'>('all')
  const cancel = useMutation({ mutationFn: api.cancelDeployment, onSuccess: () => void client.invalidateQueries({ queryKey: ['deployments'] }) })
  const retry = useMutation({ mutationFn: api.retryDeployment, onSuccess: () => void client.invalidateQueries({ queryKey: ['deployments'] }) })
  const create = useMutation({
    mutationFn: () => api.createDeployment({ environment, playbook: selectedPlaybook, hosts: targetHosts, check_mode: checkMode }),
    onSuccess: (deployment) => {
      void client.invalidateQueries({ queryKey: ['deployments'] })
      navigate(`/deployments/${deployment.id}`)
    },
  })
  const environments = [...new Set((hosts.data ?? []).map((host) => host.environment))]
  const environmentHosts = (hosts.data ?? []).filter((host) => host.environment === environment)
  const allowedPlaybooks = (playbooks.data ?? []).filter((item) => item.is_allowlisted)
  if (isLoading) return <Loading label="Chargement des déploiements…" />
  const running = data.filter((job) => ['queued', 'running'].includes(job.status)).length
  const succeeded = data.filter((job) => job.status === 'succeeded').length
  const failed = data.filter((job) => ['failed', 'cancelled'].includes(job.status)).length
  const visible = data.filter((job) => filter === 'all' || (filter === 'active' ? ['queued', 'running'].includes(job.status) : ['succeeded', 'failed', 'cancelled'].includes(job.status)))
  return (
    <div className="page">
      <PageHeader eyebrow="Automatisation" title="Déploiements" description={`${formatNumber(data.length)} exécution(s) · ${formatNumber(running)} en cours · ${formatNumber(succeeded)} réussie(s) · ${formatNumber(failed)} échouée(s)`} />
      {canOperate && (
        <article className="panel form-panel">
          <div className="panel-heading"><div><p className="eyebrow">Nouvelle exécution</p><h2>Lancer un playbook</h2></div></div>
          <div className="form-grid">
            <label>Environnement<select value={environment} onChange={(event) => { setEnvironment(event.target.value); setTargetHosts([]) }}><option value="">Sélectionner</option>{environments.map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
            <label>Playbook<select value={selectedPlaybook} onChange={(event) => setSelectedPlaybook(event.target.value)}><option value="">Sélectionner</option>{allowedPlaybooks.map((item) => <option key={item.filename} value={item.filename}>{item.filename}</option>)}</select></label>
            <label>Hôtes cibles<select multiple value={targetHosts} onChange={(event) => setTargetHosts(Array.from(event.target.selectedOptions, (option) => option.value))}>{environmentHosts.map((host) => <option key={host.id} value={host.name}>{host.name}</option>)}</select></label>
            <label className="check-control"><input type="checkbox" checked={checkMode} onChange={(event) => setCheckMode(event.target.checked)} /> Check mode</label>
          </div>
          {create.isError && <div className="alert error">{create.error instanceof Error ? create.error.message : 'Création du déploiement impossible.'}</div>}
          <div className="form-actions"><button className="primary" disabled={create.isPending || !environment || !selectedPlaybook || targetHosts.length === 0} onClick={() => create.mutate()}>{create.isPending ? 'Mise en file…' : checkMode ? 'Prévisualiser' : 'Lancer'}</button></div>
        </article>
      )}
      {(cancel.isError || retry.isError) && <div className="alert error">{cancel.isError ? (cancel.error instanceof Error ? cancel.error.message : 'Annulation impossible.') : (retry.error instanceof Error ? retry.error.message : 'Relance impossible.')}</div>}
      <article className="panel">
        <div className="panel-heading">
          <div><p className="eyebrow">Historique</p><h2>Exécutions Ansible</h2></div>
          <div className="segmented">
            <button className={filter === 'all' ? 'active' : ''} onClick={() => setFilter('all')}>Toutes</button>
            <button className={filter === 'active' ? 'active' : ''} onClick={() => setFilter('active')}>En cours</button>
            <button className={filter === 'finished' ? 'active' : ''} onClick={() => setFilter('finished')}>Terminées</button>
          </div>
        </div>
        <DataTable
          headers={['Playbook', 'Environnement', 'Cibles', 'Lancé', 'Statut', 'Actions']}
          empty="Aucun déploiement"
          rows={visible.map((job) => [
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
  const hosts = useQuery({ queryKey: ['hosts'], queryFn: api.hosts })
  const profiles = useQuery({ queryKey: ['compliance-profiles'], queryFn: api.complianceProfiles })
  const summary = useQuery({ queryKey: ['compliance-summary'], queryFn: api.complianceSummary })
  const client = useQueryClient()
  const navigate = useNavigate()
  const [hostName, setHostName] = useState('')
  const [profile, setProfile] = useState('')
  const [launchError, setLaunchError] = useState('')
  const launch = useMutation({
    mutationFn: () => api.createDeployment({ environment: (hosts.data ?? []).find((host) => host.name === hostName)?.environment ?? '', playbook: 'openscap-scan.yml', hosts: [hostName], extra_vars: profile ? { openscap_profile: profile } : {} }),
    onSuccess: (deployment) => { setLaunchError(''); void client.invalidateQueries({ queryKey: ['compliance'] }); navigate(`/deployments/${deployment.id}`) },
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
          </>
        )}
      />
      <section className="metrics-grid three">
        <StatCard label="Hôtes scannés" item={{ value: summary.data?.hosts_scanned ?? null, status: summary.data ? 'ok' : 'unknown' }} icon={Server} />
        <StatCard label="Score moyen" item={{ value: summary.data?.average_score ?? null, status: summary.data?.average_score != null ? 'ok' : 'unknown' }} icon={Gauge} tone="success" suffix="%" />
        <StatCard label="Hôte le plus faible" item={{ value: worst?.score ?? null, status: worst ? 'ok' : 'unknown' }} icon={TriangleAlert} tone="warning" suffix="%" hint={worst?.host} />
      </section>
      <article className="panel form-panel">
        <div className="panel-heading"><div><p className="eyebrow">Nouveau scan</p><h2>Lancer OpenSCAP</h2></div></div>
        <div className="form-grid three">
          <label>Hôte<select value={hostName} onChange={(event) => setHostName(event.target.value)}><option value="">Sélectionner</option>{(hosts.data ?? []).map((host) => <option key={host.id} value={host.name}>{host.name}</option>)}</select></label>
          <label>Profil<select value={profile} onChange={(event) => setProfile(event.target.value)}><option value="">Défaut du playbook</option>{(profiles.data ?? []).map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
          <div className="form-spacer"><button className="primary" disabled={!hostName || launch.isPending} onClick={() => launch.mutate()}>{launch.isPending ? 'Lancement…' : 'Lancer OpenSCAP'}</button></div>
        </div>
        {launchError && <div className="alert error">{launchError}</div>}
      </article>
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
  const { data = [], isLoading, error } = useQuery({ queryKey: ['patch-findings'], queryFn: api.patchFindings })
  const uyuniSystems = useQuery({ queryKey: ['uyuni-systems'], queryFn: api.uyuniSystems, retry: false })
  const syncWazuh = useMutation({ mutationFn: api.syncWazuhPatches, onSuccess: () => void client.invalidateQueries({ queryKey: ['patch-findings'] }) })
  const syncUyuni = useMutation({ mutationFn: api.syncUyuni, onSuccess: () => { void client.invalidateQueries({ queryKey: ['patch-findings'] }); void client.invalidateQueries({ queryKey: ['uyuni-systems'] }) } })
  const resolve = useMutation({ mutationFn: api.resolvePatch, onSuccess: () => void client.invalidateQueries({ queryKey: ['patch-findings'] }) })
  if (isLoading) return <Loading label="Chargement des correctifs…" />
  if (error) return <div className="alert error">Impossible de charger les correctifs.</div>
  const open = data.filter((finding) => finding.status === 'open')
  const critical = open.filter((finding) => finding.severity === 'critical').length
  const high = open.filter((finding) => finding.severity === 'high').length
  const reboots = open.filter((finding) => finding.reboot_required).length
  return (
    <div className="page">
      <PageHeader
        eyebrow="Patching"
        title="Correctifs"
        description="Vulnérabilités Wazuh, errata Uyuni et état du live patching noyau."
        actions={(
          <>
            <button className="secondary" disabled={syncWazuh.isPending} onClick={() => syncWazuh.mutate()}><RefreshCw /> Synchroniser Wazuh</button>
            <button className="secondary" disabled={syncUyuni.isPending} onClick={() => syncUyuni.mutate()}><RefreshCw />{syncUyuni.isPending ? 'Récupération…' : 'Récupérer depuis Uyuni'}</button>
          </>
        )}
      />
      {syncWazuh.isError && <div className="alert error">{syncWazuh.error instanceof Error ? syncWazuh.error.message : 'Synchronisation Wazuh impossible.'}</div>}
      {syncUyuni.isError && <div className="alert error">{syncUyuni.error instanceof Error ? syncUyuni.error.message : 'Synchronisation Uyuni impossible.'}</div>}
      {syncUyuni.data && <div className="alert success">Uyuni : {syncUyuni.data.systems.systems} système(s) récupéré(s), {syncUyuni.data.systems.matched_hosts} lié(s) à l’inventaire ; {syncUyuni.data.errata.created} errata ajoutés, {syncUyuni.data.errata.updated} actualisés.</div>}
      <section className="metrics-grid">
        <StatCard label="Correctifs ouverts" item={{ value: open.length, status: 'ok' }} icon={Boxes} tone="danger" hint="findings" />
        <StatCard label="Critiques" item={{ value: critical, status: 'ok' }} icon={ShieldAlert} tone="danger" />
        <StatCard label="Élevés" item={{ value: high, status: 'ok' }} icon={TriangleAlert} tone="warning" />
        <StatCard label="Redémarrages requis" item={{ value: reboots, status: 'ok' }} icon={RefreshCw} tone="violet" />
        <StatCard label="Systèmes Uyuni" item={{ value: uyuniSystems.data?.length ?? null, status: uyuniSystems.isError ? 'unknown' : uyuniSystems.data ? 'ok' : 'unknown' }} icon={Server} />
        <StatCard label="Total findings" item={{ value: data.length, status: 'ok' }} icon={Database} hint="toutes sources" />
      </section>
      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Uyuni</p><h2>Systèmes enregistrés</h2></div><span className="badge muted">{uyuniSystems.data?.length ?? 0}</span></div>
        <DataTable
          headers={['Hôte', 'ID Uyuni', 'Statut', 'Canaux', 'Dernière synchro']}
          empty="Aucun système Uyuni synchronisé"
          rows={(uyuniSystems.data ?? []).map((system) => [
            <span className="strong" key={`h-${system.id}`}>{system.host_name}</span>,
            <span className="mono" key={`id-${system.id}`}>{system.uyuni_system_id}</span>,
            <StatusBadge value={system.status} key={`s-${system.id}`} />,
            <span key={`c-${system.id}`}>{system.channels.join(', ') || '—'}</span>,
            <span key={`d-${system.id}`}>{system.last_sync ? formatDateTime(system.last_sync) : '—'}</span>,
          ])}
        />
      </article>
      <article className="panel">
        <div className="panel-heading"><div><p className="eyebrow">Vulnérabilités</p><h2>Correctifs détectés</h2></div><span className="badge muted">{data.length}</span></div>
        <DataTable
          headers={['Hôte', 'Paquet', 'CVE', 'Errata', 'Sévérité', 'Source', 'Statut', 'Action']}
          empty="Aucun correctif connu"
          rows={data.map((finding: PatchFinding) => [
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
  const { data = [], isLoading, error } = useQuery({ queryKey: ['alerts'], queryFn: api.alerts })
  const summary = useQuery({ queryKey: ['alert-summary'], queryFn: api.alertSummary, retry: false })
  const sync = useMutation({ mutationFn: api.syncAllWazuh, onSuccess: () => { void client.invalidateQueries({ queryKey: ['alerts'] }); void client.invalidateQueries({ queryKey: ['patch-findings'] }); void client.invalidateQueries({ queryKey: ['alert-summary'] }) } })
  const ack = useMutation({ mutationFn: api.acknowledgeAlert, onSuccess: () => { void client.invalidateQueries({ queryKey: ['alerts'] }); void client.invalidateQueries({ queryKey: ['alert-summary'] }) } })
  const response = useMutation({ mutationFn: ({ id, action }: { id: number; action: 'firewall-drop' | 'disable-account' }) => api.activeResponse(id, action), onSuccess: () => { void client.invalidateQueries({ queryKey: ['alerts'] }); void client.invalidateQueries({ queryKey: ['alert-summary'] }) } })
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
  const [filename, setFilename] = useState(playbook?.filename ?? '')
  const [description, setDescription] = useState(playbook?.description ?? '')
  const [content, setContent] = useState(playbook?.content ?? '')
  const [validation, setValidation] = useState<{ valid: boolean; detail: string } | null>(null)

  const validate = useMutation({
    mutationFn: () => api.validatePlaybook(content),
    onSuccess: setValidation,
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
    },
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
    onSuccess: () => {
      setSelected('')
      setCreating(false)
      void client.invalidateQueries({ queryKey: ['playbooks'] })
      void client.invalidateQueries({ queryKey: ['playbook'] })
    },
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
      {creating && <PlaybookEditor key="new-playbook" creating selected="" canEdit={canEdit} onSaved={(saved) => { setCreating(false); setSelected(saved.filename) }} />}
      {!creating && selected && detail.isLoading && <Loading label="Chargement du playbook…" />}
      {!creating && selected && detail.isError && <div className="alert error">Impossible de charger ce playbook.</div>}
      {!creating && detail.data && <PlaybookEditor key={selected} creating={false} selected={selected} playbook={detail.data} canEdit={canEdit} onSaved={(saved) => { setSelected(saved.filename) }} />}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Settings                                                            */
/* ------------------------------------------------------------------ */

function useIntegrationTest(name: 'wazuh' | 'uyuni' | 'ansible', client: ReturnType<typeof useQueryClient>) {
  return useMutation({
    mutationFn: () => api.testIntegration(name),
    onSuccess: (state) => client.setQueryData(['integrations'], (current: Awaited<ReturnType<typeof api.integrations>> | undefined) => current ? { ...current, [name]: state } : current),
  })
}

function Settings() {
  const client = useQueryClient()
  const { data, isLoading, isError } = useQuery({ queryKey: ['integrations'], queryFn: api.integrations })
  const testWazuh = useIntegrationTest('wazuh', client)
  const testUyuni = useIntegrationTest('uyuni', client)
  const testAnsible = useIntegrationTest('ansible', client)
  if (isLoading) return <Loading label="Chargement des intégrations…" />
  if (isError || !data) return <div className="alert error">Impossible de charger les paramètres.</div>
  const integrations = [
    { name: 'Wazuh', key: 'wazuh' as const, label: 'Détection & SIEM', icon: Radar, state: data.wazuh, mutation: testWazuh },
    { name: 'Uyuni', key: 'uyuni' as const, label: 'Gestion des correctifs', icon: Boxes, state: data.uyuni, mutation: testUyuni },
    { name: 'Ansible', key: 'ansible' as const, label: 'Orchestration', icon: Cpu, state: data.ansible, mutation: testAnsible },
  ]
  const statusText = (value: boolean | null) => value === null ? 'Non testé' : value ? 'Oui' : 'Non'
  return (
    <div className="page">
      <PageHeader
        eyebrow="Configuration"
        title="Paramètres"
        description="État des services de la pile et tests de connectivité."
        actions={<button className="secondary" onClick={() => void client.invalidateQueries({ queryKey: ['integrations'] })}><RefreshCw /> Actualiser</button>}
      />
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
                <div className="stat-line"><span>Joignable</span><strong>{state.reachable === null ? (state.configured ? 'À tester' : 'Non configuré') : statusText(state.reachable)}</strong></div>
              </div>
              {state.detail && <p className="integrations-detail">{state.detail}</p>}
              {mutation.isError && <div className="alert error" style={{ marginTop: 12 }}>{mutation.error instanceof Error ? mutation.error.message : 'Test impossible.'}</div>}
              <button className="secondary btn sm" style={{ marginTop: 16 }} disabled={mutation.isPending || (key !== 'ansible' && !state.configured)} onClick={() => mutation.mutate()}>
                {mutation.isPending ? 'Test…' : key === 'ansible' ? 'Vérifier Ansible' : key === 'wazuh' ? 'Tester l’API Wazuh' : 'Tester XML-RPC Uyuni'}
              </button>
            </div>
          </article>
        ))}
      </div>
      <p className="integration-help">Ansible est vérifié localement dans l’environnement de l’API (version uniquement, aucun playbook n’est exécuté). Wazuh et Uyuni sont testés via leurs API configurées. Aucune valeur synthétique n’est affichée : une source absente reste explicitement inconnue.</p>
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
  const role = me.data?.role ? me.data.role.charAt(0).toUpperCase() + me.data.role.slice(1) : 'Session'
  return (
    <div className="app">
      <aside className="sidebar">
        <NavLink to="/" className="brand">
          <span className="brand-mark"><ShieldCheck /></span>
          <span className="brand-text"><strong>LinSec<em>360</em></strong><span>Security operations</span></span>
        </NavLink>
        <nav>
          {navGroups.map((group) => (
            <div className="nav-group" key={group.label}>
              <div className="nav-label">{group.label}</div>
              {group.items.map(({ to, label: itemLabel, icon: Icon }) => (
                <NavLink key={to} to={to} end={to === '/'}>
                  <Icon /><span>{itemLabel}</span><ChevronRight className="chevron" />
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-status"><span className="live-dot success" /><span>Console SOC <strong>active</strong></span></div>
          <button className="logout" onClick={onLogout}><LogOut /><span>Déconnexion</span></button>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="topbar-left">
            <div className="breadcrumb"><span className="crumb-root">LinSec360</span><ChevronRight /><strong>{label}</strong></div>
          </div>
          <div className="topbar-right">
            <div className="search">
              <Search />
              <input aria-label="Recherche" placeholder="Rechercher un hôte, un playbook…" />
              <kbd>⌘K</kbd>
            </div>
            <button className="icon-button" aria-label="Notifications"><Bell /><span className="notif-dot" /></button>
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
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}

function App() {
  const [authenticated, setAuthenticated] = useState(false)
  const me = useQuery({ queryKey: ['me'], queryFn: api.me, retry: false, enabled: !authenticated })
  const client = useQueryClient()
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
