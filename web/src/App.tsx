import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, Bell, Boxes, ChevronRight, CircleUserRound, HardDrive, LayoutDashboard, LogOut, Play, Radar, RefreshCw, Search, Settings, ShieldCheck } from 'lucide-react'
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Navigate, NavLink, Route, Routes } from 'react-router-dom'
import { api, type Deployment, type Host } from './api'

const nav = [
  ['/', 'Vue d’ensemble', LayoutDashboard],
  ['/hosts', 'Hôtes', HardDrive],
  ['/deployments', 'Déploiements', Play],
  ['/compliance', 'Conformité', ShieldCheck],
  ['/patching', 'Correctifs', Boxes],
  ['/detection', 'Détection', Radar],
  ['/audit', 'Audit', Activity],
  ['/settings', 'Paramètres', Settings],
] as const

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
      <form className="login-card" onSubmit={(event) => { event.preventDefault(); setError(''); login.mutate() }}>
        <div className="brand-mark"><ShieldCheck /></div>
        <p className="eyebrow">LinSec360</p><h1>Connexion sécurisée</h1>
        {error && <div className="alert error">{error}</div>}
        <label>Utilisateur<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required /></label>
        <label>Mot de passe<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
        <button className="primary" disabled={login.isPending}>{login.isPending ? 'Connexion…' : 'Se connecter'}</button>
      </form>
    </main>
  )
}

function Metric({ label, item }: { label: string; item: { value: number | null; status: string } }) {
  return <article className="metric"><span>{label}</span><strong>{item.status === 'ok' && item.value !== null ? item.value : '—'}</strong><small className={`state ${item.status}`}>{item.status === 'ok' ? 'À jour' : item.status}</small></article>
}

function DataTable({ headers, rows }: { headers: string[]; rows: (string | number)[][] }) {
  return <div className="table-wrap"><table><thead><tr>{headers.map((header) => <th key={header}>{header}</th>)}</tr></thead><tbody>{rows.length ? rows.map((row, index) => <tr key={index}>{row.map((value, cell) => <td key={cell}>{value}</td>)}</tr>) : <tr><td colSpan={headers.length} className="empty">Aucune donnée</td></tr>}</tbody></table></div>
}

function Overview() {
  const kpis = useQuery({ queryKey: ['kpis'], queryFn: api.kpis })
  const hosts = useQuery({ queryKey: ['hosts'], queryFn: api.hosts })
  const deployments = useQuery({ queryKey: ['deployments'], queryFn: api.deployments })
  const history = useQuery({ queryKey: ['kpi-history', 'compliance_score'], queryFn: () => api.kpiHistory('compliance_score') })
  if (kpis.isLoading) return <div className="loading">Chargement des métriques…</div>
  if (kpis.isError) return <div className="alert error">Impossible de charger le tableau de bord.</div>
  const data = kpis.data
  return <>
    <div className="page-heading"><div><p className="eyebrow">Centre de sécurité</p><h1>Vue d’ensemble</h1></div><button className="secondary" onClick={() => kpis.refetch()}><RefreshCw size={16} /> Actualiser</button></div>
    <section className="metrics-grid">
      <Metric label="Hôtes" item={data.hosts_total} /><Metric label="Hôtes sécurisés" item={data.hosts_secured} />
      <Metric label="Déploiements actifs" item={data.active_deployments} /><Metric label="Vulnérabilités ouvertes" item={data.open_vulnerabilities} />
      <Metric label="Score conformité" item={data.compliance_score} /><Metric label="Agents déconnectés" item={data.disconnected_agents} />
    </section>
    <article className="panel trend-panel">
      <div className="panel-heading"><div><p className="eyebrow">30 derniers jours</p><h2>Score de conformité</h2></div></div>
      {history.data?.length ? (
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={history.data.map((item) => ({ value: item.status === 'ok' ? item.value : null, date: item.captured_at.slice(0, 10) }))}>
            <XAxis dataKey="date" tick={{ fontSize: 11 }} />
            <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
            <Tooltip />
            <Line type="monotone" dataKey="value" stroke="#0878a0" strokeWidth={2} dot={false} connectNulls />
          </LineChart>
        </ResponsiveContainer>
      ) : <div className="empty">Aucune donnée historique disponible</div>}
    </article>
    <section className="dashboard-grid">
      <article className="panel"><div className="panel-heading"><div><p className="eyebrow">Inventaire</p><h2>Hôtes récents</h2></div><NavLink to="/hosts">Voir tout</NavLink></div><DataTable headers={['Hôte', 'IP', 'Environnement', 'Statut']} rows={(hosts.data ?? []).slice(0, 7).map((host: Host) => [host.name, host.ip, host.environment, host.status])} /></article>
      <article className="panel"><div className="panel-heading"><div><p className="eyebrow">Automatisation</p><h2>Déploiements récents</h2></div><NavLink to="/deployments">Voir tout</NavLink></div><DataTable headers={['Playbook', 'Cibles', 'Statut']} rows={(deployments.data ?? []).slice(0, 7).map((job: Deployment) => [job.playbook_name, String(job.targets.length), job.status])} /></article>
    </section>
  </>
}

function Hosts() {
  const { data = [], isLoading, error } = useQuery({ queryKey: ['hosts'], queryFn: api.hosts })
  if (isLoading) return <div className="loading">Chargement de l’inventaire…</div>
  if (error) return <div className="alert error">Impossible de charger les hôtes.</div>
  return <><div className="page-heading"><div><p className="eyebrow">Inventaire</p><h1>Hôtes</h1></div></div><article className="panel"><DataTable headers={['Nom', 'Adresse IP', 'Environnement', 'Sécurité', 'Statut']} rows={data.map((host) => [host.name, host.ip, host.environment, host.security_level, host.status])} /></article></>
}

function Deployments() {
  const client = useQueryClient()
  const { data = [], isLoading } = useQuery({ queryKey: ['deployments'], queryFn: api.deployments })
  const cancel = useMutation({ mutationFn: api.cancelDeployment, onSuccess: () => client.invalidateQueries({ queryKey: ['deployments'] }) })
  const retry = useMutation({ mutationFn: api.retryDeployment, onSuccess: () => client.invalidateQueries({ queryKey: ['deployments'] }) })
  if (isLoading) return <div className="loading">Chargement des déploiements…</div>
  return <><div className="page-heading"><div><p className="eyebrow">Automatisation</p><h1>Déploiements</h1></div></div><article className="panel"><div className="table-wrap"><table><thead><tr><th>Playbook</th><th>Environnement</th><th>Cibles</th><th>Statut</th><th>Actions</th></tr></thead><tbody>{data.map((job) => <tr key={job.id}><td>{job.playbook_name}</td><td>{job.environment_name}</td><td>{job.targets.length}</td><td><span className={`status ${job.status}`}>{job.status}</span></td><td>{job.status === 'running' || job.status === 'queued' ? <button className="link-button" onClick={() => cancel.mutate(job.id)}>Annuler</button> : <button className="link-button" onClick={() => retry.mutate(job.id)}>Réexécuter</button>}</td></tr>)}</tbody></table></div></article></>
}

function Compliance() {
  const { data = [], isLoading, error } = useQuery({ queryKey: ['compliance'], queryFn: api.complianceScans })
  if (isLoading) return <div className="loading">Chargement des résultats OpenSCAP…</div>
  if (error) return <div className="alert error">Impossible de charger la conformité.</div>
  const rows = data.map((item) => {
    const scan = item as Record<string, unknown>
    return [scan.id, scan.host_name, scan.profile, scan.status, scan.score ?? '—'].map(String)
  })
  return <>
    <div className="page-heading"><div><p className="eyebrow">OpenSCAP</p><h1>Conformité</h1></div><div style={{ display: 'flex', gap: 8 }}>
      <button className="secondary" onClick={() => void api.exportCompliance('csv')}>Exporter CSV</button>
      <button className="secondary" onClick={() => void api.exportCompliance('json')}>Exporter JSON</button>
    </div></div>
    <article className="panel"><DataTable headers={['ID', 'Hôte', 'Profil', 'Statut', 'Score']} rows={rows} /></article>
  </>
}

function Collection({ title, loader, columns }: { title: string; loader: () => Promise<unknown[]>; columns: string[] }) {
  const { data = [], isLoading, error } = useQuery({ queryKey: [title], queryFn: loader })
  if (isLoading) return <div className="loading">Chargement…</div>
  if (error) return <div className="alert error">Impossible de charger {title.toLowerCase()}.</div>
  const rows = data.map((item) => {
    const record = item as Record<string, unknown>
    return Object.values(record).slice(0, columns.length).map((value) => String(value ?? ''))
  })
  return <><div className="page-heading"><div><p className="eyebrow">LinSec360</p><h1>{title}</h1></div></div><article className="panel"><DataTable headers={columns} rows={rows} /></article></>
}

function App() {
  const [authenticated, setAuthenticated] = useState(false)
  const me = useQuery({ queryKey: ['me'], queryFn: api.me, retry: false, enabled: !authenticated })
  const client = useQueryClient()
  if (!authenticated && me.isLoading) return <div className="login-page"><div className="loading">Vérification de la session…</div></div>
  if (!authenticated && me.isError) return <Login onLogin={() => { setAuthenticated(true); void client.invalidateQueries() }} />
  const logout = async () => { await api.logout(); client.clear(); setAuthenticated(false) }
  return <div className="app">
    <aside className="sidebar"><div className="brand"><ShieldCheck /><span>LinSec<strong>360</strong></span></div><nav>{nav.map(([to, label, Icon]) => <NavLink key={to} to={to} end={to === '/'}><Icon /><span>{label}</span><ChevronRight className="chevron" /></NavLink>)}</nav><button className="logout" onClick={logout}><LogOut /><span>Déconnexion</span></button></aside>
    <main className="main"><header className="topbar"><div className="search"><Search /><input aria-label="Recherche" placeholder="Rechercher…" /></div><button className="icon-button" aria-label="Notifications"><Bell /></button><button className="icon-button" aria-label="Compte"><CircleUserRound /></button></header><div className="content">
      <Routes>
        <Route path="/" element={<Overview />} /><Route path="/hosts" element={<Hosts />} /><Route path="/deployments" element={<Deployments />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/patching" element={<Collection title="Correctifs" loader={api.patchFindings} columns={['Hôte', 'Paquet', 'CVE', 'Sévérité', 'Statut']} />} />
        <Route path="/detection" element={<Collection title="Détection" loader={api.alerts} columns={['ID', 'Horodatage', 'Agent', 'Sévérité', 'Description']} />} />
        <Route path="/audit" element={<Collection title="Audit" loader={api.audit} columns={['Action', 'Cible', 'Acteur', 'Horodatage']} />} />
        <Route path="/settings" element={<Collection title="Paramètres" loader={api.integrations} columns={['Intégration', 'Configurée', 'Accessible']} />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div></main>
  </div>
}

export default App
