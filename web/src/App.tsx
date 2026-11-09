import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, Bell, Boxes, ChevronRight, CircleUserRound, HardDrive, LayoutDashboard, LogOut, Play, Radar, RefreshCw, Search, Settings as SettingsIcon, ShieldCheck } from 'lucide-react'
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Navigate, NavLink, Route, Routes, useNavigate, useParams } from 'react-router-dom'
import { api, type Alert, type Deployment, type Host, type PatchFinding } from './api'

const nav = [
  ['/', 'Vue d’ensemble', LayoutDashboard],
  ['/hosts', 'Hôtes', HardDrive],
  ['/deployments', 'Déploiements', Play],
  ['/compliance', 'Conformité', ShieldCheck],
  ['/patching', 'Correctifs', Boxes],
  ['/detection', 'Détection', Radar],
  ['/audit', 'Audit', Activity],
  ['/settings', 'Paramètres', SettingsIcon],
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
      <article className="panel"><div className="panel-heading"><div><p className="eyebrow">Automatisation</p><h2>Déploiements récents</h2></div><NavLink to="/deployments">Voir tout</NavLink></div><DataTable headers={['Playbook', 'Cibles', 'Statut']} rows={(deployments.data ?? []).slice(0, 7).map((job: Deployment) => [job.playbook, String(job.target_hosts.length), job.status])} /></article>
    </section>
  </>
}

function Hosts() {
  const client = useQueryClient()
  const navigate = useNavigate()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', ip: '', environment: 'production', security_level: 'high', groups: '', ansible_user: 'linsec-ansible', ansible_port: 22 })
  const { data = [], isLoading, error } = useQuery({ queryKey: ['hosts'], queryFn: api.hosts })
  const create = useMutation({
    mutationFn: () => api.createHost({
      ...form,
      groups: form.groups.split(',').map((value) => value.trim()).filter(Boolean),
    }),
    onSuccess: () => { setShowForm(false); setForm({ name: '', ip: '', environment: 'production', security_level: 'high', groups: '', ansible_user: 'linsec-ansible', ansible_port: 22 }); void client.invalidateQueries({ queryKey: ['hosts'] }) },
  })
  if (isLoading) return <div className="loading">Chargement de l’inventaire…</div>
  if (error) return <div className="alert error">Impossible de charger les hôtes.</div>
  return <>
    <div className="page-heading"><div><p className="eyebrow">Inventaire</p><h1>Hôtes</h1></div><button className="primary" onClick={() => setShowForm(true)}>Ajouter un hôte</button></div>
    {showForm && <article className="panel form-panel"><div className="panel-heading"><h2>Nouvel hôte</h2></div><div className="form-grid">
      <label>Nom<input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></label>
      <label>Adresse IP<input value={form.ip} onChange={(event) => setForm({ ...form, ip: event.target.value })} /></label>
      <label>Environnement<select value={form.environment} onChange={(event) => setForm({ ...form, environment: event.target.value })}><option value="production">production</option><option value="staging">staging</option><option value="development">development</option></select></label>
      <label>Niveau<select value={form.security_level} onChange={(event) => setForm({ ...form, security_level: event.target.value })}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
      <label>Groupes<input value={form.groups} onChange={(event) => setForm({ ...form, groups: event.target.value })} placeholder="linux,servers" /></label>
      <label>Utilisateur SSH<input value={form.ansible_user} onChange={(event) => setForm({ ...form, ansible_user: event.target.value })} /></label>
      <label>Port SSH<input type="number" min="1" max="65535" value={form.ansible_port} onChange={(event) => setForm({ ...form, ansible_port: Number(event.target.value) })} /></label>
    </div>{create.isError && <div className="alert error">{create.error instanceof Error ? create.error.message : 'Création impossible'}</div>}<div className="form-actions"><button className="secondary" onClick={() => setShowForm(false)}>Annuler</button><button className="primary" disabled={create.isPending || !form.name || !form.ip} onClick={() => create.mutate()}>Créer</button></div></article>}
    <article className="panel"><div className="table-wrap"><table><thead><tr><th>Nom</th><th>Adresse IP</th><th>Environnement</th><th>Sécurité</th><th>Statut</th><th>Actions</th></tr></thead><tbody>{data.map((host) => <tr key={host.id}><td>{host.name}</td><td>{host.ip}</td><td>{host.environment}</td><td>{host.security_level}</td><td><span className={`status ${host.status}`}>{host.status}</span></td><td><button className="link-button" onClick={() => navigate(`/hosts/${host.id}`)}>Voir la posture</button></td></tr>)}{!data.length && <tr><td className="empty" colSpan={6}>Aucun hôte enregistré</td></tr>}</tbody></table></div></article>
  </>
}

function HostDetail() {
  const { hostId = '' } = useParams()
  const id = Number(hostId)
  const navigate = useNavigate()
  const client = useQueryClient()
  const host = useQuery({ queryKey: ['host', id], queryFn: () => api.host(id), enabled: Number.isInteger(id) })
  const posture = useQuery({ queryKey: ['host-posture', id], queryFn: () => api.hostPosture(id), enabled: Number.isInteger(id) })
  const playbooks = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks })
  const publicKey = useQuery({ queryKey: ['ansible-public-key'], queryFn: api.ansiblePublicKey })
  const [playbook, setPlaybook] = useState('openscap-scan.yml')
  const [checkMode, setCheckMode] = useState(false)
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
    mutationFn: () => api.acceptHostSSHFingerprint(id),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['host', id] })
    },
  })
  if (host.isLoading || posture.isLoading) return <div className="loading">Chargement de la posture…</div>
  if (host.isError || posture.isError) return <div className="alert error">Impossible de charger cet hôte.</div>
  const data = posture.data
  return <>
    <div className="page-heading"><div><p className="eyebrow">Posture unifiée</p><h1>{host.data?.name}</h1></div><div className="actions"><label className="check-control"><input type="checkbox" checked={checkMode} onChange={(event) => setCheckMode(event.target.checked)} /> Check mode</label><select value={playbook} onChange={(event) => setPlaybook(event.target.value)}>{(playbooks.data ?? []).filter((item) => item.is_allowlisted).map((item) => <option key={item.filename} value={item.filename}>{item.filename}</option>)}</select><button className="primary" disabled={run.isPending || !host.data} onClick={() => run.mutate()}>{checkMode ? 'Prévisualiser' : 'Exécuter'}</button>{host.data?.ssh_status === 'fingerprint_changed' && <button className="secondary" disabled={acceptFingerprint.isPending} onClick={() => { if (window.confirm('Accepter explicitement la nouvelle empreinte SSH ?')) acceptFingerprint.mutate() }}>Accepter l’empreinte</button>}<button className="secondary" disabled={testSSH.isPending} onClick={() => testSSH.mutate()}>{testSSH.isPending ? 'Test en cours…' : 'Tester SSH'}</button><button className="danger" onClick={() => { if (window.confirm(`Supprimer ${host.data?.name} ?`)) remove.mutate() }}>Supprimer</button></div></div>
    <section className="detail-grid">
      <article className="panel detail-card"><p className="eyebrow">Identité</p><dl><dt>IP</dt><dd>{host.data?.ip}</dd><dt>Environnement</dt><dd>{host.data?.environment}</dd><dt>Sécurité</dt><dd>{host.data?.security_level}</dd><dt>Agent Wazuh</dt><dd>{data?.agent ? `${data.agent.name} (${data.agent.status})` : 'Non associé'}</dd></dl></article>
      <article className="panel detail-card"><p className="eyebrow">Connexion Ansible</p><dl><dt>Utilisateur</dt><dd>{host.data?.ansible_user}</dd><dt>Port</dt><dd>{host.data?.ansible_port}</dd><dt>Statut SSH</dt><dd><span className={`status ${host.data?.ssh_status}`}>{host.data?.ssh_status}</span></dd><dt>Empreinte</dt><dd className="mono">{host.data?.ssh_fingerprint ?? 'Non vérifiée'}</dd></dl>{testSSH.data && <small>{testSSH.data.message}</small>}{host.data?.ssh_error && <small className="alert error">{host.data.ssh_error}</small>}</article>
      <article className="panel detail-card"><p className="eyebrow">Conformité</p><strong className="detail-score">{data?.compliance?.score ?? '—'}%</strong><small>{data?.compliance ? `${data.compliance.profile} · ${data.compliance.status}` : 'Aucun scan disponible'}</small></article>
      <article className="panel detail-card"><p className="eyebrow">Patching</p><strong>{data?.patch_findings.length ?? 0}</strong><small>correctifs suivis</small></article>
      <article className="panel detail-card"><p className="eyebrow">Live patch</p><strong>{data?.livepatch?.livepatch_state ?? 'unknown'}</strong><small>{data?.livepatch?.kernel ?? 'Kernel inconnu'}</small></article>
    </section>
    <article className="panel"><div className="panel-heading"><div><p className="eyebrow">Enrôlement SSH</p><h2>Clé publique Ansible</h2></div></div>{publicKey.data ? <><textarea className="ssh-key" readOnly value={publicKey.data.public_key} /><small>Ajoutez cette clé dans <code>~/.ssh/authorized_keys</code> du compte <strong>{host.data?.ansible_user}</strong>, puis lancez « Tester SSH ».</small></> : <small>Génération de la clé…</small>}</article>
    <article className="panel"><div className="panel-heading"><div><p className="eyebrow">Durcissement</p><h2>Contrôles récents</h2></div></div><DataTable headers={['Catégorie', 'Contrôle', 'Résultat']} rows={(data?.hardening ?? []).map((check) => [check.category, check.control, check.status])} /></article>
  </>
}

function Deployments() {
  const client = useQueryClient()
  const navigate = useNavigate()
  const { data = [], isLoading } = useQuery({ queryKey: ['deployments'], queryFn: api.deployments })
  const cancel = useMutation({ mutationFn: api.cancelDeployment, onSuccess: () => client.invalidateQueries({ queryKey: ['deployments'] }) })
  const retry = useMutation({ mutationFn: api.retryDeployment, onSuccess: () => client.invalidateQueries({ queryKey: ['deployments'] }) })
  if (isLoading) return <div className="loading">Chargement des déploiements…</div>
  return <>
    <div className="page-heading"><div><p className="eyebrow">Automatisation</p><h1>Déploiements</h1></div></div>
    <article className="panel"><div className="table-wrap"><table><thead><tr><th>Playbook</th><th>Environnement</th><th>Cibles</th><th>Statut</th><th>Actions</th></tr></thead><tbody>{data.map((job) => <tr key={job.id}><td><button className="link-button strong" onClick={() => navigate(`/deployments/${job.id}`)}>{job.playbook}</button></td><td>{job.environment}</td><td>{job.target_hosts.length}</td><td><span className={`status ${job.status}`}>{job.status}</span></td><td>{job.status === 'running' || job.status === 'queued' ? <button className="link-button" onClick={() => cancel.mutate(job.id)}>Annuler</button> : <button className="link-button" onClick={() => retry.mutate(job.id)}>Réexécuter</button>}</td></tr>)}{!data.length && <tr><td className="empty" colSpan={5}>Aucun déploiement</td></tr>}</tbody></table></div></article>
  </>
}

function DeploymentDetail() {
  const { deploymentId = '' } = useParams()
  const { data: job, isLoading, isError } = useQuery({ queryKey: ['deployment', deploymentId], queryFn: () => api.deployment(deploymentId), refetchInterval: (query) => ['queued', 'running'].includes(query.state.data?.status ?? '') ? 2000 : false })
  const events = useQuery({ queryKey: ['deployment-events', deploymentId], queryFn: () => api.deploymentEvents(deploymentId), refetchInterval: job?.status === 'running' || job?.status === 'queued' ? 2000 : false })
  const log = useQuery({ queryKey: ['deployment-log', deploymentId], queryFn: () => api.deploymentLog(deploymentId), refetchInterval: job?.status === 'running' || job?.status === 'queued' ? 2000 : false })
  if (isLoading) return <div className="loading">Chargement du déploiement…</div>
  if (isError || !job) return <div className="alert error">Impossible de charger ce déploiement.</div>
  return <>
    <div className="page-heading"><div><p className="eyebrow">Déploiement</p><h1>{job.playbook}</h1></div><span className={`status ${job.status}`}>{job.status}</span></div>
    <section className="detail-grid">
      <article className="panel detail-card"><p className="eyebrow">Environnement</p><strong>{job.environment}</strong></article>
      <article className="panel detail-card"><p className="eyebrow">Cibles</p><strong>{job.target_hosts.length}</strong></article>
    </section>
    <article className="panel log-panel"><div className="panel-heading"><h2>Sortie Ansible</h2></div><pre>{log.data || 'Aucune sortie disponible.'}</pre></article>
    <article className="panel"><div className="panel-heading"><h2>Événements</h2></div><DataTable headers={['Horodatage', 'Niveau', 'Événement', 'Message']} rows={(events.data ?? []).map((event) => [event.created_at, event.level, event.event, event.message])} /></article>
  </>
}

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
  if (isLoading) return <div className="loading">Chargement des résultats OpenSCAP…</div>
  if (error) return <div className="alert error">Impossible de charger la conformité.</div>
  const rows = data.map((item) => {
    const scan = item as unknown as Record<string, unknown>
    return [scan.id, scan.host_name, scan.profile, scan.status, scan.score ?? '—'].map(String)
  })
  return <>
    <div className="page-heading"><div><p className="eyebrow">OpenSCAP</p><h1>Conformité</h1></div><div style={{ display: 'flex', gap: 8 }}>
      <button className="secondary" onClick={() => void api.exportCompliance('csv')}>Exporter CSV</button>
      <button className="secondary" onClick={() => void api.exportCompliance('json')}>Exporter JSON</button>
    </div></div>
    <section className="metrics-grid">
      <Metric label="Hôtes scannés" item={{ value: summary.data?.hosts_scanned ?? null, status: summary.data ? 'ok' : 'unknown' }} />
      <Metric label="Score moyen" item={{ value: summary.data?.average_score ?? null, status: summary.data?.average_score != null ? 'ok' : 'unknown' }} />
      <Metric label="Plus faible score" item={{ value: summary.data?.worst_hosts[0]?.score ?? null, status: summary.data?.worst_hosts.length ? 'ok' : 'unknown' }} />
    </section>
    <article className="panel form-panel"><div className="panel-heading"><h2>Lancer un scan</h2></div><div className="form-grid">
      <label>Hôte<select value={hostName} onChange={(event) => setHostName(event.target.value)}><option value="">Sélectionner</option>{(hosts.data ?? []).map((host) => <option key={host.id} value={host.name}>{host.name}</option>)}</select></label>
      <label>Profil<select value={profile} onChange={(event) => setProfile(event.target.value)}><option value="">Défaut du playbook</option>{(profiles.data ?? []).map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
      <div className="form-spacer"><button className="primary" disabled={!hostName || launch.isPending} onClick={() => launch.mutate()}>{launch.isPending ? 'Lancement…' : 'Lancer OpenSCAP'}</button></div>
    </div>{launchError && <div className="alert error">{launchError}</div>}</article>
    <article className="panel"><DataTable headers={['ID', 'Hôte', 'Profil', 'Statut', 'Score']} rows={rows} /></article>
  </>
}

function Patching() {
  const client = useQueryClient()
  const { data = [], isLoading, error } = useQuery({ queryKey: ['patch-findings'], queryFn: api.patchFindings })
  const uyuniSystems = useQuery({ queryKey: ['uyuni-systems'], queryFn: api.uyuniSystems })
  const syncWazuh = useMutation({ mutationFn: api.syncWazuhPatches, onSuccess: () => void client.invalidateQueries({ queryKey: ['patch-findings'] }) })
  const syncUyuni = useMutation({ mutationFn: api.syncUyuni, onSuccess: () => { void client.invalidateQueries({ queryKey: ['patch-findings'] }); void client.invalidateQueries({ queryKey: ['uyuni-systems'] }) } })
  const resolve = useMutation({ mutationFn: api.resolvePatch, onSuccess: () => void client.invalidateQueries({ queryKey: ['patch-findings'] }) })
  if (isLoading) return <div className="loading">Chargement…</div>
  if (error) return <div className="alert error">Impossible de charger les correctifs.</div>
  return <>
    <div className="page-heading"><div><p className="eyebrow">Patching</p><h1>Correctifs</h1></div><div className="actions"><button className="secondary" disabled={syncWazuh.isPending} onClick={() => syncWazuh.mutate()}><RefreshCw size={15} /> Synchroniser Wazuh</button><button className="secondary" disabled={syncUyuni.isPending} onClick={() => syncUyuni.mutate()}><RefreshCw size={15} /> Synchroniser Uyuni</button></div></div>
    {(syncWazuh.isError || syncUyuni.isError) && <div className="alert error">Une intégration n’est pas configurée ou inaccessible.</div>}
    <article className="panel"><div className="panel-heading"><div><p className="eyebrow">Uyuni</p><h2>Systèmes enregistrés</h2></div></div><div className="table-wrap"><table><thead><tr><th>Hôte</th><th>ID Uyuni</th><th>Statut</th><th>Canaux</th><th>Dernière synchro</th></tr></thead><tbody>{(uyuniSystems.data ?? []).map((system) => <tr key={system.id}><td>{system.host_name}</td><td>{system.uyuni_system_id}</td><td><span className={`status ${system.status}`}>{system.status}</span></td><td>{system.channels.join(', ') || '—'}</td><td>{system.last_sync ?? '—'}</td></tr>)}{!uyuniSystems.data?.length && <tr><td className="empty" colSpan={5}>Aucun système Uyuni synchronisé</td></tr>}</tbody></table></div></article>
    <article className="panel"><div className="table-wrap"><table><thead><tr><th>Hôte</th><th>Paquet</th><th>CVE</th><th>Errata</th><th>Sévérité</th><th>Source</th><th>Statut</th><th>Action</th></tr></thead><tbody>{data.map((finding: PatchFinding) => <tr key={finding.id}><td>{finding.host_name}</td><td>{finding.package}</td><td>{finding.cve || '—'}</td><td>{finding.errata || '—'}</td><td>{finding.severity}</td><td>{finding.source}</td><td><span className={`status ${finding.status}`}>{finding.status}</span></td><td>{finding.status !== 'resolved' && <button className="link-button" disabled={resolve.isPending} onClick={() => resolve.mutate(finding.id)}>Résoudre</button>}</td></tr>)}{!data.length && <tr><td className="empty" colSpan={8}>Aucun correctif connu</td></tr>}</tbody></table></div></article>
  </>
}

function Detection() {
  const client = useQueryClient()
  const { data = [], isLoading, error } = useQuery({ queryKey: ['alerts'], queryFn: api.alerts })
  const sync = useMutation({ mutationFn: api.syncAllWazuh, onSuccess: () => { void client.invalidateQueries({ queryKey: ['alerts'] }); void client.invalidateQueries({ queryKey: ['patch-findings'] }); } })
  const ack = useMutation({ mutationFn: api.acknowledgeAlert, onSuccess: () => void client.invalidateQueries({ queryKey: ['alerts'] }) })
  const response = useMutation({ mutationFn: ({ id, action }: { id: number; action: 'firewall-drop' | 'disable-account' }) => api.activeResponse(id, action), onSuccess: () => void client.invalidateQueries({ queryKey: ['alerts'] }) })
  if (isLoading) return <div className="loading">Chargement des alertes…</div>
  if (error) return <div className="alert error">Impossible de charger les alertes.</div>
  return <>
    <div className="page-heading"><div><p className="eyebrow">Wazuh</p><h1>Détection</h1></div><button className="secondary" disabled={sync.isPending} onClick={() => sync.mutate()}><RefreshCw size={15} /> Synchroniser</button></div>
    {sync.isError && <div className="alert error">{sync.error instanceof Error ? sync.error.message : 'Synchronisation Wazuh impossible'}</div>}
    <article className="panel"><div className="table-wrap"><table><thead><tr><th>Horodatage</th><th>Agent</th><th>Sévérité</th><th>Règle</th><th>Description</th><th>Statut</th><th>Actions</th></tr></thead><tbody>{data.map((alert: Alert) => <tr key={alert.id}><td>{alert.timestamp}</td><td>{alert.agent_name || alert.agent_id || '—'}</td><td><span className={`status ${alert.severity}`}>{alert.severity}</span></td><td>{alert.rule_id || '—'} · niveau {alert.rule_level ?? '—'}</td><td>{alert.description || '—'}</td><td>{alert.acknowledged ? 'Acquittée' : 'Nouvelle'}</td><td>{!alert.acknowledged && <button className="link-button" onClick={() => ack.mutate(alert.id)}>Acquitter</button>}<button className="link-button" disabled={response.isPending || !alert.agent_id} onClick={() => { if (window.confirm('Envoyer firewall-drop à cet agent Wazuh ?')) response.mutate({ id: alert.id, action: 'firewall-drop' }) }}>Bloquer</button></td></tr>)}{!data.length && <tr><td className="empty" colSpan={7}>Aucune alerte synchronisée</td></tr>}</tbody></table></div></article>
  </>
}

function Audit() {
  const { data = [], isLoading, error } = useQuery({ queryKey: ['audit'], queryFn: api.audit })
  if (isLoading) return <div className="loading">Chargement de l’audit…</div>
  if (error) return <div className="alert error">Impossible de charger l’audit.</div>
  return <><div className="page-heading"><div><p className="eyebrow">Traçabilité</p><h1>Audit</h1></div></div><article className="panel"><div className="table-wrap"><table><thead><tr><th>Horodatage</th><th>Acteur</th><th>Action</th><th>Type</th><th>Cible</th></tr></thead><tbody>{data.map((item) => <tr key={item.id}><td>{item.created_at}</td><td>{item.actor_username || 'Système'}</td><td>{item.action}</td><td>{item.target_type}</td><td>{item.target_id || '—'}</td></tr>)}{!data.length && <tr><td className="empty" colSpan={5}>Aucun événement audité</td></tr>}</tbody></table></div></article></>
}

function Settings() {
  const { data = [], isLoading, isError } = useQuery({ queryKey: ['integrations'], queryFn: api.integrations })
  const testWazuh = useMutation({ mutationFn: () => fetch('/api/v1/integrations/wazuh/test', { method: 'POST', credentials: 'include', headers: { 'X-CSRF-Token': decodeURIComponent(document.cookie.match(/(?:^|; )linsec_csrf=([^;]*)/)?.[1] ?? '') } }).then(async (response) => ({ ok: response.ok, payload: await response.json() })) })
  const testUyuni = useMutation({ mutationFn: () => fetch('/api/v1/integrations/uyuni/test', { method: 'POST', credentials: 'include', headers: { 'X-CSRF-Token': decodeURIComponent(document.cookie.match(/(?:^|; )linsec_csrf=([^;]*)/)?.[1] ?? '') } }).then(async (response) => ({ ok: response.ok, payload: await response.json() })) })
  if (isLoading) return <div className="loading">Chargement des intégrations…</div>
  if (isError) return <div className="alert error">Impossible de charger les paramètres.</div>
  const wazuhReachable = (testWazuh.data?.payload as { reachable?: boolean } | undefined)?.reachable
  const uyuniReachable = (testUyuni.data?.payload as { reachable?: boolean } | undefined)?.reachable
  return <>
    <div className="page-heading"><div><p className="eyebrow">Configuration</p><h1>Paramètres</h1></div></div>
    <article className="panel">
      <div className="table-wrap">
        <table>
          <thead><tr><th>Intégration</th><th>Configurée</th><th>Accessible</th><th>Actions</th></tr></thead>
          <tbody>
            {data.map((item) => (
              <tr key={item.integration}>
                <td>{item.integration}</td>
                <td>{item.configured ? 'Oui' : 'Non'}</td>
                <td>{item.reachable}</td>
                <td>
                  {item.integration === 'Wazuh' ? (
                    <button className="link-button" disabled={testWazuh.isPending || !item.configured} onClick={() => testWazuh.mutate()}>Tester</button>
                  ) : (
                    <button className="link-button" disabled={testUyuni.isPending || !item.configured} onClick={() => testUyuni.mutate()}>Tester</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </article>
    {testWazuh.data && <div className={`alert ${wazuhReachable ? 'success' : 'error'}`}>{wazuhReachable ? 'Wazuh accessible' : 'Wazuh inaccessible ou non configuré'}</div>}
    {testUyuni.data && <div className={`alert ${uyuniReachable ? 'success' : 'error'}`}>{uyuniReachable ? 'Uyuni accessible' : 'Uyuni inaccessible ou non configuré'}</div>}
  </>
}

function App() {
  const [authenticated, setAuthenticated] = useState(false)
  const me = useQuery({ queryKey: ['me'], queryFn: api.me, retry: false, enabled: !authenticated })
  const client = useQueryClient()
  if (!authenticated && me.isLoading) return <div className="login-page"><div className="loading">Vérification de la session…</div></div>
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
  return <div className="app">
    <aside className="sidebar"><div className="brand"><ShieldCheck /><span>LinSec<strong>360</strong></span></div><nav>{nav.map(([to, label, Icon]) => <NavLink key={to} to={to} end={to === '/'}><Icon /><span>{label}</span><ChevronRight className="chevron" /></NavLink>)}</nav><button className="logout" onClick={logout}><LogOut /><span>Déconnexion</span></button></aside>
    <main className="main"><header className="topbar"><div className="search"><Search /><input aria-label="Recherche" placeholder="Rechercher…" /></div><button className="icon-button" aria-label="Notifications"><Bell /></button><button className="icon-button" aria-label="Compte"><CircleUserRound /></button></header><div className="content">
      <Routes>
        <Route path="/" element={<Overview />} /><Route path="/hosts" element={<Hosts />} /><Route path="/deployments" element={<Deployments />} />
        <Route path="/hosts/:hostId" element={<HostDetail />} />
        <Route path="/deployments/:deploymentId" element={<DeploymentDetail />} />
        <Route path="/compliance" element={<Compliance />} />
        <Route path="/patching" element={<Patching />} />
        <Route path="/detection" element={<Detection />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div></main>
  </div>
}

export default App
