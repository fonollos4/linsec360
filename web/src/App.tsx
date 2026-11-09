import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, Bell, Boxes, ChevronRight, CircleUserRound, FileCode2, HardDrive, LayoutDashboard, LogOut, Play, Radar, RefreshCw, Search, Settings as SettingsIcon, ShieldCheck } from 'lucide-react'
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Navigate, NavLink, Route, Routes, useNavigate, useParams } from 'react-router-dom'
import { api, type Alert, type Deployment, type Host, type HostImportItem, type PatchFinding, type PlaybookDetail } from './api'

const nav = [
  ['/', 'Vue d’ensemble', LayoutDashboard],
  ['/hosts', 'Hôtes', HardDrive],
  ['/deployments', 'Déploiements', Play],
  ['/playbooks', 'Playbooks', FileCode2],
  ['/compliance', 'Conformité', ShieldCheck],
  ['/patching', 'Correctifs', Boxes],
  ['/detection', 'Détection', Radar],
  ['/audit', 'Audit', Activity],
  ['/settings', 'Paramètres', SettingsIcon],
] as const

const hostIdentifier = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/
const sshFingerprint = /^SHA256:[A-Za-z0-9+/]{43}$/
const hostCsvColumns = ['name', 'ip', 'environment', 'security_level', 'groups', 'ansible_user', 'ansible_port', 'ssh_fingerprint']

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

function parseHostCsv(text: string): HostImportItem[] {
  const rows = parseCsv(text)
  if (!rows.length) throw new Error('Le fichier CSV est vide.')
  if (rows.length > 201) throw new Error('Maximum 200 hôtes par import.')
  const headers = rows[0].map((value, index) =>
    (index === 0 ? value.replace(/^\uFEFF/, '') : value).trim().toLowerCase(),
  )
  if (new Set(headers).size !== headers.length) throw new Error('En-têtes CSV dupliqués.')
  const unsupported = headers.filter((header) => !hostCsvColumns.includes(header))
  if (unsupported.length) throw new Error(`Colonnes non acceptées : ${unsupported.join(', ')}.`)
  const required = ['name', 'ip', 'environment', 'ssh_fingerprint']
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
    const fingerprint = values.ssh_fingerprint ?? ''
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
    if (!sshFingerprint.test(fingerprint)) {
      throw new Error(`Ligne ${rowNumber} : empreinte SSH SHA256 invalide ou absente.`)
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
      ssh_fingerprint: fingerprint,
    }
  })
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
  const [showImport, setShowImport] = useState(false)
  const [importRows, setImportRows] = useState<HostImportItem[]>([])
  const [importError, setImportError] = useState('')
  const [form, setForm] = useState({ name: '', ip: '', environment: 'production', security_level: 'high', groups: '', ansible_user: 'linsec-ansible', ansible_port: 22, ssh_fingerprint: '' })
  const { data = [], isLoading, error } = useQuery({ queryKey: ['hosts'], queryFn: api.hosts })
  const create = useMutation({
    mutationFn: () => api.createHost({
      ...form,
      groups: form.groups.split(',').map((value) => value.trim()).filter(Boolean),
      ssh_fingerprint: form.ssh_fingerprint.trim() || undefined,
    }),
    onSuccess: () => { setShowForm(false); setForm({ name: '', ip: '', environment: 'production', security_level: 'high', groups: '', ansible_user: 'linsec-ansible', ansible_port: 22, ssh_fingerprint: '' }); void client.invalidateQueries({ queryKey: ['hosts'] }) },
  })
  const importHosts = useMutation({
    mutationFn: () => api.importHosts(importRows),
    onSuccess: () => { void client.invalidateQueries({ queryKey: ['hosts'] }) },
  })
  const readImportFile = (file?: File) => {
    importHosts.reset()
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
      setImportRows(parsed)
    }).catch((cause: unknown) => {
      setImportError(cause instanceof Error ? cause.message : 'Lecture du CSV impossible.')
    })
  }
  if (isLoading) return <div className="loading">Chargement de l’inventaire…</div>
  if (error) return <div className="alert error">Impossible de charger les hôtes.</div>
  return <>
    <div className="page-heading"><div><p className="eyebrow">Inventaire</p><h1>Hôtes</h1></div><div className="actions"><button className="secondary" onClick={() => setShowImport((visible) => !visible)}>Import CSV</button><button className="primary" onClick={() => setShowForm(true)}>Ajouter un hôte</button></div></div>
    {showImport && <article className="panel form-panel host-import">
      <div className="panel-heading"><div><p className="eyebrow">Import d’inventaire</p><h2>Ajouter plusieurs hôtes</h2></div></div>
      <p className="host-import-note">CSV sans mot de passe ni clé privée. Colonnes requises : <code>name,ip,environment,ssh_fingerprint</code>. L’empreinte SHA256 doit être vérifiée hors bande avant l’import ; la clé publique Ansible doit déjà être installée par votre procédure d’administration. L’import ne contacte pas les hôtes.</p>
      <label className="host-csv-file">Fichier CSV<input type="file" accept=".csv,text/csv" onChange={(event) => readImportFile(event.target.files?.[0])} /></label>
      {importError && <div className="alert error">{importError}</div>}
      {importRows.length > 0 && <><p className="host-import-note">Aperçu : {importRows.length} hôte(s). Valeurs facultatives : <code>security_level</code>, <code>groups</code> (séparés par <code>;</code>), <code>ansible_user</code>, <code>ansible_port</code>.</p>
        <div className="table-wrap"><table><thead><tr><th>Nom</th><th>IP</th><th>Environnement</th><th>Utilisateur</th><th>Empreinte vérifiée</th></tr></thead><tbody>
          {importRows.slice(0, 8).map((host) => <tr key={`${host.environment}-${host.name}`}><td>{host.name}</td><td>{host.ip}</td><td>{host.environment}</td><td>{host.ansible_user}</td><td className="mono">{host.ssh_fingerprint}</td></tr>)}
        </tbody></table></div>
        {importRows.length > 8 && <p className="host-import-note">Les {importRows.length - 8} autres hôtes seront également importés.</p>}
      </>}
      {importHosts.data && <div className={importHosts.data.failed.length ? 'alert error' : 'alert success'}>
        {importHosts.data.imported.length} hôte(s) importé(s), {importHosts.data.failed.length} échec(s).
        {importHosts.data.failed.map((item) => <div key={`${item.row}-${item.name}`}>Ligne {item.row} ({item.name}) : {item.detail}</div>)}
      </div>}
      {importHosts.isError && <div className="alert error">{importHosts.error instanceof Error ? importHosts.error.message : 'Import impossible.'}</div>}
      <div className="form-actions"><button className="primary" disabled={!importRows.length || importHosts.isPending} onClick={() => importHosts.mutate()}>{importHosts.isPending ? 'Import en cours…' : `Importer ${importRows.length || ''} hôte(s)`}</button></div>
    </article>}
    {showForm && <article className="panel form-panel"><div className="panel-heading"><h2>Nouvel hôte</h2></div><div className="form-grid">
      <label>Nom<input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></label>
      <label>Adresse IP<input value={form.ip} onChange={(event) => setForm({ ...form, ip: event.target.value })} /></label>
      <label>Environnement<select value={form.environment} onChange={(event) => setForm({ ...form, environment: event.target.value })}><option value="production">production</option><option value="staging">staging</option><option value="development">development</option></select></label>
      <label>Niveau<select value={form.security_level} onChange={(event) => setForm({ ...form, security_level: event.target.value })}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label>
      <label>Groupes<input value={form.groups} onChange={(event) => setForm({ ...form, groups: event.target.value })} placeholder="linux,servers" /></label>
      <label>Utilisateur SSH<input value={form.ansible_user} onChange={(event) => setForm({ ...form, ansible_user: event.target.value })} /></label>
      <label>Port SSH<input type="number" min="1" max="65535" value={form.ansible_port} onChange={(event) => setForm({ ...form, ansible_port: Number(event.target.value) })} /></label>
      <label className="fingerprint-field">Empreinte SSH vérifiée (SHA256)<input value={form.ssh_fingerprint} onChange={(event) => setForm({ ...form, ssh_fingerprint: event.target.value })} placeholder="SHA256:…" /><small>Comparez-la à une source de confiance ; vide = aucune connexion SSH avant approbation.</small></label>
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
  if (host.isLoading || posture.isLoading) return <div className="loading">Chargement de la posture…</div>
  if (host.isError || posture.isError) return <div className="alert error">Impossible de charger cet hôte.</div>
  const data = posture.data
  const fingerprintNeedsApproval = testSSH.data?.ssh_status === 'fingerprint_pending' || testSSH.data?.ssh_status === 'fingerprint_changed'
  return <>
    <div className="page-heading"><div><p className="eyebrow">Posture unifiée</p><h1>{host.data?.name}</h1></div><div className="actions"><label className="check-control"><input type="checkbox" checked={checkMode} onChange={(event) => setCheckMode(event.target.checked)} /> Check mode</label><select value={playbook} onChange={(event) => setPlaybook(event.target.value)}>{(playbooks.data ?? []).filter((item) => item.is_allowlisted).map((item) => <option key={item.filename} value={item.filename}>{item.filename}</option>)}</select><button className="primary" disabled={run.isPending || !host.data} onClick={() => run.mutate()}>{checkMode ? 'Prévisualiser' : 'Exécuter'}</button><button className="secondary" disabled={testSSH.isPending} onClick={() => testSSH.mutate()}>{testSSH.isPending ? 'Test en cours…' : 'Tester SSH'}</button><button className="danger" onClick={() => { if (window.confirm(`Supprimer ${host.data?.name} ?`)) remove.mutate() }}>Supprimer</button></div></div>
    <section className="detail-grid">
      <article className="panel detail-card"><p className="eyebrow">Identité</p><dl><dt>IP</dt><dd>{host.data?.ip}</dd><dt>Environnement</dt><dd>{host.data?.environment}</dd><dt>Sécurité</dt><dd>{host.data?.security_level}</dd><dt>Agent Wazuh</dt><dd>{data?.agent ? `${data.agent.name} (${data.agent.status})` : 'Non associé'}</dd></dl></article>
      <article className="panel detail-card"><p className="eyebrow">Connexion Ansible</p><dl><dt>Utilisateur</dt><dd>{host.data?.ansible_user}</dd><dt>Port</dt><dd>{host.data?.ansible_port}</dd><dt>Statut SSH</dt><dd><span className={`status ${host.data?.ssh_status}`}>{host.data?.ssh_status}</span></dd><dt>Empreinte</dt><dd className="mono">{host.data?.ssh_fingerprint ?? 'Non vérifiée'}</dd></dl>{testSSH.data && <small>{testSSH.data.message}</small>}{host.data?.ssh_error && <small className="alert error">{host.data.ssh_error}</small>}</article>
      <article className="panel detail-card"><p className="eyebrow">Conformité</p><strong className="detail-score">{data?.compliance?.score ?? '—'}%</strong><small>{data?.compliance ? `${data.compliance.profile} · ${data.compliance.status}` : 'Aucun scan disponible'}</small></article>
      <article className="panel detail-card"><p className="eyebrow">Patching</p><strong>{data?.patch_findings.length ?? 0}</strong><small>correctifs suivis</small></article>
      <article className="panel detail-card"><p className="eyebrow">Live patch</p><strong>{data?.livepatch?.livepatch_state ?? 'unknown'}</strong><small>{data?.livepatch?.kernel ?? 'Kernel inconnu'}</small></article>
    </section>
    {fingerprintNeedsApproval && <article className="panel fingerprint-approval">
      <div className="panel-heading"><div><p className="eyebrow">Vérification hors bande requise</p><h2>Empreinte SSH non approuvée</h2></div></div>
      <p className="host-import-note">Aucune connexion SSH n’a été tentée. Comparez l’empreinte découverte ci-dessous à une source de confiance (console ou inventaire officiel), puis saisissez la valeur vérifiée. Ne l’approuvez pas uniquement parce qu’elle a été détectée par le réseau.</p>
      <p className="mono fingerprint-candidate">{testSSH.data?.fingerprint}</p>
      <label className="fingerprint-confirm">Empreinte vérifiée hors bande<input value={expectedFingerprint} onChange={(event) => setExpectedFingerprint(event.target.value.trim())} placeholder="SHA256:…" /></label>
      {acceptFingerprint.isError && <div className="alert error">{acceptFingerprint.error instanceof Error ? acceptFingerprint.error.message : 'Approbation impossible.'}</div>}
      <div className="form-actions"><button className="primary" disabled={acceptFingerprint.isPending || !sshFingerprint.test(expectedFingerprint)} onClick={() => { if (window.confirm('Avez-vous comparé cette empreinte avec une source de confiance ?')) acceptFingerprint.mutate() }}>{acceptFingerprint.isPending ? 'Vérification…' : 'Enregistrer l’empreinte vérifiée'}</button></div>
    </article>}
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

function PlaybookEditor({ creating, selected, playbook, onSaved }: {
  creating: boolean
  selected: string
  playbook?: PlaybookDetail
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
  const validationResult = validation
  return <article className="panel form-panel playbook-editor">
    <div className="panel-heading"><div><p className="eyebrow">{creating ? 'Nouveau playbook' : 'Édition'}</p><h2>{creating ? 'Créer un playbook' : filename}</h2></div></div>
    <div className="form-grid playbook-meta">
      <label>Nom du fichier{creating ? <input value={filename} onChange={(event) => { setFilename(event.target.value); resetFeedback() }} placeholder="mon-playbook.yml" /> : <input value={filename} readOnly />}</label>
      <label className="description-field">Description<input value={description} onChange={(event) => { setDescription(event.target.value); resetFeedback() }} /></label>
    </div>
    <label className="playbook-content">Contenu YAML<textarea spellCheck={false} value={content} onChange={(event) => { setContent(event.target.value); resetFeedback() }} /></label>
    <p className="validation-note">La vérification contrôle la syntaxe YAML et que la racine est une liste de plays. Elle ne lance pas Ansible et ne vérifie pas les plugins, rôles ou variables.</p>
    {validationResult && <div className={`alert ${validationResult.valid ? 'success' : 'error'}`} role="status">{validationResult.detail}</div>}
    {validate.isError && <div className="alert error">{validate.error instanceof Error ? validate.error.message : 'Validation impossible'}</div>}
    {save.isError && <div className="alert error">{save.error instanceof Error ? save.error.message : 'Enregistrement impossible'}</div>}
    <div className="form-actions playbook-actions">
      <button className="secondary" disabled={validate.isPending || !content.trim()} onClick={() => validate.mutate()}>{validate.isPending ? 'Vérification…' : 'Vérifier YAML'}</button>
      <button className="primary" disabled={save.isPending || !filenameValid} onClick={() => save.mutate()}>{save.isPending ? 'Enregistrement…' : 'Enregistrer'}</button>
    </div>
  </article>
}

function Playbooks() {
  const list = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks })
  const [selected, setSelected] = useState('')
  const [creating, setCreating] = useState(false)
  const detail = useQuery({
    queryKey: ['playbook', selected],
    queryFn: () => api.playbook(selected),
    enabled: Boolean(selected) && !creating,
  })

  const startNew = () => {
    setSelected('')
    setCreating(true)
  }
  const selectPlaybook = (name: string) => {
    setCreating(false)
    setSelected(name)
  }

  if (list.isLoading) return <div className="loading">Chargement des playbooks…</div>
  if (list.isError) return <div className="alert error">Impossible de charger les playbooks.</div>
  return <>
    <div className="page-heading"><div><p className="eyebrow">Automatisation</p><h1>Playbooks</h1></div><button className="primary" onClick={startNew}>Créer un playbook</button></div>
    <article className="panel playbook-library">
      <div className="panel-heading"><div><p className="eyebrow">Bibliothèque</p><h2>Sélectionner un playbook</h2></div></div>
      <div className="playbook-list">
        {!list.data?.length && <span className="empty">Aucun playbook enregistré</span>}
        {(list.data ?? []).map((item) => <button key={item.filename} className={`playbook-choice ${selected === item.filename && !creating ? 'selected' : ''}`} onClick={() => selectPlaybook(item.filename)}>
          <strong>{item.filename}</strong><small>{item.description || 'Aucune description'}</small>
        </button>)}
      </div>
    </article>
    {creating && <PlaybookEditor key="new-playbook" creating selected="" onSaved={(saved) => { setCreating(false); setSelected(saved.filename) }} />}
    {!creating && selected && detail.isLoading && <div className="loading">Chargement du playbook…</div>}
    {!creating && selected && detail.isError && <div className="alert error">Impossible de charger ce playbook.</div>}
    {!creating && detail.data && <PlaybookEditor key={selected} creating={false} selected={selected} playbook={detail.data} onSaved={(saved) => { setSelected(saved.filename) }} />}
  </>
}

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
  if (isLoading) return <div className="loading">Chargement des intégrations…</div>
  if (isError || !data) return <div className="alert error">Impossible de charger les paramètres.</div>
  const rows = [
    { name: 'Wazuh', key: 'wazuh' as const, state: data.wazuh, mutation: testWazuh },
    { name: 'Uyuni', key: 'uyuni' as const, state: data.uyuni, mutation: testUyuni },
    { name: 'Ansible', key: 'ansible' as const, state: data.ansible, mutation: testAnsible },
  ]
  const statusText = (value: boolean | null) => value === null ? 'Non testé' : value ? 'Oui' : 'Non'
  return <>
    <div className="page-heading"><div><p className="eyebrow">Configuration</p><h1>Paramètres</h1></div></div>
    <article className="panel"><div className="panel-heading"><div><p className="eyebrow">Services de la pile</p><h2>État des intégrations</h2></div><button className="secondary" onClick={() => void client.invalidateQueries({ queryKey: ['integrations'] })}>Actualiser</button></div>
      <div className="table-wrap"><table><thead><tr><th>Composant</th><th>Configuré</th><th>Disponible localement</th><th>Joignable / test</th><th>Action</th></tr></thead><tbody>
        {rows.map(({ name, key, state, mutation }) => <tr key={key}>
          <td><strong>{name}</strong></td><td>{statusText(state.configured)}</td>
          <td>{key === 'ansible' ? statusText(state.available) : '—'}</td>
          <td>{state.reachable === null ? (state.configured ? 'À tester' : 'Non configuré') : statusText(state.reachable)}</td>
          <td><button className="link-button" disabled={mutation.isPending || (key !== 'ansible' && !state.configured)} onClick={() => mutation.mutate()}>{mutation.isPending ? 'Test…' : key === 'ansible' ? 'Vérifier Ansible' : 'Tester'}</button></td>
        </tr>)}
      </tbody></table></div>
    </article>
    <p className="integration-help">Ansible est vérifié localement dans l’environnement de l’API (version uniquement, aucun playbook n’est exécuté). Wazuh et Uyuni sont testés via leurs API configurées.</p>
    {rows.map(({ name, key, state, mutation }) => (state.detail || mutation.isError) && <div key={`${key}-result`} className={`alert ${state.reachable ? 'success' : 'error'}`}>{name} : {mutation.isError && mutation.error instanceof Error ? mutation.error.message : state.detail}</div>)}
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
        <Route path="/playbooks" element={<Playbooks />} />
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
