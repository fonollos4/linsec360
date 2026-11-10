const API_PREFIX = '/api/v1'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  headers.set('Accept', 'application/json')
  if (init?.body) headers.set('Content-Type', 'application/json')
  const response = await fetch(`${API_PREFIX}${path}`, {
    credentials: 'include',
    ...init,
    headers,
  })
  if (!response.ok) {
    let message = response.statusText
    try { const payload = await response.json() as { error?: { message?: string }; detail?: string }; message = payload.error?.message ?? payload.detail ?? message } catch {}
    throw new Error(message)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

async function mutating<T>(path: string, method: string, body?: object): Promise<T> {
  const match = document.cookie.match(/(?:^|; )linsec_csrf=([^;]*)/)
  return request<T>(path, { method, headers: { 'X-CSRF-Token': match ? decodeURIComponent(match[1]) : '' }, body: body ? JSON.stringify(body) : undefined })
}

export interface Host {
  id: number
  name: string
  ip: string
  environment: string
  security_level: string
  status: string
  ansible_user: string
  ansible_port: number
  ansible_password_configured: boolean
  groups: string[]
  ssh_status: string
  ssh_fingerprint: string | null
  ssh_error: string | null
  last_ssh_test_at: string | null
}
export interface HostUpdateInput {
  ip?: string
  security_level?: string
  groups?: string[]
  status?: string
  ansible_user?: string
  ansible_port?: number
}
export interface HostImportItem {
  name: string
  ip: string
  environment: string
  security_level: string
  groups: string[]
  ansible_user: string
  ansible_port: number
  ssh_fingerprint: string
}
export interface HostEnrollmentInput {
  name: string
  ip: string
  environment: string
  security_level: string
  groups: string[]
  ansible_user: string
  ansible_port: number
  password: string
}
export interface HostImportResult {
  imported: Host[]
  failed: Array<{ row: number; name: string; detail: string }>
}
export interface Deployment {
  id: string
  environment: string
  playbook: string
  target_hosts: string[]
  status: string
  created_at: string
  started_at: string | null
  finished_at: string | null
  error_message: string | null
  log_url: string
}
export interface HostPosture {
  host_id: number
  host_name: string
  compliance: { id: string; profile: string; status: string; score: number | null; created_at: string } | null
  hardening: Array<{ id: number; category: string; control: string; status: string; checked_at: string }>
  patch_findings: Array<{ id: number; package: string; cve: string; severity: string; status: string; source: string; reboot_required: boolean }>
  livepatch: { livepatch_state: string; patch_available: boolean; exposure_days: number | null; kernel: string } | null
  agent: { id: string; name: string; status: string; last_keep_alive: string | null } | null
}
export interface Playbook { id: number; filename: string; description: string | null; checksum: string | null; is_allowlisted: boolean }
export interface PlaybookDetail extends Playbook { content: string; updated_at: string }
export interface PlaybookValidation { valid: boolean; detail: string }
export interface IntegrationState { configured: boolean; available: boolean | null; reachable: boolean | null; detail: string | null }
export interface StackComponentState {
  key: string
  name: string
  configured: boolean
  reachable: boolean | null
  endpoint: string | null
  addresses: string[]
  detail: string | null
}
export interface IntegrationStatus {
  wazuh: IntegrationState
  uyuni: IntegrationState
  ansible: IntegrationState
  stack: StackComponentState[]
}
export interface WazuhSyncResult {
  agents: { agents: number; hosts: number; matched: number; unmatched: number }
  alerts: { fetched: number; created: number; updated: number }
  vulnerabilities: { hosts: number; created: number; updated: number }
}
export interface UyuniSyncResult {
  systems: { systems: number; matched_hosts: number; created: number; updated: number }
  errata: { systems: number; created: number; updated: number }
}
export interface Alert {
  id: number
  alert_id: string
  timestamp: string
  rule_id: string | null
  rule_level: number | null
  severity: string
  agent_id: string | null
  agent_name: string | null
  description: string | null
  acknowledged: boolean
}
export interface PatchFinding {
  id: number
  host_name: string
  package: string
  current_version: string | null
  fixed_version: string | null
  cve: string
  errata: string
  severity: string
  source: string
  status: string
  reboot_required: boolean
}
export interface UyuniSystem {
  id: number
  host_id: number | null
  host_name: string
  uyuni_system_id: number
  status: string
  channels: string[]
  last_sync: string | null
}
export interface ComplianceScan {
  id: string
  host_id: number | null
  host_name: string
  profile: string
  status: string
  score: number | null
  started_at: string | null
  finished_at: string | null
  created_at: string
}
export interface AuditRecord {
  id: number
  action: string
  target_type: string
  target_id: string | null
  actor_username: string | null
  created_at: string
}

export interface KpiItem {
  value: number | null
  status: 'ok' | 'unknown' | 'stale'
  source: string
}
export interface KpiOverview {
  generated_at: string
  hosts_total: KpiItem
  hosts_secured: KpiItem
  hosts_deploying: KpiItem
  active_deployments: KpiItem
  deployment_success_rate: KpiItem
  open_vulnerabilities: KpiItem
  compliance_score: KpiItem
  agent_coverage: KpiItem
  disconnected_agents: KpiItem
  open_critical_vulnerabilities: KpiItem
  open_high_vulnerabilities: KpiItem
  patch_coverage: KpiItem
  reboot_required: KpiItem
  kernel_exposure_days: KpiItem
  hardening_drift: KpiItem
  selinux_non_compliant: KpiItem
  alerts_by_severity: Record<string, number> | null
}
export interface AlertSummary {
  by_severity: Record<string, number>
  unacknowledged: Record<string, number>
  mean_time_to_detect_hours: number | null
  mean_time_to_respond_hours: number | null
}

export interface SSHPublicKey {
  public_key: string
  private_key_path: string
}

export interface SSHTest {
  reachable: boolean
  ssh_status: string
  fingerprint: string | null
  fingerprint_changed: boolean
  message: string
}
export interface SSHFingerprint { fingerprint: string }

export const api = {
  login: (username: string, password: string) => mutating('/auth/login', 'POST', { username, password }),
  logout: () => mutating('/auth/logout', 'POST'),
  me: () => request<{ id: number; username: string; role: string }>('/auth/me'),
  kpis: () => request<KpiOverview>('/kpis/overview'),
  kpiHistory: (metric = 'compliance_score') =>
    request<Array<{ value: number | null; status: string; captured_at: string }>>(
      `/kpis/history?metric=${encodeURIComponent(metric)}&days=30`,
    ),
  hosts: () => request<Host[]>('/hosts'),
  host: (id: number) => request<Host>(`/hosts/${id}`),
  hostPosture: (id: number) => request<HostPosture>(`/hosts/${id}/posture`),
  ansiblePublicKey: () => request<SSHPublicKey>('/hosts/ssh/public-key'),
  scanHostFingerprint: (body: { ip: string; ansible_port: number }) =>
    mutating<SSHFingerprint>('/hosts/ssh/fingerprint', 'POST', body),
  enrollHost: (body: HostEnrollmentInput & { verified_fingerprint: string }) =>
    mutating<Host>('/hosts/enroll', 'POST', body),
  enrollExistingHostKey: (id: number, password: string) =>
    mutating<Host>(`/hosts/${id}/ssh/enroll-key`, 'POST', { password }),
  setHostAnsiblePassword: (id: number, password: string) =>
    mutating<Host>(`/hosts/${id}/ansible-credentials`, 'PUT', { password }),
  clearHostAnsiblePassword: (id: number) =>
    mutating<Host>(`/hosts/${id}/ansible-credentials`, 'DELETE'),
  testHostSSH: (id: number) => mutating<SSHTest>(`/hosts/${id}/ssh/test`, 'POST'),
  acceptHostSSHFingerprint: (id: number, fingerprint: string) =>
    mutating<SSHTest>(`/hosts/${id}/ssh/accept-fingerprint`, 'POST', { fingerprint }),
  createHost: (body: { name: string; ip: string; environment: string; security_level: string; groups: string[]; ansible_user?: string; ansible_port?: number; ssh_fingerprint?: string }) =>
    mutating<Host>('/hosts', 'POST', body),
  importHosts: (hosts: HostImportItem[]) =>
    mutating<HostImportResult>('/hosts/import', 'POST', { hosts }),
  updateHost: (id: number, body: HostUpdateInput) =>
    mutating<Host>(`/hosts/${id}`, 'PATCH', body),
  deleteHost: (id: number) => mutating<{ message: string }>(`/hosts/${id}`, 'DELETE'),
  playbooks: () => request<Playbook[]>('/playbooks'),
  playbook: (filename: string) => request<PlaybookDetail>(`/playbooks/${encodeURIComponent(filename)}`),
  validatePlaybook: (content: string) => mutating<PlaybookValidation>('/playbooks/validate', 'POST', { content }),
  createPlaybook: (body: { filename: string; description: string; content: string }) =>
    mutating<PlaybookDetail>('/playbooks', 'POST', body),
  updatePlaybook: (filename: string, body: { description: string; content: string }) =>
    mutating<PlaybookDetail>(`/playbooks/${encodeURIComponent(filename)}`, 'PUT', body),
  deletePlaybook: (filename: string) =>
    mutating<{ message: string }>(`/playbooks/${encodeURIComponent(filename)}`, 'DELETE'),
  deployments: () => request<Deployment[]>('/deployments'),
  deployment: (id: string) => request<Deployment>(`/deployments/${id}`),
  deploymentEvents: (id: string) => request<Array<{ event: string; level: string; message: string; created_at: string }>>(`/deployments/${id}/events`),
  deploymentLog: async (id: string) => {
    const response = await fetch(`${API_PREFIX}/deployments/${id}/log`, { credentials: 'include' })
    if (!response.ok) throw new Error('Impossible de lire les logs')
    return response.text()
  },
  createDeployment: (body: { environment: string; playbook: string; hosts: string[]; group?: string; check_mode?: boolean; extra_vars?: Record<string, string> }) =>
    mutating<Deployment>('/deployments', 'POST', body),
  cancelDeployment: (id: string) => mutating(`/deployments/${id}/cancel`, 'POST'),
  retryDeployment: (id: string) => mutating(`/deployments/${id}/retry`, 'POST'),
  complianceScans: () => request<ComplianceScan[]>('/compliance/scans'),
  complianceProfiles: () => request<string[]>('/compliance/profiles'),
  complianceSummary: () => request<{ hosts_scanned: number; average_score: number | null; worst_hosts: Array<{ host: string; score: number }> }>('/compliance/summary'),
  exportCompliance: async (format: 'json' | 'csv') => {
    const response = await fetch(`${API_PREFIX}/compliance/scans/export?format=${format}`, { credentials: 'include' })
    if (!response.ok) throw new Error('Export impossible')
    const blob = await response.blob()
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `openscap-scans.${format}`
    link.click()
    URL.revokeObjectURL(url)
  },
  patchFindings: () => request<PatchFinding[]>('/patching/findings'),
  patchSummary: () => request<Record<string, unknown>>('/patching/summary'),
  syncWazuhPatches: () => mutating<Record<string, unknown>>('/patching/wazuh/sync', 'POST'),
  syncUyuni: () => mutating<UyuniSyncResult>('/patching/uyuni/sync', 'POST'),
  uyuniSystems: () => request<UyuniSystem[]>('/patching/uyuni'),
  resolvePatch: (id: number) => mutating<PatchFinding>(`/patching/findings/${id}/resolve`, 'POST'),
  alerts: () => request<Alert[]>('/alerts'),
  alertSummary: () => request<AlertSummary>('/alerts/summary'),
  syncWazuhAlerts: () => mutating<Record<string, unknown>>('/alerts/sync', 'POST'),
  syncAllWazuh: () => mutating<WazuhSyncResult>('/integrations/wazuh/sync', 'POST'),
  acknowledgeAlert: (id: number) => mutating<Alert>(`/alerts/${id}/ack`, 'POST'),
  activeResponse: (id: number, action: 'firewall-drop' | 'disable-account') =>
    mutating<Record<string, unknown>>(`/alerts/${id}/active-response`, 'POST', { action }),
  audit: () => request<AuditRecord[]>('/audit?limit=100'),
  integrations: () => request<IntegrationStatus>('/integrations/status'),
  testIntegration: (name: 'wazuh' | 'uyuni' | 'ansible') =>
    mutating<IntegrationState>(`/integrations/${name}/test`, 'POST'),
}
