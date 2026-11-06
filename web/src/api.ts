const API_PREFIX = '/api/v1'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_PREFIX}${path}`, { credentials: 'include', ...init, headers: { Accept: 'application/json', ...(init?.body ? { 'Content-Type': 'application/json' } : {}) } })
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

export interface Host { id: number; name: string; ip: string; environment: string; security_level: string; status: string }
export interface Deployment { id: string; playbook_name: string; environment_name: string; status: string; targets: { host_name: string; status: string }[] }

export const api = {
  login: (username: string, password: string) => mutating('/auth/login', 'POST', { username, password }),
  logout: () => mutating('/auth/logout', 'POST'),
  me: () => request<{ username: string }>('/auth/me'),
  kpis: () => request<any>('/kpis/overview'),
  kpiHistory: (metric = 'compliance_score') =>
    request<Array<{ value: number | null; status: string; captured_at: string }>>(
      `/kpis/history?metric=${encodeURIComponent(metric)}&days=30`,
    ),
  hosts: () => request<Host[]>('/hosts'),
  deployments: () => request<Deployment[]>('/deployments'),
  cancelDeployment: (id: string) => mutating(`/deployments/${id}/cancel`, 'POST'),
  retryDeployment: (id: string) => mutating(`/deployments/${id}/retry`, 'POST'),
  complianceScans: () => request<unknown[]>('/compliance/scans'),
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
  patchFindings: () => request<unknown[]>('/patching/findings'),
  alerts: () => request<unknown[]>('/alerts'),
  audit: () => request<unknown[]>('/audit?limit=100'),
  integrations: async () => {
    const status = await request<{ wazuh: { configured: boolean }; uyuni: { configured: boolean } }>('/integrations/status')
    return [
      { integration: 'Wazuh', configured: status.wazuh.configured, reachable: 'Inconnue' },
      { integration: 'Uyuni', configured: status.uyuni.configured, reachable: 'Inconnue' },
    ]
  },
}
