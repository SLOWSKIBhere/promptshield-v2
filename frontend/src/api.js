const BASE = import.meta.env.VITE_API_URL || '/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  health: () => request('/health'),
  
  listScans: () => request('/scans'),
  
  createScan: (target) => request('/scans', {
    method: 'POST',
    body: JSON.stringify(target),
  }),
  
  getScan: (id) => request(`/scans/${id}`),
  
  getProgress: (id, options = {}) => request(`/scans/${id}/progress`, options),
  
  getReportUrl: (id) => `${BASE}/scans/${id}/report`,
  
  deleteScan: (id) => request(`/scans/${id}`, { method: 'DELETE' }),
}
