import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const jsonResponse = (body) => ({
  ok: true,
  json: vi.fn().mockResolvedValue(body),
})

async function loadApi(apiUrl = '') {
  vi.stubEnv('VITE_API_URL', apiUrl)
  vi.resetModules()
  return (await import('./api.js')).api
}

describe('api', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
  })

  it.each([
    ['health', [], '/api/health'],
    ['listScans', [], '/api/scans'],
    ['getScan', ['scan-123'], '/api/scans/scan-123'],
    ['getProgress', ['scan-123'], '/api/scans/scan-123/progress'],
  ])('sends %s to the expected endpoint', async (method, args, url) => {
    const payload = { result: method }
    fetch.mockResolvedValueOnce(jsonResponse(payload))
    const api = await loadApi()

    await expect(api[method](...args)).resolves.toEqual(payload)
    expect(fetch).toHaveBeenCalledOnce()
    expect(fetch).toHaveBeenCalledWith(url, {
      headers: { 'Content-Type': 'application/json' },
    })
  })

  it('creates a scan with a JSON request body', async () => {
    const target = {
      provider: 'custom',
      endpoint: 'https://target.example/chat',
      categories: ['injection'],
    }
    const payload = { scan_id: 'scan-123', status: 'pending' }
    fetch.mockResolvedValueOnce(jsonResponse(payload))
    const api = await loadApi()

    await expect(api.createScan(target)).resolves.toEqual(payload)
    expect(fetch).toHaveBeenCalledWith('/api/scans', {
      headers: { 'Content-Type': 'application/json' },
      method: 'POST',
      body: JSON.stringify(target),
    })
  })

  it('deletes a scan with the DELETE method', async () => {
    const payload = { deleted: true }
    fetch.mockResolvedValueOnce(jsonResponse(payload))
    const api = await loadApi()

    await expect(api.deleteScan('scan-123')).resolves.toEqual(payload)
    expect(fetch).toHaveBeenCalledWith('/api/scans/scan-123', {
      headers: { 'Content-Type': 'application/json' },
      method: 'DELETE',
    })
  })

  it('constructs report URLs without making a request', async () => {
    const api = await loadApi()

    expect(api.getReportUrl('scan-123')).toBe('/api/scans/scan-123/report')
    expect(fetch).not.toHaveBeenCalled()
  })

  it('uses VITE_API_URL for requests and report URLs when configured', async () => {
    fetch.mockResolvedValueOnce(jsonResponse({ status: 'ok' }))
    const api = await loadApi('https://api.promptshield.example/v1')

    await api.health()

    expect(fetch).toHaveBeenCalledWith(
      'https://api.promptshield.example/v1/health',
      { headers: { 'Content-Type': 'application/json' } },
    )
    expect(api.getReportUrl('scan-456')).toBe(
      'https://api.promptshield.example/v1/scans/scan-456/report',
    )
  })

  it('throws the backend detail for an unsuccessful response', async () => {
    fetch.mockResolvedValueOnce({
      ok: false,
      status: 422,
      statusText: 'Unprocessable Content',
      json: vi.fn().mockResolvedValue({ detail: 'Unknown scan category' }),
    })
    const api = await loadApi()

    await expect(api.createScan({})).rejects.toThrow('Unknown scan category')
  })

  it('falls back to statusText when an error body is not JSON', async () => {
    fetch.mockResolvedValueOnce({
      ok: false,
      status: 502,
      statusText: 'Bad Gateway',
      json: vi.fn().mockRejectedValue(new SyntaxError('Invalid JSON')),
    })
    const api = await loadApi()

    await expect(api.health()).rejects.toThrow('Bad Gateway')
  })

  it('falls back to the HTTP status when no error detail is available', async () => {
    fetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: '',
      json: vi.fn().mockResolvedValue({}),
    })
    const api = await loadApi()

    await expect(api.listScans()).rejects.toThrow('HTTP 500')
  })
})
