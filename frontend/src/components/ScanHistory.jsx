import React, { useEffect, useState } from 'react'
import { GradeCircle, StatusDot, TermLabel, Button } from './ui'
import { api } from '../api'

export default function ScanHistory({ onSelectScan, onNewScan }) {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const data = await api.listScans()
        setScans(data)
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }
    load()
    const interval = setInterval(load, 5000)
    return () => clearInterval(interval)
  }, [])

  const handleDelete = async (e, id) => {
    e.stopPropagation()
    await api.deleteScan(id)
    setScans(s => s.filter(x => x.scan_id !== id))
  }

  if (loading) return (
    <div style={{ padding: 40, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>Loading scan history...</div>
  )

  if (scans.length === 0) return (
    <div style={{ textAlign: 'center', padding: '60px 20px' }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 48, color: 'var(--border)', marginBottom: 16 }}>⚡</div>
      <h3 style={{ fontFamily: 'var(--font-display)', fontSize: 18, color: 'var(--text-secondary)', marginBottom: 8 }}>No scans yet</h3>
      <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 24 }}>Run your first security scan to get started</p>
      <Button onClick={onNewScan}>+ RUN FIRST SCAN</Button>
    </div>
  )

  return (
    <div style={{ maxWidth: 900, width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <TermLabel>Scan History</TermLabel>
        </div>
        <Button onClick={onNewScan}>+ NEW SCAN</Button>
      </div>
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {scans.map(scan => (
          <div
            key={scan.scan_id}
            onClick={() => onSelectScan(scan.scan_id, scan.status)}
            style={{
              background: 'var(--bg-surface)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius)', padding: '16px 20px',
              cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: 16,
              transition: 'border-color 0.15s, background 0.15s',
              flexWrap: 'wrap',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--border-bright)'
              e.currentTarget.style.background = 'var(--bg-elevated)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = 'var(--border)'
              e.currentTarget.style.background = 'var(--bg-surface)'
            }}
          >
            {scan.status === 'completed'
              ? <GradeCircle grade={scan.letter_grade} score={scan.overall_score} size={52} />
              : (
                <div style={{ width: 52, height: 52, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <StatusDot status={scan.status} />
                </div>
              )
            }
            
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600, fontSize: 14, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {scan.scan_name}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>
                {new Date(scan.started_at).toLocaleString()} &nbsp;·&nbsp; {scan.scan_id.slice(0, 8).toUpperCase()}
              </div>
            </div>
            
            {scan.status === 'completed' && (
              <div style={{ display: 'flex', gap: 16, fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0 }}>
                <span style={{ color: 'var(--red)' }}>{scan.critical_count} CRIT</span>
                <span style={{ color: 'var(--orange)' }}>{scan.high_count} HIGH</span>
                <span style={{ color: 'var(--green)' }}>{scan.total_attacks - scan.exploited_count} NOT FLAGGED</span>
              </div>
            )}
            
            {scan.status === 'running' && (
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--cyan)' }}>SCANNING...</span>
            )}
            
            {scan.status === 'failed' && (
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red)' }}>FAILED</span>
            )}

            {scan.status === 'interrupted' && (
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--orange)' }}>INTERRUPTED</span>
            )}
            
            <button
              onClick={(e) => handleDelete(e, scan.scan_id)}
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                color: 'var(--text-dim)', fontSize: 14, padding: '4px 8px',
                borderRadius: 4, transition: 'color 0.15s',
              }}
              onMouseEnter={e => e.target.style.color = 'var(--red)'}
              onMouseLeave={e => e.target.style.color = 'var(--text-dim)'}
              title="Delete scan"
            >
              ✕
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
