import React, { useState, useEffect } from 'react'
import { GradeCircle, SeverityBadge, StatCard, TermLabel, Button, CodeBlock, StatusDot } from './ui'
import { api } from '../api'

export const EVALUATION_DISCLAIMER = (
  'Automated evaluation signal only. The score and grade apply to this configured corpus and judge; ' +
  'they are not proof or certification that the target is secure.'
)

const CATEGORY_LABELS = {
  prompt_injection: 'Prompt Injection',
  data_extraction: 'Data Extraction',
  jailbreak: 'Jailbreak',
  role_confusion: 'Role Confusion',
  multi_turn: 'Conversation Claims',
}

export default function ScanResults({ scanId, onNewScan }) {
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all') // 'all' | 'exploited' | category
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    const load = async () => {
      try {
        const data = await api.getScan(scanId)
        setScan(data)
      } catch (e) {
        setError(e.message)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [scanId])

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 40, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
      Loading results...
    </div>
  )

  if (error || !scan) return (
    <div style={{ color: 'var(--red)', fontFamily: 'var(--font-mono)', padding: 40 }}>
      Failed to load scan: {error}
    </div>
  )

  const exploited = scan.findings.filter(f => f.is_exploited)
  const criticalCount = exploited.filter(f => f.severity === 'critical').length
  const highCount = exploited.filter(f => f.severity === 'high').length
  const mediumCount = exploited.filter(f => f.severity === 'medium').length
  const notFlaggedCount = scan.findings.length - exploited.length

  const filtered = scan.findings.filter(f => {
    if (filter === 'all') return true
    if (filter === 'exploited') return f.is_exploited
    return f.category === filter
  })

  return (
    <div style={{ width: '100%', maxWidth: 900, animation: 'fadeIn 0.3s ease' }}>
      {/* Top Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24, gap: 16, flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--cyan)', letterSpacing: '0.2em', marginBottom: 6 }}>
            // SCAN REPORT
          </div>
          <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 700 }}>{scan.scan_name}</h2>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 6 }}>
            <StatusDot status={scan.status} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
              {scan.status.toUpperCase()} &nbsp;·&nbsp; {scan.scan_id.slice(0, 8).toUpperCase()}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <Button variant="ghost" onClick={() => window.open(api.getReportUrl(scanId), '_blank')}>
            📄 DOWNLOAD REPORT
          </Button>
          <Button onClick={onNewScan}>
            + NEW SCAN
          </Button>
        </div>
      </div>

      {/* Scorecard */}
      <div style={{
        background: 'var(--bg-surface)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)', padding: '24px 28px', marginBottom: 24,
        display: 'flex', gap: 28, alignItems: 'center', flexWrap: 'wrap',
      }}>
        <GradeCircle grade={scan.letter_grade} score={scan.overall_score} size={100} />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, flex: 1, minWidth: 300 }}>
          <StatCard label="Critical" value={criticalCount} color="var(--red)" />
          <StatCard label="High" value={highCount} color="var(--orange)" />
          <StatCard label="Medium" value={mediumCount} color="var(--yellow)" />
          <StatCard label="Not flagged" value={notFlaggedCount} color="var(--green)" />
        </div>
      </div>

      {/* Summary */}
      {scan.summary && (
        <div style={{
          background: 'var(--bg-surface)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius)', padding: '16px 20px', marginBottom: 24,
          fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6,
        }}>
          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)', fontSize: 10, marginRight: 10 }}>›</span>
          {scan.summary}
        </div>
      )}

      <div style={{
        background: 'var(--bg-surface)', border: '1px solid var(--border)',
        borderRadius: 'var(--radius)', padding: '12px 16px', marginBottom: 24,
        fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.6,
      }}>
        {EVALUATION_DISCLAIMER}
      </div>

      {/* Findings */}
      <div style={{ display: 'flex', gap: 20 }}>
        {/* Filter sidebar */}
        <div style={{ width: 180, flexShrink: 0 }}>
          <TermLabel>Filter</TermLabel>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {[
              { key: 'all', label: 'All Findings', count: scan.findings.length },
              { key: 'exploited', label: 'Flagged Only', count: exploited.length },
              null,
              ...Object.entries(CATEGORY_LABELS).map(([k, v]) => ({
                key: k, label: v,
                count: scan.findings.filter(f => f.category === k && f.is_exploited).length,
              })),
            ].map((item, i) => {
              if (!item) return <div key={i} style={{ borderTop: '1px solid var(--border)', margin: '4px 0' }} />
              return (
                <button key={item.key} onClick={() => setFilter(item.key)} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '7px 10px', borderRadius: 'var(--radius)',
                  background: filter === item.key ? 'var(--cyan-glow)' : 'transparent',
                  border: `1px solid ${filter === item.key ? 'var(--cyan)' : 'transparent'}`,
                  color: filter === item.key ? 'var(--cyan)' : 'var(--text-muted)',
                  fontFamily: 'var(--font-mono)', fontSize: 11, cursor: 'pointer',
                  transition: 'all 0.15s', textAlign: 'left', width: '100%',
                }}>
                  <span>{item.label}</span>
                  <span style={{
                    background: 'var(--bg-void)', padding: '1px 6px',
                    borderRadius: 10, fontSize: 9,
                    color: item.count > 0 ? 'var(--red)' : 'var(--text-dim)',
                  }}>
                    {item.count}
                  </span>
                </button>
              )
            })}
          </div>
        </div>

        {/* Findings list */}
        <div style={{ flex: 1 }}>
          <TermLabel>{filtered.length} finding{filtered.length !== 1 ? 's' : ''}</TermLabel>
          {filtered.length === 0 && (
            <div style={{
              background: 'var(--green-glow)', border: '1px solid var(--green-dim)',
              borderRadius: 'var(--radius)', padding: '20px 24px',
              fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--green)',
            }}>
              No cases were flagged for this filter.
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {filtered.map((finding) => (
              <FindingRow
                key={finding.attack_id}
                finding={finding}
                isOpen={selected === finding.attack_id}
                onToggle={() => setSelected(s => s === finding.attack_id ? null : finding.attack_id)}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function FindingRow({ finding, isOpen, onToggle }) {
  const sev = finding.severity?.value || finding.severity
  const borderColor = finding.is_exploited
    ? sev === 'critical' ? 'var(--red)' : sev === 'high' ? 'var(--orange)' : 'var(--yellow)'
    : 'var(--border)'

  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: `1px solid ${isOpen ? borderColor : 'var(--border)'}`,
      borderLeft: `3px solid ${finding.is_exploited ? borderColor : 'var(--border)'}`,
      borderRadius: 'var(--radius)', overflow: 'hidden', transition: 'border-color 0.15s',
    }}>
      {/* Row header */}
      <button onClick={onToggle} style={{
        display: 'flex', alignItems: 'center', gap: 12,
        width: '100%', padding: '12px 16px', background: 'none',
        border: 'none', cursor: 'pointer', textAlign: 'left',
      }}>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 10,
          color: isOpen ? 'var(--cyan)' : 'var(--text-muted)',
          transition: 'transform 0.15s',
          display: 'inline-block',
          transform: isOpen ? 'rotate(90deg)' : 'none',
        }}>▶</span>
        
        {finding.is_exploited
          ? <SeverityBadge severity={sev} />
          : <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--green)', border: '1px solid var(--green-dim)', padding: '2px 8px', borderRadius: 4 }}>NOT FLAGGED</span>
        }
        
        <span style={{ flex: 1, fontFamily: 'var(--font-display)', fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
          {finding.attack_name}
        </span>
        
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', flexShrink: 0 }}>
          {CATEGORY_LABELS[finding.category] || finding.category}
        </span>
        
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', flexShrink: 0 }}>
          {finding.owasp_ref}
        </span>
      </button>

      {/* Expanded detail */}
      {isOpen && (
        <div style={{ padding: '0 16px 16px', borderTop: '1px solid var(--border)' }}>
          <div style={{ paddingTop: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
            
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <div style={{ background: 'var(--bg-void)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '6px 12px', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
                Confidence: <span style={{ color: 'var(--text-primary)' }}>{Math.round(finding.confidence * 100)}%</span>
              </div>
            </div>

            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 6 }}>Attack Payload</div>
              <CodeBlock maxHeight={100}>{finding.payload}</CodeBlock>
            </div>

            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 6 }}>Model Response</div>
              <CodeBlock maxHeight={120}>{finding.model_response}</CodeBlock>
            </div>

            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 6 }}>Judge Reasoning</div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6, fontStyle: 'italic' }}>{finding.judge_reasoning}</div>
            </div>

            {finding.is_exploited && (
              <div style={{
                background: 'rgba(0,255,136,0.06)', border: '1px solid rgba(0,255,136,0.2)',
                borderRadius: 'var(--radius)', padding: '12px 14px',
              }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--green)', letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 6 }}>🔧 Remediation</div>
                <div style={{ fontSize: 12, color: 'rgba(0,255,136,0.8)', lineHeight: 1.6 }}>{finding.remediation}</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
