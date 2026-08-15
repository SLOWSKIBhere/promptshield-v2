import React, { useState } from 'react'
import NewScanForm from './components/NewScanForm'
import ScanProgress from './components/ScanProgress'
import ScanResults from './components/ScanResults'
import ScanHistory from './components/ScanHistory'

// ─── Shield Logo ──────────────────────────────────────────────────────────
function ShieldLogo() {
  return (
    <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
      <path d="M14 2L4 6v8c0 5.5 4.3 10.7 10 12 5.7-1.3 10-6.5 10-12V6L14 2z"
        fill="rgba(0,229,255,0.12)" stroke="var(--cyan)" strokeWidth="1.5"/>
      <path d="M10 14l3 3 5-5" stroke="var(--cyan)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  )
}

// ─── Navigation ───────────────────────────────────────────────────────────
function Nav({ view, setView }) {
  const navItems = [
    { id: 'history', label: 'SCANS' },
    { id: 'new', label: 'NEW SCAN' },
    { id: 'docs', label: 'OWASP REF' },
  ]
  return (
    <nav style={{
      display: 'flex', alignItems: 'center', gap: 0,
      borderBottom: '1px solid var(--border)', padding: '0 32px',
      background: 'var(--bg-base)', height: 56, flexShrink: 0,
    }}>
      {/* Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginRight: 40 }}>
        <ShieldLogo />
        <div>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700,
            color: 'var(--text-primary)', letterSpacing: '0.05em',
          }}>
            Prompt<span style={{ color: 'var(--cyan)' }}>Shield</span>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 8, color: 'var(--text-muted)', letterSpacing: '0.15em' }}>
            LLM SECURITY SCANNER
          </div>
        </div>
      </div>

      {/* Nav links */}
      <div style={{ display: 'flex', gap: 4 }}>
        {navItems.map(item => (
          <button key={item.id} onClick={() => setView(item.id)} style={{
            padding: '0 16px', height: 56, background: 'none', border: 'none',
            borderBottom: `2px solid ${view === item.id ? 'var(--cyan)' : 'transparent'}`,
            color: view === item.id ? 'var(--cyan)' : 'var(--text-muted)',
            fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.1em',
            cursor: 'pointer', transition: 'color 0.15s, border-color 0.15s',
          }}>
            {item.label}
          </button>
        ))}
      </div>

      {/* Right side */}
      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--green)',
          display: 'flex', alignItems: 'center', gap: 6,
        }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--green)', display: 'inline-block' }} />
          SYSTEM ONLINE
        </div>
        <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/"
          target="_blank" rel="noreferrer"
          style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)', textDecoration: 'none' }}>
          OWASP LLM TOP 10 ↗
        </a>
      </div>
    </nav>
  )
}

// ─── OWASP Reference Panel ─────────────────────────────────────────────────
function OWASPRef() {
  const refs = [
    { id: 'LLM01:2025', name: 'Prompt Injection', desc: 'User inputs alter LLM behavior in unintended ways, potentially causing data exfiltration or unauthorized actions.', covered: true },
    { id: 'LLM02:2025', name: 'Sensitive Information Disclosure', desc: 'LLMs inadvertently reveal confidential data including PII, credentials, or proprietary information.', covered: false },
    { id: 'LLM03:2025', name: 'Supply Chain Vulnerabilities', desc: 'Third-party components, training datasets, or deployment infrastructure introduce risks.', covered: false },
    { id: 'LLM04:2025', name: 'Data and Model Poisoning', desc: 'Manipulation of training data to introduce vulnerabilities or backdoors into the model.', covered: false },
    { id: 'LLM05:2025', name: 'Insecure Output Handling', desc: 'LLM outputs not validated before passing to downstream components, enabling injection attacks.', covered: false },
    { id: 'LLM06:2025', name: 'Excessive Agency', desc: 'LLMs with overly broad permissions take unintended actions with real-world consequences.', covered: true },
    { id: 'LLM07:2025', name: 'System Prompt Leakage', desc: 'System prompt contents exposed to users, revealing business logic or security measures.', covered: true },
    { id: 'LLM08:2025', name: 'Vector and Embedding Weaknesses', desc: 'Exploitation of RAG pipelines via embedding manipulation or retrieval poisoning.', covered: false },
    { id: 'LLM09:2025', name: 'Misinformation', desc: 'LLMs generating plausible but factually incorrect content presented as authoritative.', covered: false },
    { id: 'LLM10:2025', name: 'Unbounded Consumption', desc: 'Resource exhaustion attacks causing denial of service or excessive API costs.', covered: false },
  ]

  return (
    <div style={{ maxWidth: 800, width: '100%', animation: 'fadeIn 0.3s ease' }}>
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--cyan)', letterSpacing: '0.2em', marginBottom: 8 }}>
          // REFERENCE
        </div>
        <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 700 }}>OWASP LLM Top 10 — 2025</h2>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 8, lineHeight: 1.5 }}>
          PromptShield currently covers the attack surface categories marked below. The attack library grows with every release.
        </p>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {refs.map(ref => (
          <div key={ref.id} style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderLeft: `3px solid ${ref.covered ? 'var(--cyan)' : 'var(--border)'}`,
            borderRadius: 'var(--radius)', padding: '14px 18px',
            opacity: ref.covered ? 1 : 0.6,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16 }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 4 }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: ref.covered ? 'var(--cyan)' : 'var(--text-dim)' }}>
                    {ref.id}
                  </span>
                  <strong style={{ fontSize: 13, color: 'var(--text-primary)' }}>{ref.name}</strong>
                </div>
                <p style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>{ref.desc}</p>
              </div>
              <span style={{
                fontFamily: 'var(--font-mono)', fontSize: 9, flexShrink: 0,
                padding: '3px 8px', borderRadius: 4,
                background: ref.covered ? 'var(--cyan-glow)' : 'var(--bg-elevated)',
                color: ref.covered ? 'var(--cyan)' : 'var(--text-dim)',
                border: `1px solid ${ref.covered ? 'var(--cyan-dim)' : 'var(--border)'}`,
              }}>
                {ref.covered ? '✓ COVERED' : 'ROADMAP'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Root App ─────────────────────────────────────────────────────────────
export default function App() {
  const [view, setView] = useState('history') // 'history' | 'new' | 'progress' | 'results' | 'docs'
  const [activeScanId, setActiveScanId] = useState(null)

  const handleScanCreated = (scanId) => {
    setActiveScanId(scanId)
    setView('progress')
  }

  const handleScanComplete = () => {
    setView('results')
  }

  const handleSelectScan = (scanId, status) => {
    setActiveScanId(scanId)
    setView(status === 'running' ? 'progress' : 'results')
  }

  const handleNewScan = () => {
    setActiveScanId(null)
    setView('new')
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <Nav view={['history', 'new', 'docs'].includes(view) ? view : null} setView={(v) => {
        if (v === 'new') handleNewScan()
        else setView(v)
      }} />

      {/* Background grid */}
      <div style={{
        position: 'fixed', inset: 0, top: 56, zIndex: 0, pointerEvents: 'none',
        backgroundImage: `
          linear-gradient(var(--border) 1px, transparent 1px),
          linear-gradient(90deg, var(--border) 1px, transparent 1px)
        `,
        backgroundSize: '40px 40px',
        opacity: 0.3,
      }} />

      <main style={{
        flex: 1, display: 'flex', justifyContent: 'center',
        padding: '40px 24px', position: 'relative', zIndex: 1,
      }}>
        {view === 'history' && (
          <ScanHistory onSelectScan={handleSelectScan} onNewScan={handleNewScan} />
        )}
        {view === 'new' && (
          <NewScanForm onScanCreated={handleScanCreated} />
        )}
        {view === 'progress' && activeScanId && (
          <ScanProgress scanId={activeScanId} onComplete={handleScanComplete} />
        )}
        {view === 'results' && activeScanId && (
          <ScanResults scanId={activeScanId} onNewScan={handleNewScan} />
        )}
        {view === 'docs' && <OWASPRef />}
      </main>

      <footer style={{
        borderTop: '1px solid var(--border)', padding: '12px 32px',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        background: 'var(--bg-base)',
      }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
          PROMPTSHIELD v1.0.0 &nbsp;·&nbsp; OWASP LLM TOP 10 ALIGNED &nbsp;·&nbsp; Built for developers
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
          promptshield.dev
        </span>
      </footer>
    </div>
  )
}
