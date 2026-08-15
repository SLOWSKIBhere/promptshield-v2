import React, { useState } from 'react'
import NewScanForm from './components/NewScanForm'
import ScanProgress from './components/ScanProgress'
import ScanResults from './components/ScanResults'
import ScanHistory from './components/ScanHistory'

export const OWASP_REFS = [
  { id: 'LLM01:2026', name: 'Prompt Injection', desc: 'Untrusted input changes model behavior or the surrounding application flow in unintended ways.', mapped: true },
  { id: 'LLM02:2026', name: 'Sensitive Information Disclosure', desc: 'Model output exposes confidential data such as PII, credentials, or proprietary information.', mapped: true },
  { id: 'LLM03:2026', name: 'Excessive Agency', desc: 'An LLM-enabled system receives excessive functionality, permissions, or autonomy.', mapped: false },
  { id: 'LLM04:2026', name: 'Supply Chain', desc: 'Third-party components, data, or models introduce integrity and provenance risks.', mapped: false },
  { id: 'LLM05:2026', name: 'Data and Model Poisoning', desc: 'Manipulated training, fine-tuning, or retrieval data changes model behavior.', mapped: false },
  { id: 'LLM06:2026', name: 'Unbounded Consumption', desc: 'Uncontrolled inference or resource use creates denial-of-service or cost risks.', mapped: false },
  { id: 'LLM07:2026', name: 'Misinformation', desc: 'Models generate false or misleading information that users or systems treat as reliable.', mapped: false },
  { id: 'LLM08:2026', name: 'Hidden Context Exposure', desc: 'Hidden, non-user-facing system instructions or operational context are extracted, inferred, or reconstructed.', mapped: true },
  { id: 'LLM09:2026', name: 'Vector and Embedding Weaknesses', desc: 'Weaknesses in retrieval and embedding systems compromise relevant context or data.', mapped: false },
  { id: 'LLM10:2026', name: 'Improper Output Handling', desc: 'Downstream systems fail to validate or safely handle model output.', mapped: false },
]

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
          LOCAL CONSOLE
        </div>
        <a href="https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/"
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
  return (
    <div style={{ maxWidth: 800, width: '100%', animation: 'fadeIn 0.3s ease' }}>
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--cyan)', letterSpacing: '0.2em', marginBottom: 8 }}>
          // REFERENCE
        </div>
        <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 700 }}>OWASP GenAI LLM Top 10 — 2026</h2>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 8, lineHeight: 1.5 }}>
          PromptShield maps selected test cases to the references marked below. This is not comprehensive OWASP coverage or certification.
        </p>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {OWASP_REFS.map(ref => (
          <div key={ref.id} style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderLeft: `3px solid ${ref.mapped ? 'var(--cyan)' : 'var(--border)'}`,
            borderRadius: 'var(--radius)', padding: '14px 18px',
            opacity: ref.mapped ? 1 : 0.6,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16 }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 4 }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: ref.mapped ? 'var(--cyan)' : 'var(--text-dim)' }}>
                    {ref.id}
                  </span>
                  <strong style={{ fontSize: 13, color: 'var(--text-primary)' }}>{ref.name}</strong>
                </div>
                <p style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>{ref.desc}</p>
              </div>
              <span style={{
                fontFamily: 'var(--font-mono)', fontSize: 9, flexShrink: 0,
                padding: '3px 8px', borderRadius: 4,
                background: ref.mapped ? 'var(--cyan-glow)' : 'var(--bg-elevated)',
                color: ref.mapped ? 'var(--cyan)' : 'var(--text-dim)',
                border: `1px solid ${ref.mapped ? 'var(--cyan-dim)' : 'var(--border)'}`,
              }}>
                {ref.mapped ? 'TEST CASES' : 'NOT TESTED'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Root App ─────────────────────────────────────────────────────────────
export function viewForScanStatus(status) {
  return status === 'completed' ? 'results' : 'progress'
}

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
    setView(viewForScanStatus(status))
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
          <ScanProgress scanId={activeScanId} onComplete={handleScanComplete} onNewScan={handleNewScan} />
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
          PROMPTSHIELD v1.1.0 &nbsp;·&nbsp; SELECTED OWASP 2026 REFERENCES &nbsp;·&nbsp; Built for developers
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>
          promptshield.dev
        </span>
      </footer>
    </div>
  )
}
