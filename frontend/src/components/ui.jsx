import React from 'react'

// ─── Severity Badge ────────────────────────────────────────────────────────
export function SeverityBadge({ severity }) {
  const config = {
    critical: { bg: 'rgba(255,45,85,0.15)', border: '#ff2d55', color: '#ff2d55', label: 'CRITICAL' },
    high:     { bg: 'rgba(255,107,53,0.15)', border: '#ff6b35', color: '#ff6b35', label: 'HIGH' },
    medium:   { bg: 'rgba(255,214,10,0.12)', border: '#ffd60a', color: '#ffd60a', label: 'MEDIUM' },
    low:      { bg: 'rgba(0,229,255,0.1)',  border: '#00e5ff', color: '#00e5ff', label: 'LOW' },
    info:     { bg: 'rgba(139,143,190,0.1)', border: '#8b8fbe', color: '#8b8fbe', label: 'INFO' },
  }
  const c = config[severity?.toLowerCase()] || config.info
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: '2px 8px',
      background: c.bg, border: `1px solid ${c.border}`,
      color: c.color, borderRadius: 4,
      fontFamily: 'var(--font-mono)', fontSize: 10,
      fontWeight: 700, letterSpacing: '0.12em',
    }}>
      {c.label}
    </span>
  )
}

// ─── Grade Circle ──────────────────────────────────────────────────────────
export function GradeCircle({ grade, score, size = 96 }) {
  const config = {
    'A+': '#00ff88', 'A': '#00ff88',
    'B':  '#7cff50',
    'C':  '#ffd60a',
    'D':  '#ff6b35',
    'F':  '#ff2d55',
  }
  const color = config[grade] || '#8b8fbe'
  const r = (size / 2) - 6
  const circumference = 2 * Math.PI * r
  const pct = Math.max(0, Math.min(100, score)) / 100
  const offset = circumference * (1 - pct)

  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)', position: 'absolute' }}>
        <circle cx={size/2} cy={size/2} r={r}
          fill="none" stroke="var(--border)" strokeWidth={5} />
        <circle cx={size/2} cy={size/2} r={r}
          fill="none" stroke={color} strokeWidth={5}
          strokeDasharray={circumference} strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1s cubic-bezier(0.4,0,0.2,1)', filter: `drop-shadow(0 0 6px ${color}66)` }}
        />
      </svg>
      <div style={{
        position: 'absolute', inset: 0, display: 'flex',
        flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: size * 0.28, fontWeight: 700, color, lineHeight: 1 }}>{grade}</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: size * 0.12, color: 'var(--text-muted)', marginTop: 2 }}>{score?.toFixed(0)}/100</span>
      </div>
    </div>
  )
}

// ─── Stat Card ─────────────────────────────────────────────────────────────
export function StatCard({ label, value, color = 'var(--text-primary)', sublabel }) {
  return (
    <div style={{
      background: 'var(--bg-surface)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', padding: '16px 20px',
    }}>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 28, fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 6 }}>{label}</div>
      {sublabel && <div style={{ fontSize: 10, color: 'var(--text-dim)', marginTop: 3 }}>{sublabel}</div>}
    </div>
  )
}

// ─── Terminal Label ────────────────────────────────────────────────────────
export function TermLabel({ children, color = 'var(--cyan)' }) {
  return (
    <div style={{
      fontFamily: 'var(--font-mono)', fontSize: 10, color,
      textTransform: 'uppercase', letterSpacing: '0.18em',
      borderLeft: `2px solid ${color}`, paddingLeft: 8,
      marginBottom: 12,
    }}>
      {children}
    </div>
  )
}

// ─── Button ────────────────────────────────────────────────────────────────
export function Button({ children, onClick, variant = 'primary', disabled, loading, style = {} }) {
  const base = {
    display: 'inline-flex', alignItems: 'center', gap: 8,
    padding: '10px 20px', borderRadius: 'var(--radius)',
    fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700,
    letterSpacing: '0.1em', cursor: disabled || loading ? 'not-allowed' : 'pointer',
    border: 'none', transition: 'all 0.15s', opacity: disabled || loading ? 0.5 : 1,
    ...style,
  }
  const variants = {
    primary: {
      background: 'var(--cyan)', color: '#000',
    },
    danger: {
      background: 'var(--red-glow)', color: 'var(--red)',
      border: '1px solid var(--red-dim)',
    },
    ghost: {
      background: 'transparent', color: 'var(--text-secondary)',
      border: '1px solid var(--border)',
    },
  }
  return (
    <button
      onClick={disabled || loading ? undefined : onClick}
      style={{ ...base, ...variants[variant] }}
      onMouseEnter={e => {
        if (!disabled && !loading) {
          if (variant === 'primary') e.target.style.filter = 'brightness(1.15)'
          else e.target.style.background = 'var(--bg-hover)'
        }
      }}
      onMouseLeave={e => {
        e.target.style.filter = ''
        if (variant !== 'primary') e.target.style.background = variants[variant].background
      }}
    >
      {loading && <Spinner size={12} />}
      {children}
    </button>
  )
}

// ─── Spinner ───────────────────────────────────────────────────────────────
export function Spinner({ size = 16, color = 'var(--cyan)' }) {
  return (
    <div style={{
      width: size, height: size, border: `2px solid ${color}22`,
      borderTopColor: color, borderRadius: '50%',
      animation: 'spin 0.7s linear infinite', flexShrink: 0,
    }} />
  )
}

// ─── Progress Bar ──────────────────────────────────────────────────────────
export function ProgressBar({ value, total, label, showPercent = true }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0
  return (
    <div style={{ width: '100%' }}>
      {(label || showPercent) && (
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
          {label && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{label}</span>}
          {showPercent && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--cyan)' }}>{pct}%</span>}
        </div>
      )}
      <div style={{
        height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden',
      }}>
        <div style={{
          height: '100%', width: `${pct}%`,
          background: 'linear-gradient(90deg, var(--cyan-dim), var(--cyan))',
          borderRadius: 2, transition: 'width 0.3s ease',
          boxShadow: '0 0 8px var(--cyan-glow)',
        }} />
      </div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
        {value} / {total} attacks
      </div>
    </div>
  )
}

// ─── Category Pill ─────────────────────────────────────────────────────────
export function CategoryPill({ category, active, onClick }) {
  const labels = {
    prompt_injection: 'Prompt Injection',
    data_extraction: 'Data Extraction',
    jailbreak: 'Jailbreak',
    role_confusion: 'Role Confusion',
    multi_turn: 'Multi-Turn',
  }
  return (
    <button onClick={onClick} style={{
      padding: '6px 12px', borderRadius: 20,
      background: active ? 'var(--cyan-glow)' : 'var(--bg-surface)',
      border: `1px solid ${active ? 'var(--cyan)' : 'var(--border)'}`,
      color: active ? 'var(--cyan)' : 'var(--text-muted)',
      fontFamily: 'var(--font-mono)', fontSize: 11,
      cursor: 'pointer', transition: 'all 0.15s',
    }}>
      {labels[category] || category}
    </button>
  )
}

// ─── Code Block ────────────────────────────────────────────────────────────
export function CodeBlock({ children, maxHeight }) {
  return (
    <pre style={{
      background: 'var(--bg-void)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', padding: '12px 16px',
      fontFamily: 'var(--font-mono)', fontSize: 11.5,
      color: 'var(--text-secondary)', whiteSpace: 'pre-wrap',
      wordBreak: 'break-word', lineHeight: 1.6,
      maxHeight: maxHeight || 'none', overflowY: maxHeight ? 'auto' : 'visible',
    }}>
      {children}
    </pre>
  )
}

// ─── Status Dot ────────────────────────────────────────────────────────────
export function StatusDot({ status }) {
  const config = {
    running:   { color: 'var(--cyan)', pulse: true },
    completed: { color: 'var(--green)', pulse: false },
    failed:    { color: 'var(--red)', pulse: false },
  }
  const c = config[status] || { color: 'var(--text-muted)', pulse: false }
  return (
    <span style={{
      display: 'inline-block', width: 8, height: 8,
      borderRadius: '50%', background: c.color, flexShrink: 0,
      boxShadow: c.pulse ? `0 0 0 0 ${c.color}44` : 'none',
      animation: c.pulse ? 'pulse-cyan 1.5s infinite' : 'none',
    }} />
  )
}
