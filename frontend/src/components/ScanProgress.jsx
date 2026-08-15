/**
 * ScanProgress.jsx — Live scan progress terminal
 *
 * Fixes applied:
 *   - Added explicit failed state with clear error UI
 *   - Added estimated time remaining
 *   - Added consecutive error counter — stops polling after 5 errors
 *   - Guarded against onComplete firing after unmount
 *   - Added 404 / failed scan handling
 */

import React, { useEffect, useState, useRef, useCallback } from 'react'
import { ProgressBar, Spinner, TermLabel, Button } from './ui'
import { api } from '../api'

const POLL_INTERVAL_MS = 1200
const MAX_CONSECUTIVE_ERRORS = 5

export default function ScanProgress({ scanId, onComplete, onNewScan }) {
  const [progress, setProgress] = useState({
    current: 0,
    total: 0,
    current_attack: 'Initializing engine...',
    status: 'running',
  })
  const [log, setLog] = useState([
    '[INIT] PromptShield attack engine starting...',
    '[INIT] Loading OWASP LLM Top 10 attack library...',
  ])
  const [scanFailed, setScanFailed] = useState(false)
  const [failReason, setFailReason] = useState('')

  const intervalRef = useRef(null)
  const logRef = useRef(null)
  const mountedRef = useRef(true)
  const errorCountRef = useRef(0)
  const startTimeRef = useRef(Date.now())
  const completeFiredRef = useRef(false)
  const lastProgressRef = useRef(null)

  const appendLog = useCallback((line) => {
    setLog(prev => [...prev.slice(-40), line])
  }, [])

  useEffect(() => {
    mountedRef.current = true

    const poll = async () => {
      if (!mountedRef.current) return

      try {
        const data = await api.getProgress(scanId)

        if (!mountedRef.current) return

        errorCountRef.current = 0 // reset on success
        setProgress(data)

        const progressKey = `${data.current}/${data.total}:${data.current_attack}`
        if (
          data.status === 'running' &&
          data.current_attack &&
          !data.current_attack.startsWith('Initializing') &&
          progressKey !== lastProgressRef.current
        ) {
          lastProgressRef.current = progressKey
          appendLog(
            `[${String(data.current).padStart(2, '0')}/${data.total}] Testing: ${data.current_attack}`
          )
        }

        if (data.status === 'completed') {
          clearInterval(intervalRef.current)
          appendLog('[DONE] ✓ Scan complete — generating report...')
          if (!completeFiredRef.current) {
            completeFiredRef.current = true
            setTimeout(() => {
              if (mountedRef.current) onComplete()
            }, 1000)
          }
        } else if (data.status === 'failed' || data.status === 'interrupted') {
          clearInterval(intervalRef.current)
          appendLog('[ERR] ✗ Scan failed — check API key and server logs')
          setScanFailed(true)
          setFailReason(data.failure_reason || data.current_attack || 'Unknown error — check backend logs')
        }
      } catch (err) {
        if (!mountedRef.current) return
        errorCountRef.current += 1
        appendLog(`[ERR] Poll error (${errorCountRef.current}/${MAX_CONSECUTIVE_ERRORS}): ${err.message}`)

        if (errorCountRef.current >= MAX_CONSECUTIVE_ERRORS) {
          clearInterval(intervalRef.current)
          setScanFailed(true)
          setFailReason(`Lost connection to server after ${MAX_CONSECUTIVE_ERRORS} retries`)
          appendLog('[ERR] ✗ Stopped polling — too many consecutive errors')
        }
      }
    }

    poll()
    intervalRef.current = setInterval(poll, POLL_INTERVAL_MS)

    return () => {
      mountedRef.current = false
      clearInterval(intervalRef.current)
    }
  }, [scanId, appendLog, onComplete])

  // Auto-scroll terminal
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [log])

  // Estimated time remaining
  const elapsedMs = Date.now() - startTimeRef.current
  const attacksDone = progress.current
  const attacksTotal = progress.total || 50
  let etaStr = ''
  if (attacksDone > 3 && progress.status === 'running') {
    const msPerAttack = elapsedMs / attacksDone
    const remaining = Math.round((msPerAttack * (attacksTotal - attacksDone)) / 1000)
    etaStr = remaining > 0 ? `~${remaining}s remaining` : 'almost done'
  }

  if (scanFailed) {
    return (
      <div style={{
        background: 'var(--bg-surface)', border: '1px solid var(--red-dim)',
        borderRadius: 'var(--radius-lg)', padding: '28px 32px',
        maxWidth: 720, width: '100%',
      }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--red)', letterSpacing: '0.2em', marginBottom: 8 }}>
          // SCAN FAILED
        </div>
        <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 20, fontWeight: 700, color: 'var(--red)', marginBottom: 12 }}>
          Scan could not complete
        </h2>
        <div style={{
          background: 'var(--red-glow)', border: '1px solid var(--red-dim)',
          borderRadius: 'var(--radius)', padding: '12px 16px', marginBottom: 20,
          fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--red)',
        }}>
          {failReason}
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20, lineHeight: 1.6 }}>
          Common causes: missing <code style={{ fontFamily: 'var(--font-mono)', background: 'var(--bg-void)', padding: '1px 5px', borderRadius: 3 }}>ANTHROPIC_API_KEY</code> env var,
          invalid API key, or rate limit hit. Check the Backend: FastAPI terminal in VS Code.
        </div>
        <Button onClick={onNewScan}>+ TRY AGAIN</Button>

        <div style={{ marginTop: 16 }}>
          <TermLabel color="var(--red)">Error Log</TermLabel>
          <div ref={logRef} style={{
            background: 'var(--bg-void)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius)', padding: '14px 16px', height: 160,
            overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.8,
          }}>
            {log.map((line, i) => (
              <div key={i} style={{ color: line.startsWith('[ERR]') ? 'var(--red)' : 'var(--text-muted)' }}>
                {line}
              </div>
            ))}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div style={{
      background: 'var(--bg-surface)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius-lg)', padding: '28px 32px',
      maxWidth: 720, width: '100%', animation: 'fadeIn 0.3s ease',
    }}>
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
          <Spinner size={16} />
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--cyan)', letterSpacing: '0.2em' }}>
            // ATTACK SIMULATION RUNNING
          </div>
        </div>
        <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 20, fontWeight: 700 }}>
          Testing Your AI Feature
        </h2>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', marginTop: 6 }}>
          Scan ID: {scanId}
        </div>
      </div>

      <div style={{ marginBottom: 24 }}>
        <ProgressBar
          value={progress.current}
          total={progress.total}
          label={progress.current_attack}
        />
        {etaStr && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 6 }}>
            {etaStr}
          </div>
        )}
      </div>

      <div>
        <TermLabel color="var(--green)">Live Attack Log</TermLabel>
        <div ref={logRef} style={{
          background: 'var(--bg-void)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius)', padding: '14px 16px', height: 240,
          overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.8,
        }}>
          {log.map((line, i) => {
            const isErr  = line.startsWith('[ERR]')
            const isDone = line.startsWith('[DONE]')
            const isInit = line.startsWith('[INIT]')
            const isLast = i === log.length - 1
            return (
              <div key={i} style={{
                color: isErr ? 'var(--red)' : isDone ? 'var(--green)' : isInit ? 'var(--text-dim)' : 'var(--text-secondary)',
                opacity: isLast ? 1 : 0.65,
              }}>
                {line}
                {isLast && progress.status === 'running' && (
                  <span style={{ animation: 'blink 1s step-end infinite', color: 'var(--cyan)' }}>█</span>
                )}
              </div>
            )
          })}
        </div>
      </div>

      <div style={{ marginTop: 14, fontSize: 11, color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
        Each attack makes 2 LLM calls (target + judge). A full 50-attack scan takes ~2-4 minutes.
      </div>
    </div>
  )
}
