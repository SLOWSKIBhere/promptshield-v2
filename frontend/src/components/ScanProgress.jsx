/**
 * ScanProgress.jsx — Live scan progress terminal
 *
 * Fixes applied:
 *   - Added explicit failed state with clear error UI
 *   - Added estimated time remaining
 *   - Added consecutive error counter — stops polling after 5 errors
 *   - Guarded against onComplete firing after unmount
 *   - Added 404 / failed scan handling
 *   - Uses single-flight polling with request timeout and unmount cancellation
 */

import React, { useEffect, useState, useRef, useCallback } from 'react'
import { ProgressBar, Spinner, TermLabel, Button } from './ui'
import { api } from '../api'

const POLL_INTERVAL_MS = 1200
const POLL_REQUEST_TIMEOUT_MS = 10_000
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
    '[INIT] Loading PromptShield test corpus and OWASP reference mappings...',
  ])
  const [scanFailed, setScanFailed] = useState(false)
  const [terminalStatus, setTerminalStatus] = useState(null)
  const [failReason, setFailReason] = useState('')

  const timeoutRef = useRef(null)
  const abortRef = useRef(null)
  const logRef = useRef(null)
  const errorCountRef = useRef(0)
  const startTimeRef = useRef(Date.now())
  const completeFiredRef = useRef(false)
  const lastProgressRef = useRef(null)

  const appendLog = useCallback((line) => {
    setLog(prev => [...prev.slice(-40), line])
  }, [])

  useEffect(() => {
    let cancelled = false

    const poll = async () => {
      if (cancelled) return

      let shouldContinue = true
      const controller = new AbortController()
      abortRef.current = controller
      const requestTimeout = setTimeout(
        () => controller.abort(),
        POLL_REQUEST_TIMEOUT_MS,
      )

      try {
        const data = await api.getProgress(scanId, { signal: controller.signal })

        if (cancelled) return

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
          shouldContinue = false
          appendLog('[DONE] ✓ Scan complete — generating report...')
          if (!completeFiredRef.current) {
            completeFiredRef.current = true
            setTimeout(() => {
              if (!cancelled) onComplete()
            }, 1000)
          }
        } else if (data.status === 'failed' || data.status === 'interrupted') {
          shouldContinue = false
          appendLog(data.status === 'interrupted'
            ? '[ERR] Scan interrupted before completion'
            : '[ERR] Scan failed — check configuration and server logs')
          setScanFailed(true)
          setTerminalStatus(data.status)
          setFailReason(data.failure_reason || data.current_attack || 'Unknown error — check backend logs')
        }
      } catch (err) {
        if (cancelled) return
        errorCountRef.current += 1
        appendLog(`[ERR] Poll error (${errorCountRef.current}/${MAX_CONSECUTIVE_ERRORS}): ${err.message}`)

        if (errorCountRef.current >= MAX_CONSECUTIVE_ERRORS) {
          shouldContinue = false
          setScanFailed(true)
          setTerminalStatus('failed')
          setFailReason(`Lost connection to server after ${MAX_CONSECUTIVE_ERRORS} retries`)
          appendLog('[ERR] ✗ Stopped polling — too many consecutive errors')
        }
      } finally {
        clearTimeout(requestTimeout)
        if (abortRef.current === controller) abortRef.current = null
        if (shouldContinue && !cancelled) {
          timeoutRef.current = setTimeout(poll, POLL_INTERVAL_MS)
        }
      }
    }

    poll()

    return () => {
      cancelled = true
      clearTimeout(timeoutRef.current)
      abortRef.current?.abort()
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
          // {terminalStatus === 'interrupted' ? 'SCAN INTERRUPTED' : 'SCAN FAILED'}
        </div>
        <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 20, fontWeight: 700, color: 'var(--red)', marginBottom: 12 }}>
          {terminalStatus === 'interrupted' ? 'Scan was interrupted' : 'Scan could not complete'}
        </h2>
        <div style={{
          background: 'var(--red-glow)', border: '1px solid var(--red-dim)',
          borderRadius: 'var(--radius)', padding: '12px 16px', marginBottom: 20,
          fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--red)',
        }}>
          {failReason}
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20, lineHeight: 1.6 }}>
          Review the reason above and the Backend: FastAPI terminal in VS Code. Interrupted scans can occur after a backend restart.
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
        Each case makes one target call and, unless heuristic judging is selected, one external judge call. Runtime and provider cost vary.
      </div>
    </div>
  )
}
