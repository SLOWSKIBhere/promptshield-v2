import { describe, expect, it } from 'vitest'

import { OWASP_REFS, viewForScanStatus } from './App.jsx'
import { EVALUATION_DISCLAIMER } from './components/ScanResults.jsx'


describe('viewForScanStatus', () => {
  it('shows results only for completed scans', () => {
    expect(viewForScanStatus('completed')).toBe('results')
  })

  it.each(['running', 'failed', 'interrupted'])(
    'routes %s scans through the terminal state view',
    (status) => {
      expect(viewForScanStatus(status)).toBe('progress')
    },
  )
})

describe('OWASP_REFS', () => {
  it('uses the current 2026 risk names and marks only mapped risks', () => {
    expect(OWASP_REFS.map(({ id, name }) => [id, name])).toEqual([
      ['LLM01:2026', 'Prompt Injection'],
      ['LLM02:2026', 'Sensitive Information Disclosure'],
      ['LLM03:2026', 'Excessive Agency'],
      ['LLM04:2026', 'Supply Chain'],
      ['LLM05:2026', 'Data and Model Poisoning'],
      ['LLM06:2026', 'Unbounded Consumption'],
      ['LLM07:2026', 'Misinformation'],
      ['LLM08:2026', 'Hidden Context Exposure'],
      ['LLM09:2026', 'Vector and Embedding Weaknesses'],
      ['LLM10:2026', 'Improper Output Handling'],
    ])
    expect(OWASP_REFS.filter(ref => ref.mapped).map(ref => ref.id)).toEqual([
      'LLM01:2026', 'LLM02:2026', 'LLM08:2026',
    ])
  })
})

describe('result claims', () => {
  it('defines an unconditional automated-evaluation disclaimer', () => {
    expect(EVALUATION_DISCLAIMER).toContain('not proof or certification')
    expect(EVALUATION_DISCLAIMER).toContain('configured corpus and judge')
  })
})
