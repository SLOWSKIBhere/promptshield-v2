"""
report.py — HTML security report generator

Fixes applied:
  BUG-18: Removed redundant SEVERITY_COLORS/GRADE_COLORS dicts (dead code)
  XSS:    finding.model_response and finding.judge_reasoning now escaped
  CODE:   escape_html() moved to top of file for clarity
"""

from datetime import datetime
from models import ScanResult


# ─── Helpers ─────────────────────────────────────────────────────────────────
# Moved to top — used throughout generate_html_report()

def _escape(text: str) -> str:
    """Escape all HTML special characters to prevent XSS in report output."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


_SEVERITY_STYLE = {
    "critical": ("#ff2d55", "rgba(255,45,85,0.15)"),
    "high":     ("#ff6b35", "rgba(255,107,53,0.15)"),
    "medium":   ("#ffd60a", "rgba(255,214,10,0.12)"),
    "low":      ("#00e5ff", "rgba(0,229,255,0.10)"),
    "info":     ("#8b8fbe", "rgba(139,143,190,0.10)"),
}

_GRADE_COLOR = {
    "A+": "#00ff88", "A": "#00ff88",
    "B":  "#7cff50",
    "C":  "#ffd60a",
    "D":  "#ff6b35",
    "F":  "#ff2d55",
}


def generate_html_report(scan: ScanResult) -> str:
    exploited = [f for f in scan.findings if f.is_exploited]
    safe_count = len(scan.findings) - len(exploited)
    critical_count = sum(1 for f in exploited if _sev(f) == "critical")
    high_count = sum(1 for f in exploited if _sev(f) == "high")

    grade_color = _GRADE_COLOR.get(scan.letter_grade, "#8b8fbe")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    findings_html = _build_findings_html(exploited, scan.findings) if scan.findings else (
        '<div class="no-findings">✅ No vulnerabilities detected. All attack vectors blocked.</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PromptShield Report — {_escape(scan.scan_name)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:Arial,sans-serif;background:#050508;color:#e2e8f0;padding:2rem;-webkit-font-smoothing:antialiased}}
.container{{max-width:900px;margin:0 auto}}
.header{{border-bottom:2px solid #1a1c35;padding-bottom:1.5rem;margin-bottom:2rem}}
.logo{{font-family:Consolas,monospace;font-size:.7rem;color:#00e5ff;letter-spacing:.2em;margin-bottom:.75rem}}
h1{{font-size:1.6rem;font-weight:700;color:#f1f5f9}}
.meta{{color:#8b8fbe;font-size:.8rem;margin-top:.4rem;font-family:Consolas,monospace}}
.scorecard{{display:grid;grid-template-columns:auto 1fr;gap:2rem;background:#0d0e1a;border:1px solid #1a1c35;border-radius:8px;padding:1.75rem;margin-bottom:1.5rem;align-items:center}}
.grade-circle{{width:96px;height:96px;border-radius:50%;background:{grade_color}1a;border:3px solid {grade_color};display:flex;flex-direction:column;align-items:center;justify-content:center;flex-shrink:0}}
.grade-letter{{font-size:2.2rem;font-weight:700;color:{grade_color};font-family:Consolas,monospace;line-height:1}}
.grade-score{{font-size:.7rem;color:{grade_color}99;font-family:Consolas,monospace;margin-top:2px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem}}
.stat{{text-align:center;background:#111228;border:1px solid #1a1c35;border-radius:6px;padding:12px}}
.stat-num{{font-size:1.75rem;font-weight:700;font-family:Consolas,monospace;line-height:1}}
.stat-label{{font-size:.65rem;color:#8b8fbe;text-transform:uppercase;letter-spacing:.1em;margin-top:4px}}
.section-label{{font-family:Consolas,monospace;font-size:.65rem;color:#00e5ff;text-transform:uppercase;letter-spacing:.18em;border-left:2px solid #00e5ff;padding-left:8px;margin:1.5rem 0 .75rem}}
.summary-box{{background:#0d0e1a;border:1px solid #1a1c35;border-radius:6px;padding:1rem 1.25rem;margin-bottom:1.5rem;font-size:.875rem;color:#8b8fbe;line-height:1.6}}
.prompt-box{{background:#020617;border:1px solid #1a1c35;border-radius:6px;padding:1rem;margin-bottom:1.5rem;font-family:Consolas,monospace;font-size:.75rem;color:#8b8fbe;white-space:pre-wrap;word-break:break-word;max-height:200px;overflow-y:auto}}
.finding{{background:#0d0e1a;border:1px solid #1a1c35;border-radius:8px;padding:1.25rem;margin-bottom:.75rem}}
.finding-header{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:.75rem;gap:1rem}}
.finding-title{{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}}
.badge{{padding:2px 8px;border-radius:3px;font-size:.65rem;font-weight:700;font-family:Consolas,monospace;color:#fff}}
.owasp{{font-family:Consolas,monospace;font-size:.65rem;color:#454870}}
.conf{{font-family:Consolas,monospace;font-size:.65rem;color:#454870}}
.field-label{{font-size:.6rem;text-transform:uppercase;letter-spacing:.1em;color:#454870;display:block;margin-bottom:3px;margin-top:.75rem}}
.field-value{{font-size:.8rem;color:#94a3b8;line-height:1.5}}
code{{display:block;background:#020617;border:1px solid #1a1c35;border-radius:4px;padding:.6rem .75rem;font-family:Consolas,monospace;font-size:.72rem;color:#8b8fbe;white-space:pre-wrap;word-break:break-word;margin-top:3px;max-height:120px;overflow-y:auto}}
.remediation{{background:#0d2818;border:1px solid #166534;border-radius:6px;padding:.75rem 1rem;margin-top:.75rem}}
.remediation .field-label{{color:#4ade80}}
.remediation .field-value{{color:#86efac}}
.no-findings{{background:#0d2818;border:1px solid #166534;border-radius:8px;padding:2rem;text-align:center;color:#4ade80}}
.safe-finding{{opacity:.5}}
.footer{{margin-top:3rem;padding-top:1rem;border-top:1px solid #1a1c35;font-family:Consolas,monospace;font-size:.65rem;color:#282b4a;text-align:center}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">PROMPTSHIELD // AI SECURITY REPORT</div>
    <h1>{_escape(scan.scan_name)}</h1>
    <div class="meta">Generated: {generated_at} &nbsp;·&nbsp; Scan ID: {scan.scan_id} &nbsp;·&nbsp; Feature: {_escape(scan.feature_description)}</div>
  </div>

  <div class="scorecard">
    <div class="grade-circle">
      <span class="grade-letter">{_escape(scan.letter_grade)}</span>
      <span class="grade-score">{scan.overall_score:.0f}/100</span>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-num" style="color:#ff2d55">{critical_count}</div><div class="stat-label">Critical</div></div>
      <div class="stat"><div class="stat-num" style="color:#ff6b35">{high_count}</div><div class="stat-label">High</div></div>
      <div class="stat"><div class="stat-num" style="color:#00ff88">{safe_count}</div><div class="stat-label">Blocked</div></div>
      <div class="stat"><div class="stat-num" style="color:#8b8fbe">{len(scan.findings)}</div><div class="stat-label">Total</div></div>
    </div>
  </div>

  <div class="section-label">Executive Summary</div>
  <div class="summary-box">{_escape(scan.summary or 'No summary available.')}</div>

  <div class="section-label">System Prompt Tested</div>
  <div class="prompt-box">{_escape(scan.system_prompt_preview)}</div>

  <div class="section-label">Findings — {len(exploited)} exploit{'s' if len(exploited) != 1 else ''} of {len(scan.findings)} attacks</div>
  {findings_html}

  <div class="footer">PromptShield v1.1.0 &nbsp;·&nbsp; OWASP LLM Top 10 Aligned &nbsp;·&nbsp; promptshield.dev</div>
</div>
</body>
</html>"""


def _sev(finding) -> str:
    s = finding.severity
    return s.value if hasattr(s, "value") else str(s)


def _build_findings_html(exploited, all_findings) -> str:
    if not exploited:
        return '<div class="no-findings">✅ No vulnerabilities detected. All attack vectors successfully blocked.</div>'

    parts = []
    for f in all_findings:
        sev = _sev(f)
        color, bg = _SEVERITY_STYLE.get(sev, ("#8b8fbe", "rgba(139,143,190,0.1)"))

        if f.is_exploited:
            # XSS FIX: ALL user-controlled fields now go through _escape()
            parts.append(f"""
<div class="finding" style="border-left:3px solid {color}">
  <div class="finding-header">
    <div class="finding-title">
      <span class="badge" style="background:{color}">{sev.upper()}</span>
      <strong>{_escape(f.attack_name)}</strong>
      <span class="owasp">{_escape(f.owasp_ref)}</span>
    </div>
    <span class="conf">Confidence: {int(f.confidence * 100)}%</span>
  </div>
  <span class="field-label">Category</span>
  <div class="field-value">{_escape(f.category.replace("_", " ").title())}</div>
  <span class="field-label">Attack Payload</span>
  <code>{_escape(f.payload)}</code>
  <span class="field-label">Model Response (excerpt)</span>
  <code>{_escape(str(f.model_response)[:400])}{'...' if len(str(f.model_response)) > 400 else ''}</code>
  <span class="field-label">Judge Reasoning</span>
  <div class="field-value" style="font-style:italic">{_escape(f.judge_reasoning)}</div>
  <div class="remediation">
    <span class="field-label">🔧 Remediation</span>
    <div class="field-value">{_escape(f.remediation)}</div>
  </div>
</div>""")
        else:
            parts.append(f"""
<div class="finding safe-finding" style="border-left:3px solid #1a1c35">
  <div class="finding-header">
    <div class="finding-title">
      <span class="badge" style="background:#0d2818;color:#4ade80;border:1px solid #166534">BLOCKED</span>
      <strong>{_escape(f.attack_name)}</strong>
      <span class="owasp">{_escape(f.owasp_ref)}</span>
    </div>
    <span class="conf">Confidence: {int(f.confidence * 100)}%</span>
  </div>
</div>""")

    return "\n".join(parts)
