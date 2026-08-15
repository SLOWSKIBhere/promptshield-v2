# ⚡ PromptShield — LLM Security Scanner

> Automatically test your AI features for prompt injection, jailbreaks, data extraction, and policy bypasses. OWASP LLM Top 10 aligned.

![PromptShield](https://img.shields.io/badge/OWASP-LLM%20Top%2010-00e5ff?style=flat&logo=owasp)
![Stack](https://img.shields.io/badge/Stack-FastAPI%20%2B%20React-00ff88?style=flat)

---

## What It Does

PromptShield is a developer-first security scanner for LLM-powered features. You give it:
1. Your AI feature's **system prompt**
2. Optionally, your **live HTTP endpoint**

It runs **50+ adversarial attacks** across 5 OWASP LLM Top 10 categories and gives you a security grade + remediation guide.

### Attack Categories
| Category | OWASP Ref | Attacks |
|---|---|---|
| Prompt Injection | LLM01:2025 | 15 attacks |
| Data Extraction | LLM06/07:2025 | 10 attacks |
| Jailbreaking | LLM01:2025 | 10 attacks |
| Role Confusion | LLM01:2025 | 7 attacks |
| Multi-Turn Manipulation | LLM01:2025 | 8 attacks |

---

## Run locally in VS Code

### Prerequisites

- VS Code with the recommended Python and Python Debugger extensions
- Python 3.11+
- Node.js 18+
- An Anthropic or OpenAI API key for direct-provider scans. A custom HTTP target does not require a provider key, but judging may use the heuristic fallback.

### First-time setup

Open the repository folder in VS Code, then run these tasks from **Terminal: Run Task**:

1. **Backend: Create venv and install dependencies**
2. **Frontend: Install dependencies**

The backend task creates `backend/.venv`. The workspace selects `backend/.venv/Scripts/python.exe` automatically; if necessary, choose it manually with **Python: Select Interpreter**.

Create your ignored local configuration from the integrated PowerShell terminal:

```powershell
Copy-Item backend/.env.example backend/.env
```

Edit `backend/.env` and set the credential for the provider you use. Keep `PROMPTSHIELD_API_KEY` empty for local browser development. The Vite client does not send that server credential, and server secrets must never be placed in a `VITE_*` variable.

### Start and debug the full stack

Open **Run and Debug**, select **PromptShield: Full Stack**, and press F5. This starts:

- FastAPI with debugpy at `http://127.0.0.1:8000`
- Vite at `http://127.0.0.1:5173`
- API docs at `http://127.0.0.1:8000/docs`

The frontend calls `/api`; Vite proxies those requests to FastAPI and strips the `/api` prefix. No frontend backend URL is needed for local development.

To stay inside VS Code, run **Simple Browser: Show** from the Command Palette and enter `http://127.0.0.1:5173`.

You can also start either service independently with **Backend: Start** or **Frontend: Start** from **Terminal: Run Task**.

### Offline fixture mode (no API keys)

The separate **PromptShield: Offline Full Stack** Run and Debug compound needs no `backend/.env`, API key, or external model provider. Select it and press F5 once to start three processes with separate integrated terminal/debug output:

- Deterministic fixture target at `http://127.0.0.1:9000/chat`
- FastAPI at `http://127.0.0.1:8000`
- Vite at `http://127.0.0.1:5173`

The offline backend launch supplies `ALLOW_PRIVATE_TARGETS=true`, `JUDGE_PROVIDER=heuristic`, `DATABASE_PATH=promptshield-offline.db`, and explicitly empty PromptShield, Anthropic, and OpenAI key variables directly in `.vscode/launch.json`. It has no `envFile`, so values in `backend/.env` are not needed and cannot supply those credentials to this process. The normal **PromptShield: Full Stack** launch remains provider-backed and unchanged.

Run **Simple Browser: Show** from the Command Palette and open `http://127.0.0.1:5173`. On **New Scan**, choose **load local fixture**. This fills the fixture URL, a safe example prompt, no bearer token, and only the `prompt_injection` category. Launch the scan to exercise the real React → Vite `/api` proxy → FastAPI → local fixture flow.

Expected offline health values at either URL below are `status=ok`, both provider-configured flags `false`, `auth_enabled=false`, `allow_private_targets=true`, and `judge_provider=heuristic`:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:5173/api/health
```

The offline SQLite file is `backend/promptshield-offline.db`; `backend/*.db` is ignored. Stop all three services together with Shift+F5. Private targets are enabled only in this explicit offline launch environment, never in `backend/.env` or production defaults.

For manual custom-endpoint development, **Fixture Target: Start (development only)** remains available. It serves the same deterministic target, but the normal backend still rejects private targets unless you deliberately configure its process. Never enable private targets in a deployed environment.

### Verify, test, and build

With the stack running, smoke-test it in an integrated PowerShell terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:5173/api/health
```

Both responses should report `status` as `ok`. The health payload also shows which provider is configured, the selected target/judge providers, whether API authentication is enabled, and whether private targets are allowed.

Run **Tests: All** or **Build: All** from **Terminal: Run Task**. Backend tests also appear in VS Code's Testing panel and use mocked providers plus a temporary database; they do not spend API credits.

### Local configuration and security

`backend/.env.example` documents every supported setting. Important defaults are:

| Setting | Local behavior |
|---|---|
| `DATABASE_PATH` | Relative paths resolve from `backend/`, independent of the terminal working directory. |
| `ALLOWED_ORIGINS` | Allows only the two local Vite origins by default. Set explicit deployed origins in production. |
| `TARGET_PROVIDER` | `auto` selects an available direct provider; use `anthropic`, `openai`, or `groq` to make the choice explicit. |
| `JUDGE_PROVIDER` | `auto` selects an available judge; `heuristic` avoids an external judge call. |
| `GROQ_API_KEY` | Enables Groq through its OpenAI-compatible API; set `TARGET_PROVIDER=groq` and `JUDGE_PROVIDER=groq` to select it explicitly. |
| `GROQ_TARGET_MODEL` / `GROQ_JUDGE_MODEL` | Groq model IDs used for target and judge calls; both default to `llama-3.1-8b-instant`. |
| `TARGET_TIMEOUT_SECONDS` | Bounds custom endpoint HTTP requests. |
| `ALLOW_PRIVATE_TARGETS` | `false`; enable only for a trusted local fixture, never in production. |
| `PROMPTSHIELD_API_KEY` | Empty for local browser use; set only when clients are deliberately configured to authenticate. |

The ignored `backend/.env` may contain secrets. Do not commit it, paste it into logs, or copy provider keys into scan form fields unless that custom target explicitly requires a key.

---

## Deploy to Production

### Backend → Railway (free tier)
```bash
# Install Railway CLI
npm install -g @railway/cli
railway login

cd backend
railway init
railway up

# Add env var in Railway dashboard:
# ANTHROPIC_API_KEY = sk-ant-...
```

### Frontend → Vercel
```bash
# Install Vercel CLI
npm install -g vercel

cd frontend
# Edit vercel.json: replace "your-backend.railway.app" with your Railway URL
vercel deploy --prod

# Add env var in Vercel dashboard:
# VITE_API_URL = https://your-backend.railway.app
```

---

## Project Structure

```
promptshield/
├── backend/
│   ├── main.py           # FastAPI app, all API routes
│   ├── engine.py         # Core attack runner + scoring
│   ├── evaluator.py      # LLM-as-judge logic (in engine.py)
│   ├── models.py         # Pydantic data models
│   ├── database.py       # SQLite persistence
│   ├── report.py         # HTML report generator
│   ├── attacks/          # YAML attack library ← YOUR MAIN MOAT
│   │   ├── prompt_injection.yaml
│   │   ├── data_extraction.yaml
│   │   ├── jailbreak.yaml
│   │   ├── role_confusion.yaml
│   │   └── multi_turn.yaml
│   └── requirements.txt
└── frontend/
    └── src/
        ├── App.jsx           # Root layout + routing
        ├── api.js            # HTTP client
        └── components/
            ├── NewScanForm.jsx    # Target configuration
            ├── ScanProgress.jsx   # Live progress terminal
            ├── ScanResults.jsx    # Findings explorer
            ├── ScanHistory.jsx    # Past scans list
            └── ui.jsx            # Reusable design system
```

---

## Extending the Attack Library

This is your **primary competitive moat**. Adding new attacks is just YAML:

```yaml
# backend/attacks/prompt_injection.yaml
attacks:
  - id: pi_016          # Must be unique
    name: My New Attack
    description: What this attack tests
    payload: "The actual adversarial prompt you're testing with"
    severity: high       # critical | high | medium | low | info
    owasp_ref: "LLM01:2025"
    expected_safe_behavior: "What the model SHOULD do when attacked"
```

**Sources for new attacks:**
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Garak attack library](https://github.com/NVIDIA/garak) (open source, study the probes)
- [PromptFoo adversarial plugins](https://promptfoo.dev/docs/red-team/strategies/)
- Anthropic's red-teaming papers on arXiv
- Your own research — this is where to invest time

---

## API Reference

```
POST /scans               Start a new scan (returns 202 immediately)
GET  /scans               List all scans with summaries
GET  /scans/{id}          Get full scan result with all findings
GET  /scans/{id}/progress Live progress for running scan
GET  /scans/{id}/report   HTML security report (viewable in browser)
DELETE /scans/{id}        Delete a scan
GET  /health              Health check + API key status
```

`POST /scans` returns the initial `ScanResult` payload; the frontend uses its `scan_id` and then polls the typed `ScanProgress` response until the status is terminal.

### Example: Create a Scan via curl
```bash
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{
    "scan_name": "My Chatbot Security Audit",
    "system_prompt": "You are a helpful assistant...",
    "feature_description": "Customer support bot",
    "categories": ["prompt_injection", "data_extraction"]
  }'
```

---

## GitHub Actions CI Integration

Add this to `.github/workflows/ai-security.yml` in any repo to scan on every PR:

```yaml
name: AI Security Scan
on: [pull_request]

jobs:
  promptshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run PromptShield Scan
        env:
          PROMPTSHIELD_URL: ${{ secrets.PROMPTSHIELD_URL }}
          SYSTEM_PROMPT: ${{ secrets.AI_SYSTEM_PROMPT }}
        run: |
          SCAN=$(curl -s -X POST "$PROMPTSHIELD_URL/scans" \
            -H "Content-Type: application/json" \
            -d "{\"scan_name\":\"PR #${{ github.event.number }}\",\"system_prompt\":\"$SYSTEM_PROMPT\",\"feature_description\":\"AI feature\"}")
          
          SCAN_ID=$(echo $SCAN | python3 -c "import json,sys; print(json.load(sys.stdin)['scan_id'])")
          echo "Scan ID: $SCAN_ID"
          
          # Poll until complete
          for i in {1..30}; do
            STATUS=$(curl -s "$PROMPTSHIELD_URL/scans/$SCAN_ID/progress" | python3 -c "import json,sys; print(json.load(sys.stdin)['status'])")
            if [ "$STATUS" = "completed" ]; then break; fi
            sleep 10
          done
          
          # Check grade
          GRADE=$(curl -s "$PROMPTSHIELD_URL/scans/$SCAN_ID" | python3 -c "import json,sys; print(json.load(sys.stdin)['letter_grade'])")
          echo "Security Grade: $GRADE"
          if [ "$GRADE" = "F" ] || [ "$GRADE" = "D" ]; then
            echo "::error::AI security grade is $GRADE. Review findings."
            exit 1
          fi
```

---

## Roadmap

- [ ] **More attack categories**: Indirect prompt injection, RAG poisoning, multi-modal attacks
- [ ] **Integrations**: VS Code extension, GitHub Action (native), Slack notifications
- [ ] **Attack library subscriptions**: Weekly updates with new CVE-style discoveries
- [ ] **Batch scanning**: Test multiple prompts / model versions simultaneously
- [ ] **Regression tracking**: Compare security posture across versions with git blame-style history
- [ ] **SARIF output**: Native GitHub Security tab integration

---

## License

MIT — build on top of this, sell services with it, make it yours.

---

*Built by a 16-year-old who read the OWASP LLM Top 10 and thought "someone should automate this."*
