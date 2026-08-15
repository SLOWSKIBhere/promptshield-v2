# PromptShield — LLM Security Scanner

> Run a finite, reviewable set of adversarial test cases against an LLM feature during development.

![PromptShield](https://img.shields.io/badge/OWASP-selected%202026%20references-00e5ff?style=flat&logo=owasp)
![Stack](https://img.shields.io/badge/Stack-FastAPI%20%2B%20React-00ff88?style=flat)

PromptShield is a developer-focused scanner with a React/Vite frontend, FastAPI backend, SQLite history, a Python evaluation engine, and a YAML attack corpus. It can call Anthropic, OpenAI, or Groq directly, or send test cases to a custom HTTP endpoint.

This repository is currently a local-development project. The checked-in deployment files are templates, not a production-ready deployment.

## What it tests

The checked-in corpus contains exactly **50 test cases** in five internal attack families:

| Internal family | API value | Test cases | Selected OWASP 2026 references |
|---|---|---:|---|
| Prompt Injection | `prompt_injection` | 15 | LLM01: Prompt Injection |
| Data Extraction | `data_extraction` | 10 | LLM02: Sensitive Information Disclosure; LLM08: Hidden Context Exposure |
| Jailbreak | `jailbreak` | 10 | LLM01: Prompt Injection |
| Role Confusion | `role_confusion` | 7 | LLM01: Prompt Injection |
| Conversation Claims | `multi_turn` | 8 | LLM01: Prompt Injection; LLM08: Hidden Context Exposure |

These are PromptShield groupings, not five OWASP Top 10 categories. The `multi_turn` family uses single messages that claim or simulate prior conversational context; the engine does **not** maintain a stateful multi-turn conversation.

The mappings are references to relevant risks in the [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), not a claim of comprehensive coverage, conformance, or certification. In particular, PromptShield does not currently test tool permissions or actions required to evaluate LLM03: Excessive Agency. OWASP's 2026 list broadens the former System Prompt Leakage entry into LLM08: Hidden Context Exposure; system prompts still must not be treated as secrets or authorization controls.

## How a scan works

1. The API creates a running scan row in SQLite and schedules an in-process FastAPI background task.
2. The engine loads the selected YAML families and sends each test case either to a direct provider or to the configured custom endpoint.
3. Each response is evaluated by the selected Anthropic, OpenAI, or Groq judge. If `JUDGE_PROVIDER=heuristic`, no external judge call is made. An unavailable, invalid, or unconfigured judge also falls back to a labeled heuristic result.
4. Progress, responses, findings, the corpus score, and the terminal state are persisted in SQLite.
5. The frontend polls `/scans/{id}/progress` and displays completed results or an explicit failed/interrupted state.

A full scan makes 50 target calls and normally another 50 external judge calls. Heuristic judging avoids the second set. Provider cost and runtime therefore depend on the selected configuration.

### Interpreting results

The displayed score and letter grade summarize only the selected PromptShield corpus and its configured judge. A high score means those automated cases were not flagged; it does not prove that the target is secure and is not a security certification. External LLM judges can make mistakes. PromptShield separates untrusted evidence from higher-priority judge instructions and strictly validates judge JSON, but real-model resistance to judge prompt injection is **not verified**.

## Current security boundaries and limitations

- Private and non-global custom-target addresses are blocked by default. The offline VS Code launch opts into private targets only for its local fixture.
- Custom endpoint redirects are not followed. DNS preflight runs outside the event loop with a five-second deadline, but the validated address is not pinned to the connection, so DNS-rebinding resistance is not complete.
- A custom bearer token is accepted only for an HTTPS target. It is not part of the persistence model. Exact appearances in stored metadata and exact reflections from the target are redacted before judging or storage, but transformed or encoded versions cannot be guaranteed detectable.
- Custom responses must use identity encoding and are streamed with a 1,000,000-byte limit. At most 2,000 characters of the selected response value are judged or stored.
- An external judge receives the selected test metadata, up to 1,500 characters of the submitted system prompt, and up to 1,000 characters of the target response. Use heuristic judging if that data must not be sent to another provider.
- Scan metadata, the first 300 characters of the submitted system prompt, target responses, findings, and judge reasoning are stored in SQLite. Do not submit secrets as prompt or target content.
- API authentication is optional and disabled when `PROMPTSHIELD_API_KEY` is unset. There is no rate limit, aggregate scan-admission limit, quota, cancellation, or cost budget. Do not expose a provider-backed instance to untrusted users.
- Background work is in-process. A restart interrupts active scans; startup marks orphaned running rows as `interrupted`.
- Custom HTTP operations default to a 30-second timeout. Direct provider and external judge clients default to an explicit 60-second timeout. These are operation/client timeouts, not a hard scan-wide deadline; SDK retries and streaming behavior may extend total wall-clock time.
- YAML is repository-owned, loaded with `yaml.safe_load`, and selected through an enum-constrained API. Users cannot submit YAML paths through the scan endpoint.

See [SHIP_STATUS.md](SHIP_STATUS.md) for the broader repository audit and known deployment blockers.

## Run locally in VS Code

### Prerequisites

- VS Code with the recommended Python and Python Debugger extensions
- Python 3.11+
- Node.js 18+
- An Anthropic, OpenAI, or Groq API key for direct-provider scans. A custom HTTP target can run without one and use heuristic judging.

### First-time setup

Open the repository in VS Code and run these tasks from **Terminal: Run Task**:

1. **Backend: Create venv and install dependencies**
2. **Frontend: Install dependencies**

Create the ignored local configuration from the integrated PowerShell terminal:

```powershell
Copy-Item backend/.env.example backend/.env
```

Edit `backend/.env` for the provider you use. Keep `PROMPTSHIELD_API_KEY` empty for the default local browser workflow: the Vite client does not send that server credential. Never put server credentials in a `VITE_*` variable.

### Start and debug the full stack

In **Run and Debug**, select **PromptShield: Full Stack** and press F5. It starts:

- FastAPI with debugpy at `http://127.0.0.1:8000`
- Vite at `http://127.0.0.1:5173`
- API docs at `http://127.0.0.1:8000/docs`

The browser calls `/api`; Vite proxies those requests to FastAPI and strips the `/api` prefix. No frontend backend URL is required for this local workflow.

### Offline fixture mode

Select **PromptShield: Offline Full Stack** to run without credentials or external calls. It starts:

- A deterministic fixture target at `http://127.0.0.1:9000/chat`
- FastAPI at `http://127.0.0.1:8000`
- Vite at `http://127.0.0.1:5173`

The launch configuration sets `ALLOW_PRIVATE_TARGETS=true`, `JUDGE_PROVIDER=heuristic`, `DATABASE_PATH=promptshield-offline.db`, and empty Anthropic, OpenAI, Groq, and PromptShield credential variables. It deliberately does not load `backend/.env`.

Open `http://127.0.0.1:5173`, choose **load local fixture**, and start the prefilled one-family scan. Expected health values are `status=ok`, all three provider-configured flags `false`, `auth_enabled=false`, `allow_private_targets=true`, and `judge_provider=heuristic`:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:5173/api/health
```

The offline database is `backend/promptshield-offline.db`; `backend/*.db` is ignored. Private targets remain disabled in normal configuration.

### Test and build

Run **Tests: All** or **Build: All** from **Terminal: Run Task**, or use:

```powershell
backend/.venv/Scripts/python.exe -m pytest backend/tests -q
npm --prefix frontend test
npm --prefix frontend run build
```

Backend tests use mock providers and temporary databases. They make no real provider/API calls.

No GitHub Actions workflow is currently checked in. If scan automation is added later, build request bodies with a JSON-aware encoder (for example, Python's `json` module or `jq --arg`); never interpolate an arbitrary system prompt directly into quoted shell JSON.

## Configuration

`backend/.env.example` documents the supported settings. Important defaults include:

| Setting | Default behavior |
|---|---|
| `DATABASE_PATH` | `backend/promptshield.db`; relative paths resolve from `backend/`. |
| `ALLOWED_ORIGINS` | Only the two local Vite origins. |
| `TARGET_PROVIDER` | `auto`; chooses an available Anthropic, OpenAI, or Groq client. |
| `JUDGE_PROVIDER` | `auto`; chooses an available judge, or use `heuristic` to avoid judge calls. |
| `TARGET_TIMEOUT_SECONDS` | 30 seconds for custom HTTP targets. |
| `PROVIDER_TIMEOUT_SECONDS` | 60 seconds for direct providers and external judges. |
| `ALLOW_PRIVATE_TARGETS` | `false`; use only for a trusted local fixture. |
| `PROMPTSHIELD_API_KEY` | Empty; set only when every client is configured to authenticate. |

The ignored `backend/.env` may contain secrets. Never commit it or paste its values into logs.

## Custom HTTP target contract

PromptShield sends an HTTP(S) JSON `POST` shaped as:

```json
{"message": "test case", "content": "test case", "input": "test case"}
```

The response must be a JSON object. PromptShield reads the first present key from `response`, `message`, `content`, `output`, `text`, `answer`, or `result`; otherwise it evaluates a bounded JSON serialization of the object. A bearer token, when supplied, is sent as `Authorization: Bearer ...` and requires an HTTPS URL.

## Project structure

```text
promptshield/
├── backend/
│   ├── main.py           # FastAPI routes and background worker
│   ├── engine.py         # Target calls, judging, corpus execution, scoring
│   ├── models.py         # Pydantic request/response models
│   ├── database.py       # SQLite persistence
│   ├── report.py         # Escaped HTML report generator
│   ├── attacks/          # Five YAML attack-family documents
│   ├── tests/            # Offline backend regression tests and fixture target
│   └── requirements.txt
├── frontend/
│   ├── src/              # React UI and `/api` client
│   └── package.json
└── .vscode/              # Local tasks and debug compounds
```

## API

```text
POST   /scans               Create and schedule a scan (202)
GET    /scans               List scan summaries
GET    /scans/{id}          Get a full scan result
GET    /scans/{id}/progress Get typed progress and terminal status
GET    /scans/{id}/report   Get HTML for a completed scan
DELETE /scans/{id}          Delete a persisted scan row
GET    /health              Get health and non-secret configuration flags
```

Deleting a running scan does not cancel its already scheduled provider work.

## Extending the corpus

Attack definitions live in `backend/attacks/*.yaml` and are loaded with `yaml.safe_load`. Keep IDs unique and add/update the corpus-integrity regression test when changing counts or OWASP references. Use the current official OWASP pages when assigning mappings:

- [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
- [Canonical 2026 final source](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final)
- [LLM01: Prompt Injection](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM01_PromptInjection.md)
- [LLM02: Sensitive Information Disclosure](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM02_SensitiveInformationDisclosure.md)
- [LLM08: Hidden Context Exposure](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/2026/final/LLM08_HiddenContextExposure.md)

Do not add live provider calls to automated tests.

## Deployment status

`backend/railway.toml` and `frontend/vercel.json` are incomplete templates. The frontend rewrite still contains a placeholder backend hostname, and the repository has no complete plan for durable database storage, authenticated browser/report access, admission control, or deployed CORS. Resolve the blockers in [SHIP_STATUS.md](SHIP_STATUS.md) before deploying or making an instance public.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the small-project branch, test, commit, and draft-PR workflow.

## License

MIT

---

*Built by a 16-year-old who read the OWASP LLM Top 10 and thought “someone should automate this.”*
