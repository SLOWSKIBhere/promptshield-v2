# PromptShield Backend Wiring Plan (VS Code Only)

## Goal

Run, debug, test, and verify the React frontend and FastAPI backend entirely from one VS Code workspace. The finished local flow is:

```text
React UI (Vite :5173)
        |
        | /api/*
        v
Vite development proxy
        |
        | strips /api
        v
FastAPI (:8000) -> scan engine -> provider/target endpoint -> SQLite
```

No deployment dashboard, external IDE, API GUI, or standalone browser is required. Commands run in the VS Code integrated terminal; services run through VS Code tasks/debug configurations; API smoke tests use PowerShell in the integrated terminal; the UI can be opened with VS Code's built-in Simple Browser.

## Current State

The main connection already exists:

- `frontend/src/api.js` uses `VITE_API_URL` or `/api`.
- `frontend/vite.config.js` forwards `/api/*` to `http://localhost:8000/*`.
- `backend/main.py` exposes the routes required by the frontend.
- `backend/database.py` persists scans in SQLite.
- `backend/engine.py` loads attacks, calls the target/provider, evaluates results, and reports progress.

Frontend-to-backend route mapping:

| Frontend operation | HTTP contract | Backend handler |
|---|---|---|
| Health | `GET /health` | `health` |
| History | `GET /scans` | `list_all_scans` |
| Start scan | `POST /scans` | `create_scan` |
| Scan result | `GET /scans/{id}` | `get_scan_result` |
| Progress | `GET /scans/{id}/progress` | `get_scan_progress` |
| HTML report | `GET /scans/{id}/report` | `get_scan_report` |
| Delete scan | `DELETE /scans/{id}` | `delete_scan_endpoint` |

## Phase 1 — Make Local Configuration Deterministic

1. Create `backend/.venv` from the VS Code integrated terminal and select `backend/.venv/Scripts/python.exe` with **Python: Select Interpreter**.
2. Install `backend/requirements.txt` into that environment.
3. Copy `backend/.env.example` to the ignored `backend/.env`; insert one real provider key. Never commit `.env`.
4. Add a small `backend/config.py` using `pydantic-settings`, or explicitly load `.env` at process startup. Centralize:
   - `ANTHROPIC_API_KEY`
   - `OPENAI_API_KEY`
   - `PROMPTSHIELD_API_KEY`
   - `ALLOWED_ORIGINS`
   - `DATABASE_PATH`
   - provider model names
   - `ALLOW_PRIVATE_TARGETS` (development only; default `false`)
5. Resolve the SQLite path from `backend/` or from `DATABASE_PATH`, not from the caller's current directory. This prevents VS Code launch-directory changes from creating databases in different folders.
6. Keep `PROMPTSHIELD_API_KEY` unset for local browser development. If local API authentication is required later, add a frontend header configuration deliberately; do not expose a production server secret through a `VITE_*` variable.

Deliverable: starting FastAPI from either a task or debugger reads the same configuration and uses the same database.

## Phase 2 — Stabilize the API Contract

1. Add explicit enums/validation for scan status and allowed category names.
2. Reject an empty or unknown category list with a clear `422` response instead of silently producing zero attacks.
3. Define a `ScanProgress` response model and use it on `/scans/{id}/progress`.
4. Return a small creation response (`scan_id`, `status`) or retain `ScanResult`; document whichever contract is chosen and test the frontend against it.
5. Normalize API errors to `{ "detail": "..." }`, which is what `frontend/src/api.js` already expects.
6. Add `Cache-Control: no-store` to progress/results while a scan is running.
7. Add a root route only if useful for a terminal health message; it is not required by the frontend.

Deliverable: OpenAPI and the JavaScript client agree on payloads, status codes, and error shapes.

## Phase 3 — Harden the Scan Engine Integration

1. Introduce a provider interface with two operations:
   - call the target model;
   - judge whether a response was exploited.
2. Stop hard-coding the Anthropic model inside `call_target` and `evaluate_with_judge`; use validated settings so the form/backend default cannot drift.
3. Make the judge provider explicit. Today an OpenAI-only setup can call the target but silently falls back to heuristic judging because the judge only accepts an Anthropic client.
4. Call `resp.raise_for_status()` before parsing custom endpoint responses; the existing `HTTPStatusError` branch is otherwise unreachable.
5. Validate that custom endpoint responses are JSON objects before searching response keys. Return a structured failure for HTML, arrays, invalid JSON, timeout, or non-2xx responses.
6. Preserve SSRF protection. For testing a target running locally in VS Code, allow localhost/private targets only when `ALLOW_PRIVATE_TARGETS=true` in the local `.env`. This flag must default to `false` and must never be enabled in production.
7. Never persist the submitted target `api_key`; redact it from logs and exception messages.
8. Add bounded concurrency only after sequential behavior is covered by tests. Use a semaphore to respect provider rate limits and serialize database progress updates safely.

Deliverable: both direct-provider scans and custom-endpoint scans fail predictably and produce trustworthy findings.

## Phase 4 — Make Progress and Background Work Reliable

1. Add dedicated database columns for `current_attack_index` and `current_attack_name`. Do not overload `summary` with a `[PROGRESS:x/y]` string.
2. Update progress after each completed attack, using one consistent convention (`0..total` or `1..total`).
3. On startup, mark orphaned `running` scans as `failed` or `interrupted`; in-process FastAPI background tasks do not survive a debugger restart.
4. Keep FastAPI `BackgroundTasks` for the local VS Code version. A separate worker/queue is unnecessary until multi-process or production execution is in scope.
5. Store a concise failure reason for the UI and log the full traceback only in the backend terminal.

Deliverable: the progress screen remains internally consistent through success, failure, and a VS Code debug restart.

## Phase 5 — Create the VS Code-Only Run Experience

Replace the current Chrome-only `.vscode/launch.json` entry (`localhost:8080`) with workspace-aware configurations:

1. **Backend: FastAPI**
   - debugger type: Python/debugpy;
   - module: `uvicorn`;
   - args: `main:app --reload --host 127.0.0.1 --port 8000`;
   - working directory: `${workspaceFolder}/backend`;
   - env file: `${workspaceFolder}/backend/.env`.
2. **Frontend: Vite**
   - run `npm run dev -- --host 127.0.0.1 --port 5173`;
   - working directory: `${workspaceFolder}/frontend`.
3. Add `.vscode/tasks.json` tasks for dependency installation, backend start, frontend start, tests, and production builds.
4. Add a compound configuration named **PromptShield: Full Stack** that starts both services.
5. Add `.vscode/settings.json` with the Python interpreter path, pytest directory, and terminal environment only where necessary.
6. Document opening `http://127.0.0.1:5173` through **Simple Browser: Show** inside VS Code.

Deliverable: one VS Code command starts both services with breakpoints and separate terminal output.

## Phase 6 — Add Automated Tests

Add `pytest`, `pytest-asyncio`, and an appropriate FastAPI/httpx test setup as development dependencies.

Minimum backend tests:

1. health response and configuration flags;
2. valid scan creation returns `202` and an ID;
3. invalid/unknown categories return `422`;
4. missing scan returns `404` for result, progress, report, and delete;
5. scan history ordering and summary counts;
6. deletion removes exactly one scan;
7. report is rejected before completion and returns HTML after completion;
8. target endpoint parsing for every supported response key;
9. non-2xx, invalid JSON, and timeout behavior;
10. SSRF rejection and the explicit development-only override;
11. provider error fallback behavior;
12. persistence and orphaned-running-scan recovery.

Mock provider calls and the attack runner so tests never spend API credits. Use a temporary SQLite database per test.

Frontend contract tests should mock `fetch` and verify each function in `frontend/src/api.js`, especially error parsing and report URL construction.

Deliverable: the VS Code **Testing** panel can run the backend suite without network access or paid-provider calls.

## Phase 7 — VS Code Integrated Smoke Test

With the full-stack compound task running:

1. In a VS Code terminal, call `http://127.0.0.1:8000/health` with `Invoke-RestMethod` and confirm status `ok` plus the intended provider flag.
2. Open `http://127.0.0.1:5173` in VS Code Simple Browser.
3. Confirm history loads through the Vite proxy with no CORS errors.
4. Load a sample prompt, select one category, and start a scan.
5. Confirm the UI transitions through create -> progress -> completed result.
6. Confirm the progress count increases and polling stops on `completed` or `failed`.
7. Open the HTML report inside VS Code.
8. Delete the scan and confirm it disappears from history and SQLite.
9. Repeat with an intentionally invalid provider key to verify the visible failure path.
10. If custom endpoints are in scope, run a fixture target as another VS Code task and test it with `ALLOW_PRIVATE_TARGETS=true` only for that local session.

Deliverable: every frontend action is verified against the real local backend without leaving VS Code.

## Recommended Implementation Order

1. Configuration and stable database path.
2. VS Code tasks and compound debug launch.
3. API schema/category validation.
4. Engine provider and HTTP-response fixes.
5. Dedicated progress persistence and restart recovery.
6. Backend and frontend contract tests.
7. Full-stack smoke test in VS Code Simple Browser.

## Definition of Done

- One VS Code compound launch starts FastAPI on `8000` and Vite on `5173`.
- The frontend uses `/api` locally; no hard-coded backend URL is needed.
- Health, creation, polling, results, reports, history, and deletion work end to end.
- Secrets are loaded from ignored local configuration and are not persisted or logged.
- Custom endpoint handling is bounded, validated, and SSRF-safe by default.
- OpenAI-only and Anthropic configurations have explicit, tested judge behavior.
- Restarted/interrupted scans do not remain permanently `running`.
- Tests run from VS Code without paid API calls.
- Production builds for both application layers complete from VS Code tasks.

## Scope Boundary

This plan intentionally does not add Railway, Vercel, Docker, Redis, Celery, cloud databases, or external dashboards. Those are separate productionization decisions, not requirements for wiring the current frontend and backend in a VS Code-only environment.
