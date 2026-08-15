# PromptShield Repository Truth Audit

Audit date: 2026-08-14

This audit compares the checked-out implementation with `README.md` and `BACKEND_IMPLEMENTATION_PLAN.md`. It follows executable paths rather than relying on filenames or comments. No paid-provider calls were made and `backend/.env` was not read.

## Classification key

- **IMPLEMENTED**: the intended path exists and was verified by code tracing, automated tests, a local smoke check, or a build.
- **PARTIAL**: a usable path exists, but an important mode, integration, safety property, or test layer is incomplete.
- **BROKEN**: the checked-in configuration or normal path cannot work as shipped.
- **DOCUMENTED_ONLY**: described in documentation but has no corresponding implementation.
- **NOT_APPLICABLE**: not relevant to this repository.

## Architecture summary

```text
React UI
  -> frontend/src/api.js (`VITE_API_URL` or `/api`)
  -> Vite development proxy (strips `/api`)
  -> FastAPI routes and optional API-key middleware
  -> FastAPI in-process BackgroundTasks
  -> YAML attack loader
  -> Anthropic, OpenAI, Groq, or custom HTTP target
  -> configured LLM judge or heuristic fallback
  -> SQLite (WAL) for scan state, progress, findings, and summaries
  -> JSON result/history responses or an escaped HTML report
```

Configuration is loaded by `pydantic-settings` from process environment variables and `backend/.env`. Relative database paths resolve from `backend/`. The local frontend/backend contract is `/api` -> Vite -> FastAPI. The explicit offline launch adds a deterministic local target, enables private targets only for that backend process, disables provider credentials, and selects heuristic judging.

## Verification performed

- Existing services returned `200` from FastAPI `/health`, Vite `/`, and Vite-proxied `/api/health`.
- An isolated offline lifecycle completed 15 prompt-injection attacks through a real local HTTP fixture and a temporary SQLite database. Creation, progress, results, report, history, deletion, and submitted-key non-persistence all passed.
- Backend test suite: **36 passed**.
- Frontend test suite: **11 passed**.
- Backend compile check: **passed**.
- Frontend production build: **passed** with Vite 5.4.21.
- Attack library validation: **50 attacks**, **50 unique IDs**, no missing required fields.
- Optional API authentication and allowed-origin CORS behavior were verified in an isolated process with dummy credentials.

The first isolated lifecycle command exited nonzero only during temporary-directory cleanup: Windows still held the SQLite database file after all functional assertions passed. This is consistent with the database layer relying on `with connection` without explicitly closing connections; Python's SQLite connection context manager handles transactions but does not close the connection.

## Status matrix

| # | Area | Status | Actual implementation and evidence |
|---:|---|---|---|
| 1 | FastAPI startup | **IMPLEMENTED** | `uvicorn main:app` is configured in tasks, debug launches, and Railway. Lifespan initializes SQLite and marks orphaned scans interrupted. A running instance returned healthy status and TestClient startup passed. |
| 2 | Vite startup | **IMPLEMENTED** | `npm run dev` invokes Vite. Tasks and debug launches use port 5173. The running server returned the application HTML. |
| 3 | Vite `/api` proxy | **IMPLEMENTED** | `frontend/src/api.js` defaults to `/api`; Vite proxies to `127.0.0.1:8000` and strips the prefix. A live request to `/api/health` returned `200`. |
| 4 | Health endpoint | **IMPLEMENTED** | `GET /health` reports service/version, provider flags, auth, private-target setting, and selected providers. It is intentionally public. Backend tests and live checks pass. |
| 5 | Scan creation | **IMPLEMENTED** | `POST /scans` validates lengths and enum categories, stores an initial running record, returns `202` with `ScanResult`, and queues work. Invalid/empty categories return `422`; tests pass. |
| 6 | Background scan execution | **IMPLEMENTED** | FastAPI `BackgroundTasks` invokes `_run_scan_background`, creates provider clients, executes attacks sequentially, persists completion/failure, and redacts target-call exceptions. The offline lifecycle completed. It is intentionally in-process and therefore not durable across restarts. |
| 7 | Scan progress | **IMPLEMENTED** | Dedicated SQLite fields store index/name; `/progress` returns typed status/current/total/failure data with `no-store`; React polls until completed, failed, or interrupted. Tests and offline lifecycle pass. |
| 8 | Results | **PARTIAL** | Completed results persist and render with filtering/details. The UI can also route an `interrupted` scan to the results screen, where incomplete/default scores and an unusable report action can be shown. There are no component tests for terminal-state behavior. |
| 9 | HTML reports | **PARTIAL** | Completed scans return escaped HTML and incomplete scans are rejected. Tests and offline lifecycle pass. The UI opens reports with `window.open`, which cannot attach the configured API credential, so reports fail from the frontend when API auth is enabled. The generated timestamp uses local time but is labeled UTC. |
| 10 | Scan history | **PARTIAL** | SQLite-backed summaries, ordering, counts, polling, and deletion are implemented. Fetch/delete errors have no user-visible handling. `interrupted` status has no explicit label/interaction and is treated unlike `failed`. |
| 11 | Deletion | **IMPLEMENTED** | `DELETE /scans/{id}` deletes exactly one row and returns `404` when absent; backend and frontend API tests pass. Deleting a running scan does not cancel its background/provider work. |
| 12 | SQLite persistence | **PARTIAL** | Schema creation, migrations, WAL, deterministic paths, upsert, history, findings, progress, and restart recovery work. Connections are not explicitly closed, as exposed by the audit's Windows file-lock cleanup failure. A local SQLite file is also not durable on an ephemeral/multi-instance production host without a mounted volume or replacement datastore. |
| 13 | Offline fixture mode | **IMPLEMENTED** | Fixture FastAPI target, offline backend/frontend debug configurations, private-target opt-in, empty provider env overrides, heuristic judge, dedicated DB, and form quick-load exist. An isolated real-HTTP scan completed all 15 selected attacks without external calls. |
| 14 | Anthropic provider | **PARTIAL** | Async target and judge paths, configurable models, selection, and sanitized target failures are implemented. There is no successful mocked target/judge integration test for Anthropic and no live verification in this audit. Judge failures silently downgrade to heuristic evaluation. |
| 15 | OpenAI provider | **PARTIAL** | Async target and judge paths and configurable models are implemented; an OpenAI-only judge is tested. A successful target path is not tested, and judge failure silently downgrades to heuristic evaluation. |
| 16 | Groq provider | **PARTIAL** | Implemented through the OpenAI-compatible client with configurable base URL/models. Client construction, target, and judge are mocked in tests. No live verification exists, and judge failure silently downgrades to heuristic evaluation. |
| 17 | Custom HTTP targets | **IMPLEMENTED** | Sends bounded JSON POSTs, supports a bearer token without persistence, calls `raise_for_status`, validates object JSON, recognizes documented response keys, and returns sanitized operational failures. Unit tests and the real local fixture lifecycle pass. The contract is intentionally fixed rather than user-configurable. |
| 18 | SSRF protection | **PARTIAL** | HTTP(S)-only validation, hostname resolution, rejection of non-global/private/link-local addresses, and a default-off private-target override are present and tested. Validation resolves DNS separately from `httpx`, leaving a DNS-rebinding/time-of-check-to-time-of-use gap because the validated address is not pinned to the request. |
| 19 | API authentication | **PARTIAL** | Optional `PROMPTSHIELD_API_KEY` middleware accepts `X-API-Key` or bearer auth; health and OPTIONS remain public. Isolated checks passed. The React API client never sends the credential, and report navigation cannot add it, so enabling auth breaks the shipped frontend. Leaving auth disabled exposes scan creation, deletion, provider spending, and stored findings. |
| 20 | CORS | **IMPLEMENTED** | Defaults allow only both local Vite origins; configured origins are parsed from settings; methods are restricted. An allowed-origin preflight passed. Production still requires an explicit deployed origin, which deployment config does not supply. |
| 21 | Backend tests | **IMPLEMENTED** | 36 tests pass and cover the implementation plan's minimum API, persistence, progress, report, custom-target, SSRF, provider-error, Groq, and recovery cases without paid calls. Important gaps remain around auth/CORS regression, successful Anthropic/OpenAI targets, report escaping, and full background failure paths. |
| 22 | Frontend tests | **PARTIAL** | 11 Vitest API-client contract tests pass. There are no component tests for form submission, polling, failure/interrupted states, history, deletion errors, results, or report navigation, and no browser-level end-to-end suite. |
| 23 | VS Code tasks | **PARTIAL** | Install, start, fixture, test, compile, frontend build, and aggregate tasks exist. The backend background problem matcher looks for `Started server process` before `Uvicorn running on`, while Uvicorn commonly emits those in the opposite order under reload, so dependent-task readiness may never resolve correctly. |
| 24 | VS Code compound launches | **IMPLEMENTED** | Normal full-stack and three-process offline compounds exist with correct working directories, ports, interpreter paths, stop-all behavior, and offline environment isolation. Existing services prevented relaunching the exact compounds during this audit, but their constituent runtime paths were verified. |
| 25 | Production frontend build | **IMPLEMENTED** | `npm run build` completed successfully: 37 modules transformed and deployable assets emitted to `frontend/dist`. |
| 26 | Deployment configuration | **BROKEN** | Railway and Vercel files exist, but Vercel still rewrites API traffic to `https://your-backend.railway.app`. No durable production database/volume is configured, deployed CORS origin is not supplied, and the authentication/frontend contract has no deployable configuration. The checked-in deployment cannot provide a working, durable, protected product as-is. |

## Release blockers

1. **Deployment routing is still a placeholder.** The checked-in Vercel rewrite cannot reach a real backend.
2. **There is no durable production persistence plan.** File-backed SQLite on an ephemeral or horizontally scaled host can lose data and cannot safely provide one shared scan history.
3. **Production authentication has no compatible frontend path.** Enabling the server key breaks normal API calls and reports; disabling it exposes paid scan execution and destructive endpoints publicly.
4. **Judge failures can silently become heuristic results.** A provider outage, invalid judge credential, or parse failure can still produce a completed-looking scan with materially weaker evaluation.
5. **SSRF validation does not pin the validated DNS result.** A DNS-rebinding target may pass validation and resolve differently during the actual request.

## Important non-blocking issues

- Database connections should be explicitly closed; the audit observed a Windows file lock after successful isolated execution.
- Deleting a running scan does not cancel attack/provider calls and may continue spending provider quota.
- `ScanProgress` renders a failure retry button using `onNewScan`, but `App.jsx` does not pass that callback.
- Interrupted scans are not handled consistently in history/results UI.
- Production CORS depends on an operator-supplied environment value that is absent from deployment configuration.
- Backend tests meet the plan's minimum list but do not cover several release-critical integrations; frontend tests cover only the API wrapper.
- The UI always displays “SYSTEM ONLINE” without calling the health endpoint.
- Backend/report version is 1.1.0 while the frontend package/footer remains 1.0.0.
- `report.py` labels a local `datetime.now()` value as UTC.
- `requirements.txt` pins OpenAI while a stale comment calls it optional.
- `reportlab` and `python-multipart` appear unused in the inspected execution paths.

## Documentation mismatches

- README says **50+** attacks; the repository contains exactly **50**.
- README's tree lists `backend/evaluator.py`; judging is inside `backend/engine.py` and no evaluator file exists.
- README prerequisites name only Anthropic/OpenAI even though Groq is implemented.
- Offline health documentation says “both” provider flags, while health reports Anthropic, OpenAI, and Groq.
- README deployment instructions describe a deployable Railway/Vercel path, but the Vercel backend hostname remains a placeholder and persistence/auth/CORS production wiring is incomplete.
- `BACKEND_IMPLEMENTATION_PLAN.md` is mostly written as future work even though phases 1-6 are substantially implemented. Phase 7 has only partial/manual evidence and no committed end-to-end test.
- The plan's claim that full progress behavior is internally consistent is too broad because interrupted-scan UI handling and the failed-scan retry callback are incomplete.
- The plan's production-build definition is imprecise for the backend: the backend task is a compile check, not a packaged production build.
- Product version labels disagree between frontend and backend/report output.

## Recommended order of fixes

1. Decide the production topology: real backend URL, durable database/volume, single- versus multi-instance execution, and deployed CORS origin.
2. Design one compatible authentication flow for API requests and HTML report access; protect scan creation/deletion before exposing a provider-backed deployment.
3. Make judge degradation explicit: either fail the scan or surface a first-class degraded/heuristic status, and add successful provider contract tests.
4. Close SQLite connections deterministically and define running-scan deletion/cancellation semantics.
5. Close the SSRF DNS-rebinding gap without weakening private-network defaults.
6. Repair frontend terminal-state handling, report auth, retry wiring, and user-visible history/delete errors; add component and end-to-end tests.
7. Correct VS Code task readiness matching, then update README, implementation-plan status, counts, provider list, deployment steps, and version labels to match reality.

## Audit limitations

- Git status/diff could not be inspected because this workspace copy has no `.git` directory.
- Existing processes occupied ports 8000 and 5173. They were queried read-only and were not stopped or replaced.
- No real Anthropic, OpenAI, or Groq request was made, by policy.
- External Railway/Vercel deployment was not attempted. Deployment status is based on the checked-in configuration and its explicit placeholder.
