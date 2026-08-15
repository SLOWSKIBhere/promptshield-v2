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
- An isolated offline lifecycle completed 15 prompt-injection attacks through a real local HTTP fixture and a temporary SQLite database. Creation, progress, results, report, history, and deletion all passed.
- Backend test suite: **64 passed**. Follow-up regressions cover reflected-key redaction before serialization/truncation (including metadata, marker, and boundary collisions) and through persistence/reporting, redacted validation errors, bounded/uncompressed custom responses, judge role separation/schema validation, DNS/HTTP timeouts and redirect behavior, exact OWASP 2026 corpus mappings, report escaping, offline-fixture compatibility, log redaction, and background setup failure.
- Frontend test suite: **17 passed**, including terminal-status routing, the unconditional evaluation disclaimer, and the complete OWASP 2026 risk list/mapped-risk set.
- Backend compile check: **passed**.
- Frontend production build: **passed** with Vite 5.4.21.
- Attack library validation: **50 attacks**, **50 unique IDs**, no missing required fields.
- Optional API authentication and allowed-origin CORS behavior were verified in an isolated process with dummy credentials.
- The repository has no checked-in GitHub Actions workflow. The former README example that interpolated an arbitrary prompt directly into shell-built JSON has been removed; the current README requires a JSON-aware encoder if automation is added.

## Claims and security-boundary reconciliation

- The five selectable values are internal attack families, not five OWASP risks. All 50 checked-in cases now use the current OWASP GenAI LLM Top 10 2026 references: 38 map to LLM01 Prompt Injection, 2 to LLM02 Sensitive Information Disclosure, and 10 to LLM08 Hidden Context Exposure.
- The `multi_turn` family contains eight independent, single-message conversation-claim simulations. No conversational state or prior model response is carried between cases.
- Target output is untrusted evidence for a probabilistic LLM judge. It is JSON-encoded under a higher-priority evaluator instruction and judge output is schema-validated, but real-model prompt-injection resistance is not established.
- Reports escape rendered prompt, target, finding, and judge text. Scores, grades, and flags are automated evaluation signals for this corpus and judge, not proof, conformance, or security certification.
- Custom endpoint redirects are disabled. DNS preflight rejects non-global addresses and now runs off the event loop with a five-second deadline, but the validated address is not pinned to the HTTP connection; DNS rebinding remains unresolved.
- Submitted target keys are not fields in the persistence model. Exact appearances in persisted metadata and exact target reflections are redacted before judging/storage; transformed or encoded variants and infrastructure outside PromptShield remain outside that guarantee.
- Each request is capped at five unique families (50 target calls and normally 50 judge calls), but aggregate request rate and provider spend remain unbounded because there is no admission, quota, or rate control.
- Custom responses must be uncompressed and are streamed with a 1,000,000-byte body cap and a 2,000-character judged/stored-value cap. Client/operation timeouts exist, but there is no hard scan-wide deadline.
- YAML loading uses `yaml.safe_load`, API family selection is enum-constrained, and request/persisted SQL values use SQLite placeholders.
- Validation and background failures return sanitized field errors, static failure details, or exception class names rather than submitted values or traces. Provider/infrastructure behavior outside the application was not live-tested.

The first isolated lifecycle command exited nonzero only during temporary-directory cleanup: Windows still held the SQLite database file after all functional assertions passed. This is consistent with the database layer relying on `with connection` without explicitly closing connections; Python's SQLite connection context manager handles transactions but does not close the connection.

## Status matrix

| # | Area | Status | Actual implementation and evidence |
|---:|---|---|---|
| 1 | FastAPI startup | **IMPLEMENTED** | `uvicorn main:app` is configured in tasks, debug launches, and Railway. Lifespan initializes SQLite and marks orphaned scans interrupted. A running instance returned healthy status and TestClient startup passed. |
| 2 | Vite startup | **IMPLEMENTED** | `npm run dev` invokes Vite. Tasks and debug launches use port 5173. The running server returned the application HTML. |
| 3 | Vite `/api` proxy | **IMPLEMENTED** | `frontend/src/api.js` defaults to `/api`; Vite proxies to `127.0.0.1:8000` and strips the prefix. A live request to `/api/health` returned `200`. |
| 4 | Health endpoint | **IMPLEMENTED** | `GET /health` reports service/version, provider flags, auth, private-target setting, and selected providers. It is intentionally public. Backend tests and live checks pass. |
| 5 | Scan creation | **IMPLEMENTED** | `POST /scans` validates lengths, enum categories, a five-family maximum, and uniqueness; stores an initial running record; returns `202`; and queues work. Validation responses omit submitted input values. Tests pass. |
| 6 | Background scan execution | **IMPLEMENTED** | FastAPI `BackgroundTasks` invokes `_run_scan_background`, creates provider clients inside terminal-state handling, executes attacks sequentially, and persists completion/failure. Target and unexpected failures expose only sanitized reasons/types. The offline lifecycle completed. It remains in-process and is not durable across restarts. |
| 7 | Scan progress | **IMPLEMENTED** | Dedicated SQLite fields store index/name; `/progress` returns typed status/current/total/failure data with `no-store`; React uses single-flight polling with a request deadline and abort cleanup until completed, failed, or interrupted. Tests and offline lifecycle pass. |
| 8 | Results | **IMPLEMENTED** | Completed results persist and render with filtering/details. Only completed scans route to results; running, failed, and interrupted rows route through the progress/terminal view. A pure routing regression covers every status. |
| 9 | HTML reports | **PARTIAL** | Completed scans return HTML with regression-tested escaping, a real UTC timestamp, and an explicit non-certification disclaimer; incomplete scans are rejected. The UI opens reports with `window.open`, which cannot attach the configured API credential, so reports still fail from the frontend when API auth is enabled. |
| 10 | Scan history | **PARTIAL** | SQLite-backed summaries, ordering, counts, polling, deletion, and explicit failed/interrupted interactions are implemented. Fetch/delete errors still have no user-visible handling. |
| 11 | Deletion | **IMPLEMENTED** | `DELETE /scans/{id}` deletes exactly one row and returns `404` when absent; backend and frontend API tests pass. Deleting a running scan does not cancel its background/provider work. |
| 12 | SQLite persistence | **PARTIAL** | Schema creation, migrations, WAL, deterministic paths, upsert, history, findings, progress, and restart recovery work. Connections are not explicitly closed, as exposed by the audit's Windows file-lock cleanup failure. A local SQLite file is also not durable on an ephemeral/multi-instance production host without a mounted volume or replacement datastore. |
| 13 | Offline fixture mode | **IMPLEMENTED** | Fixture FastAPI target, offline backend/frontend debug configurations, private-target opt-in, empty provider env overrides, heuristic judge, dedicated DB, and form quick-load exist. An isolated real-HTTP scan completed all 15 selected attacks without external calls. |
| 14 | Anthropic provider | **PARTIAL** | Async target/judge paths, configurable models, selection, explicit client timeout, sanitized target failures, and system/evidence judge separation are implemented. The judge path is mocked successfully; the target path and live service remain unverified. Judge failures downgrade to a labeled heuristic result. |
| 15 | OpenAI provider | **PARTIAL** | Async target/judge paths, configurable models, explicit client timeout, and separated judge roles are implemented and the judge is mocked. A successful target path and live service remain unverified; judge failure downgrades to a labeled heuristic result. |
| 16 | Groq provider | **PARTIAL** | Implemented through the OpenAI-compatible client with configurable base URL/models, explicit timeout, and separated judge roles. Client construction, target, and judge are mocked. No live verification exists; judge failure downgrades to a labeled heuristic result. |
| 17 | Custom HTTP targets | **IMPLEMENTED** | Sends bounded JSON POSTs, requires HTTPS when a bearer token is supplied, explicitly disables redirects, requests/requires identity encoding, streams at most 1,000,000 response bytes, caps judged/stored values at 2,000 characters, validates object JSON, recognizes documented response keys, and returns sanitized failures. Submitted keys are not modeled for persistence, and exact appearances/reflections are redacted before judging/storage; transformed values remain an acknowledged limitation. |
| 18 | SSRF protection | **PARTIAL** | HTTP(S)-only validation, off-event-loop hostname resolution with a five-second deadline, rejection of non-global/private/link-local addresses, explicit no-redirect behavior, and a default-off private-target override are tested. Validation still resolves DNS separately from `httpx`, leaving a DNS-rebinding/time-of-check-to-time-of-use gap because the validated address is not pinned to the request. |
| 19 | API authentication | **PARTIAL** | Optional `PROMPTSHIELD_API_KEY` middleware accepts `X-API-Key` or bearer auth; health and OPTIONS remain public. Isolated checks passed. The React API client never sends the credential, and report navigation cannot add it, so enabling auth breaks the shipped frontend. Leaving auth disabled exposes scan creation, deletion, provider spending, and stored findings. |
| 20 | CORS | **IMPLEMENTED** | Defaults allow only both local Vite origins; configured origins are parsed from settings; methods are restricted. An allowed-origin preflight passed. Production still requires an explicit deployed origin, which deployment config does not supply. |
| 21 | Backend tests | **IMPLEMENTED** | 64 tests pass without paid calls and cover API/persistence/progress/report paths, bounded/uncompressed custom targets, SSRF basics/DNS deadline, provider errors, judge schemas/role boundaries, target-key redaction, background setup failure, exact OWASP corpus mappings, and recovery. Auth/CORS and successful direct target calls still lack dedicated regressions. |
| 22 | Frontend tests | **PARTIAL** | 17 Vitest tests cover the API-client contract, terminal-status routing, unconditional result disclaimer, and exact OWASP 2026 references. Rendered form, polling, history, deletion-error, results, and report-navigation behavior still lack component/browser coverage. |
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
- There is no aggregate scan-admission, rate, quota, cancellation, or cost control; repeated requests can overlap and spend provider quota.
- Production CORS depends on an operator-supplied environment value that is absent from deployment configuration.
- Backend tests meet the plan's minimum list but do not cover several release-critical integrations; frontend tests remain narrow (API wrapper plus pure routing/reference checks).
- Backend/report/footer version is 1.1.0 while the frontend package metadata remains 1.0.0.
- `requirements.txt` pins OpenAI while a stale comment calls it optional.
- `reportlab` and `python-multipart` appear unused in the inspected execution paths.

## Documentation mismatches

- The claims audit corrected README attack counts/family terminology, multi-turn scope, all OWASP mappings to the current 2026 LLM list, provider list, offline flags, project tree, security limitations, cost behavior, result language, and deployment readiness.
- `BACKEND_IMPLEMENTATION_PLAN.md` is mostly written as future work even though phases 1-6 are substantially implemented. Phase 7 has only partial/manual evidence and no committed end-to-end test.
- The plan's production-build definition is imprecise for the backend: the backend task is a compile check, not a packaged production build.
- Product version labels disagree between frontend and backend/report output.

## Recommended order of fixes

1. Decide the production topology: real backend URL, durable database/volume, single- versus multi-instance execution, and deployed CORS origin.
2. Design one compatible authentication flow for API requests and HTML report access; protect scan creation/deletion before exposing a provider-backed deployment.
3. Make judge degradation explicit: either fail the scan or surface a first-class degraded/heuristic status, and add successful provider contract tests.
4. Close SQLite connections deterministically and define running-scan deletion/cancellation semantics.
5. Close the SSRF DNS-rebinding gap without weakening private-network defaults.
6. Repair report authentication and user-visible history/delete errors; add component and end-to-end tests.
7. Correct VS Code task readiness matching, then update implementation-plan status and remaining version labels.

## Audit limitations

- The initial truth-audit pass predated repository setup. The follow-up security-claims pass ran on `fix/security-claims-audit` with git status/diff inspection.
- Existing processes occupied ports 8000 and 5173. They were queried read-only and were not stopped or replaced.
- No real Anthropic, OpenAI, or Groq request was made, by policy.
- External Railway/Vercel deployment was not attempted. Deployment status is based on the checked-in configuration and its explicit placeholder.
