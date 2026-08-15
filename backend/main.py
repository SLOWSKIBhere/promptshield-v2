"""
main.py — FastAPI application

Fixes applied:
  BUG-07: Progress now reads from DB (not in-memory dict) — survives restarts
  BUG-08: CORS reads from ALLOWED_ORIGINS env var — no more wildcard in prod
  BUG-09: Proper logging with logging module — errors visible in Railway logs
  BUG-10: Removed duplicate get_connection import inside delete_scan
  BUG-11: ScanTarget field validation handles oversized inputs (via models.py)
  BUG-12: API key authentication middleware via X-API-Key header
  BUG-19: datetime.now(timezone.utc) replaces deprecated utcnow()
"""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List

import anthropic
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

try:
    import openai as openai_lib
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from models import ScanTarget, ScanResult, ScanSummary, ScanProgress, ScanStatus
from database import (
    init_db, save_scan, get_scan, list_scans, delete_scan as db_delete_scan,
    mark_orphaned_scans_interrupted,
)
from engine import TargetCallError, run_scan
from report import generate_html_report
from config import settings

# ─── Logging ────────────────────────────────────────────────────────────────
# BUG-09 FIX: structured logging — visible in Railway/Heroku log streams
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("promptshield")


# ─── Lifespan ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    interrupted = mark_orphaned_scans_interrupted()
    logger.info("PromptShield API started — DB initialized")
    if interrupted:
        logger.warning("Marked %s orphaned scan(s) as interrupted", interrupted)
    logger.info("Anthropic API: %s", "configured" if settings.anthropic_api_key else "NOT SET")
    logger.info("OpenAI API: %s", "configured" if settings.openai_api_key else "not set")
    logger.info("Groq API: %s", "configured" if settings.groq_api_key else "not set")
    yield
    logger.info("PromptShield API shutting down")


app = FastAPI(
    title="PromptShield API",
    description="LLM Security Scanner — OWASP LLM Top 10",
    version="1.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,
)

# ─── CORS ────────────────────────────────────────────────────────────────────
# BUG-08 FIX: Read from env var — wildcard only in local dev
_cors_origins = settings.cors_origins
if _cors_origins == ["*"]:
    logger.warning("CORS: allow_origins=* — set ALLOWED_ORIGINS env var in production")
else:
    logger.info(f"CORS: restricted to {_cors_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# ─── API Key Auth Middleware ──────────────────────────────────────────────────
# BUG-12 FIX: Optional API key protection — set PROMPTSHIELD_API_KEY to enable
_SERVER_API_KEY = settings.promptshield_api_key

@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    # Skip auth for health check and OPTIONS
    if request.url.path in ("/health", "/") or request.method == "OPTIONS":
        return await call_next(request)

    if _SERVER_API_KEY:
        provided_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").removeprefix("Bearer ")
        if provided_key != _SERVER_API_KEY:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or missing API key. Provide via X-API-Key header."},
            )
    return await call_next(request)


# ─── Client Factories ────────────────────────────────────────────────────────

def _get_anthropic_client() -> anthropic.AsyncAnthropic | None:
    key = settings.anthropic_api_key
    if key:
        return anthropic.AsyncAnthropic(api_key=key)
    return None


def _get_openai_client(user_api_key: str | None = None):
    if not OPENAI_AVAILABLE:
        return None
    key = user_api_key or settings.openai_api_key
    if key:
        return openai_lib.AsyncOpenAI(api_key=key)
    return None


def _get_groq_client():
    if not OPENAI_AVAILABLE or not settings.groq_api_key:
        return None
    return openai_lib.AsyncOpenAI(
        api_key=settings.groq_api_key,
        base_url=settings.groq_base_url,
    )


# ─── Background Scan Worker ──────────────────────────────────────────────────

async def _run_scan_background(scan_id: str, target: ScanTarget) -> None:
    anthropic_client = _get_anthropic_client()
    openai_client = _get_openai_client()
    groq_client = _get_groq_client()

    selected_target_provider = settings.target_provider
    if selected_target_provider == "auto":
        selected_target_provider = (
            "anthropic" if anthropic_client
            else "openai" if openai_client
            else "groq"
        )

    if not target.endpoint_url and not anthropic_client and not openai_client and not groq_client:
        scan = get_scan(scan_id)
        if scan:
            scan.status = ScanStatus.FAILED
            scan.summary = "No AI provider configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GROQ_API_KEY."
            scan.failure_reason = scan.summary
            scan.current_attack_name = "Failed"
            scan.completed_at = datetime.now(timezone.utc)
            save_scan(scan)
        logger.error(f"Scan {scan_id}: no AI provider configured")
        return

    # BUG-07 FIX: Progress stored in DB, not in-memory dict
    # The progress endpoint now reads current attack count from the DB directly.
    async def progress_callback(current: int, total: int, attack_name: str) -> None:
        scan = get_scan(scan_id)
        if scan:
            scan.total_attacks = total
            scan.current_attack_index = current
            scan.current_attack_name = attack_name
            save_scan(scan)

    try:
        logger.info(f"Scan {scan_id}: starting ({len(target.categories or [])} categories)")
        results, score, grade, summary = await run_scan(
            scan_id=scan_id,
            system_prompt=target.system_prompt,
            feature_description=target.feature_description,
            categories=[category.value for category in target.categories],
            endpoint_url=target.endpoint_url,
            api_key=target.api_key,
            model_name=target.model_name or (
                settings.anthropic_target_model
                if selected_target_provider == "anthropic"
                else settings.openai_target_model
                if selected_target_provider == "openai"
                else settings.groq_target_model
            ),
            anthropic_client=anthropic_client,
            openai_client=openai_client,
            groq_client=groq_client,
            progress_callback=progress_callback,
        )

        scan = get_scan(scan_id)
        if scan:
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_attacks = len(results)
            scan.exploited_count = sum(1 for r in results if r.is_exploited)
            scan.overall_score = score
            scan.letter_grade = grade
            scan.findings = results
            scan.summary = summary
            scan.current_attack_index = len(results)
            scan.current_attack_name = "Complete"
            scan.failure_reason = None
            save_scan(scan)

        logger.info(
            f"Scan {scan_id}: completed — {len(results)} attacks, "
            f"{sum(1 for r in results if r.is_exploited)} exploited, "
            f"grade={grade}, score={score}"
        )

    except Exception as e:
        # BUG-09 FIX: Log with full traceback — visible in Railway/Render logs
        logger.exception(f"Scan {scan_id}: FAILED with exception")
        scan = get_scan(scan_id)
        if scan:
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.now(timezone.utc)
            scan.failure_reason = (
                f"Scan failed: {e}" if isinstance(e, TargetCallError)
                else f"Scan failed: {type(e).__name__}"
            )
            scan.summary = scan.failure_reason
            scan.current_attack_name = "Failed"
            save_scan(scan)


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "1.1.0",
        "anthropic_configured": bool(settings.anthropic_api_key),
        "openai_configured": bool(settings.openai_api_key),
        "groq_configured": bool(settings.groq_api_key),
        "auth_enabled": bool(_SERVER_API_KEY),
        "allow_private_targets": settings.allow_private_targets,
        "judge_provider": settings.judge_provider,
        "target_provider": settings.target_provider,
    }


@app.get("/scans", response_model=List[ScanSummary])
async def list_all_scans():
    return list_scans()


@app.post("/scans", response_model=ScanResult, status_code=202)
async def create_scan(target: ScanTarget, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    scan = ScanResult(
        scan_id=scan_id,
        scan_name=target.scan_name,
        feature_description=target.feature_description,
        system_prompt_preview=target.system_prompt[:300] + ("..." if len(target.system_prompt) > 300 else ""),
        started_at=now,
        status=ScanStatus.RUNNING,
    )
    save_scan(scan)
    background_tasks.add_task(_run_scan_background, scan_id, target)
    logger.info(f"Scan {scan_id} created: '{target.scan_name}'")
    return scan


@app.get("/scans/{scan_id}", response_model=ScanResult)
async def get_scan_result(scan_id: str, response: Response):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    if scan.status == ScanStatus.RUNNING:
        response.headers["Cache-Control"] = "no-store"
    return scan


@app.get("/scans/{scan_id}/progress", response_model=ScanProgress)
async def get_scan_progress(scan_id: str, response: Response):
    """
    BUG-07 FIX: Progress is read from DB summary field — survives process restarts.
    Format stored during scan: '[PROGRESS:15/50] Attack Name'
    """
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    response.headers["Cache-Control"] = "no-store"
    current = scan.current_attack_index
    total = scan.total_attacks
    current_attack = scan.current_attack_name or "Initializing..."

    return {
        "scan_id": scan_id,
        "status": scan.status,
        "current": current,
        "total": total,
        "current_attack": current_attack,
        "failure_reason": scan.failure_reason,
    }


@app.get("/scans/{scan_id}/report", response_class=HTMLResponse)
async def get_scan_report(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail=f"Scan is not yet completed (status: {scan.status})")
    return generate_html_report(scan)


@app.delete("/scans/{scan_id}")
async def delete_scan_endpoint(scan_id: str):
    # BUG-10 FIX: No duplicate import — using imported db_delete_scan
    deleted = db_delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    logger.info(f"Scan {scan_id} deleted")
    return {"deleted": scan_id}
