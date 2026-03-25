"""
FastAPI REST API for ai-policy-auditor.

Security controls:
- API key authentication via X-API-Key header.
- Rate limiting (slowapi) — 10 audits/minute per IP.
- File size and type validation delegated to ingest module.
- No raw stack traces in error responses.
- Request IDs for audit log correlation.
"""
from __future__ import annotations

import logging
import os
import secrets
import uuid
from typing import Annotated

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Policy Auditor",
    description="Audit AI documentation against NIST AI RMF, EU AI Act, and ISO 42001.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
)

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler  # type: ignore
    from slowapi.errors import RateLimitExceeded  # type: ignore
    from slowapi.util import get_remote_address  # type: ignore

    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    _RATE_LIMIT = "10/minute"
    _SLOWAPI_AVAILABLE = True
except ImportError:
    _SLOWAPI_AVAILABLE = False
    logger.warning("slowapi not installed — rate limiting disabled.")

    class _NoopLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator

    limiter = _NoopLimiter()  # type: ignore
    _RATE_LIMIT = "unlimited"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

_VALID_API_KEY = os.environ.get("AUDITOR_API_KEY", "")


def _require_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
    if not _VALID_API_KEY:
        return  # Auth disabled if no key configured
    if not x_api_key or not secrets.compare_digest(x_api_key, _VALID_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )


AuthDep = Annotated[None, Depends(_require_api_key)]


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class AuditTextRequest(BaseModel):
    text: str = Field(..., min_length=10, max_length=100_000)
    framework: str = Field("nist_ai_rmf", pattern="^(nist_ai_rmf|eu_ai_act|iso_42001)$")
    strategy: str = Field("auto", pattern="^(auto|keyword|semantic)$")
    enrich: bool = Field(True, description="Enable LLM enrichment via Claude API.")


class AuditResponse(BaseModel):
    request_id: str
    framework_id: str
    framework_name: str
    overall_coverage_pct: float
    risk_score: int
    risk_label: str
    total_controls: int
    addressed_count: int
    partial_count: int
    missing_count: int
    executive_summary: str
    warnings: list[str]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/audit/text", response_model=AuditResponse, status_code=200)
@limiter.limit(_RATE_LIMIT)
async def audit_text(
    request: Request,
    body: AuditTextRequest,
    _auth: AuthDep,
) -> AuditResponse:
    """
    Audit plain text content (e.g. a model card or policy document) against
    the specified framework.
    """
    request_id = str(uuid.uuid4())
    logger.info("audit/text request_id=%s framework=%s", request_id, body.framework)

    try:
        result = await _run_audit_text(body, request_id)
    except Exception as exc:
        logger.error("Audit failed request_id=%s error=%s", request_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Audit processing failed.") from exc

    return _result_to_response(result, request_id)


@app.post("/audit/file", response_model=AuditResponse, status_code=200)
@limiter.limit(_RATE_LIMIT)
async def audit_file(
    request: Request,
    file: UploadFile = File(...),
    framework: str = "nist_ai_rmf",
    strategy: str = "auto",
    enrich: bool = True,
    _auth: AuthDep = None,
) -> AuditResponse:
    """
    Audit an uploaded document file (.txt, .md, .pdf, .docx) against
    the specified framework.
    """
    request_id = str(uuid.uuid4())
    logger.info(
        "audit/file request_id=%s filename=%s framework=%s",
        request_id, file.filename, framework,
    )

    try:
        content_bytes = await file.read()
        result = await _run_audit_bytes(
            content_bytes, file.filename or "upload", framework, strategy, enrich, request_id
        )
    except Exception as exc:
        logger.error("File audit failed request_id=%s error=%s", request_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Audit processing failed.") from exc

    return _result_to_response(result, request_id)


# ---------------------------------------------------------------------------
# Internal audit runners (sync work delegated from async handlers)
# ---------------------------------------------------------------------------

async def _run_audit_text(body: AuditTextRequest, request_id: str):
    from src.ingest.document import ingest_text
    from src.frameworks.loader import load_framework
    from src.mapper.control_mapper import map_document
    from src.analyser.gap_analyser import analyse
    from src.llm.enricher import enrich_audit_result

    ingest = ingest_text(body.text, source_label=f"api-text/{request_id}")
    framework = load_framework(body.framework)
    matches = map_document(ingest.content, framework, strategy=body.strategy)
    result = analyse(
        matches, framework,
        document_source=ingest.source,
        document_sha256=ingest.sha256,
        pii_redactions=ingest.pii_redactions,
        warnings=ingest.warnings,
    )
    if body.enrich:
        result = enrich_audit_result(result, ingest.content[:3000])
    return result


async def _run_audit_bytes(
    content_bytes: bytes,
    filename: str,
    framework_id: str,
    strategy: str,
    enrich: bool,
    request_id: str,
):
    import tempfile
    from pathlib import Path
    from src.ingest.document import ingest_file
    from src.frameworks.loader import load_framework
    from src.mapper.control_mapper import map_document
    from src.analyser.gap_analyser import analyse
    from src.llm.enricher import enrich_audit_result

    suffix = Path(filename).suffix or ".txt"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content_bytes)
        tmp_path = tmp.name

    ingest = ingest_file(tmp_path)
    Path(tmp_path).unlink(missing_ok=True)

    framework = load_framework(framework_id)
    matches = map_document(ingest.content, framework, strategy=strategy)
    result = analyse(
        matches, framework,
        document_source=filename,
        document_sha256=ingest.sha256,
        pii_redactions=ingest.pii_redactions,
        warnings=ingest.warnings,
    )
    if enrich:
        result = enrich_audit_result(result, ingest.content[:3000])
    return result


def _result_to_response(result, request_id: str) -> AuditResponse:
    return AuditResponse(
        request_id=request_id,
        framework_id=result.framework_id,
        framework_name=result.framework_name,
        overall_coverage_pct=result.overall_coverage_pct,
        risk_score=result.risk_score,
        risk_label=result.risk_label,
        total_controls=result.total_controls,
        addressed_count=result.addressed_count,
        partial_count=result.partial_count,
        missing_count=result.missing_count,
        executive_summary=result.executive_summary,
        warnings=result.warnings,
    )
