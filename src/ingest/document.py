"""
Secure document ingestion with file validation, sanitisation, and PII detection.
"""
from __future__ import annotations

import hashlib
import logging
import mimetypes
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Allowlist of permitted MIME types for uploaded documents
ALLOWED_MIME_TYPES: frozenset[str] = frozenset(
    {
        "text/plain",
        "text/markdown",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/json",
        "application/yaml",
        "text/yaml",
        "text/x-yaml",
    }
)

# Hard cap on individual document size (5 MB)
MAX_FILE_SIZE_BYTES: int = 5 * 1024 * 1024

# Regex patterns for common PII — redacted before sending to LLM
_PII_PATTERNS: list[tuple[str, str]] = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    (r"\b\d{16}\b", "[REDACTED_CARD]"),
    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b", "[REDACTED_EMAIL]"),
    (r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[REDACTED_PHONE]"),
    # IPv4
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_IP]"),
    # API keys / bearer tokens (heuristic: 32+ char hex/base64 strings)
    (r"\b[A-Za-z0-9_\-]{32,}\b", "[REDACTED_TOKEN]"),
]


@dataclass
class IngestResult:
    """Result of ingesting a single document."""

    source: str
    content: str
    sha256: str
    size_bytes: int
    mime_type: str
    pii_redactions: int = 0
    warnings: list[str] = field(default_factory=list)


class IngestError(Exception):
    """Raised when a document cannot be safely ingested."""


def ingest_file(path: str | Path) -> IngestResult:
    """
    Validate, sanitise, and read a document from disk.

    Args:
        path: Absolute or relative path to the document.

    Returns:
        IngestResult with sanitised text content.

    Raises:
        IngestError: If the file fails any security or format check.
    """
    path = Path(path).resolve()

    # --- Existence check ---
    if not path.exists():
        raise IngestError(f"File not found: {path}")
    if not path.is_file():
        raise IngestError(f"Path is not a regular file: {path}")

    # --- Size check ---
    size = path.stat().st_size
    if size == 0:
        raise IngestError("File is empty.")
    if size > MAX_FILE_SIZE_BYTES:
        raise IngestError(
            f"File size {size:,} bytes exceeds limit of {MAX_FILE_SIZE_BYTES:,} bytes."
        )

    # --- MIME type check ---
    mime_type, _ = mimetypes.guess_type(str(path))
    mime_type = mime_type or "application/octet-stream"
    if mime_type not in ALLOWED_MIME_TYPES:
        raise IngestError(
            f"Unsupported file type '{mime_type}'. "
            f"Allowed types: {', '.join(sorted(ALLOWED_MIME_TYPES))}"
        )

    # --- Read raw bytes and compute integrity hash ---
    raw_bytes = path.read_bytes()
    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # --- Decode text ---
    try:
        if mime_type == "application/pdf":
            content = _extract_pdf_text(raw_bytes)
        else:
            content = raw_bytes.decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover
        raise IngestError(f"Failed to decode file: {exc}") from exc

    # --- PII redaction ---
    content, redaction_count = _redact_pii(content)

    warnings: list[str] = []
    if redaction_count > 0:
        msg = f"{redaction_count} potential PII pattern(s) redacted before analysis."
        warnings.append(msg)
        logger.warning("PII redacted from %s: %d pattern(s)", path.name, redaction_count)

    logger.info(
        "Ingested '%s' (%d bytes, sha256=%s...)", path.name, size, sha256[:12]
    )
    return IngestResult(
        source=str(path),
        content=content,
        sha256=sha256,
        size_bytes=size,
        mime_type=mime_type,
        pii_redactions=redaction_count,
        warnings=warnings,
    )


def ingest_text(text: str, source_label: str = "<inline>") -> IngestResult:
    """
    Ingest raw text directly (e.g. from stdin or API payload).

    Applies the same PII redaction as file ingestion.
    """
    if not text or not text.strip():
        raise IngestError("Input text is empty.")

    encoded = text.encode("utf-8")
    if len(encoded) > MAX_FILE_SIZE_BYTES:
        raise IngestError("Input text exceeds maximum allowed size.")

    sha256 = hashlib.sha256(encoded).hexdigest()
    content, redaction_count = _redact_pii(text)

    warnings: list[str] = []
    if redaction_count > 0:
        warnings.append(f"{redaction_count} potential PII pattern(s) redacted.")

    return IngestResult(
        source=source_label,
        content=content,
        sha256=sha256,
        size_bytes=len(encoded),
        mime_type="text/plain",
        pii_redactions=redaction_count,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _redact_pii(text: str) -> tuple[str, int]:
    """Apply all PII regex patterns and return (redacted_text, count)."""
    total_replacements = 0
    for pattern, replacement in _PII_PATTERNS:
        text, n = re.subn(pattern, replacement, text, flags=re.IGNORECASE)
        total_replacements += n
    return text, total_replacements


def _extract_pdf_text(raw_bytes: bytes) -> str:  # pragma: no cover
    """
    Extract text from a PDF.  Requires pypdf to be installed.
    Falls back to a placeholder if not available.
    """
    try:
        import io
        import pypdf  # type: ignore

        reader = pypdf.PdfReader(io.BytesIO(raw_bytes))
        pages = [page.extract_text() or "" for page in reader.pages]
        return "\n\n".join(pages)
    except ImportError:
        logger.warning("pypdf not installed — PDF text extraction unavailable.")
        return "[PDF content could not be extracted. Install pypdf to enable PDF support.]"
