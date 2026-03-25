"""Unit tests for the ingest module."""
import hashlib
import tempfile
from pathlib import Path

import pytest

from src.ingest.document import (
    IngestError,
    IngestResult,
    MAX_FILE_SIZE_BYTES,
    ingest_file,
    ingest_text,
    _redact_pii,
)


class TestIngestText:
    def test_basic_text(self):
        result = ingest_text("This is a simple model card document.")
        assert isinstance(result, IngestResult)
        assert result.mime_type == "text/plain"
        assert result.pii_redactions == 0
        assert result.sha256

    def test_sha256_is_stable(self):
        text = "Hello, world!"
        r1 = ingest_text(text)
        r2 = ingest_text(text)
        assert r1.sha256 == r2.sha256

    def test_sha256_correct(self):
        text = "test content"
        result = ingest_text(text)
        expected = hashlib.sha256(text.encode()).hexdigest()
        assert result.sha256 == expected

    def test_empty_text_raises(self):
        with pytest.raises(IngestError, match="empty"):
            ingest_text("")

    def test_whitespace_only_raises(self):
        with pytest.raises(IngestError, match="empty"):
            ingest_text("   \n\t  ")

    def test_pii_email_redacted(self):
        result = ingest_text("Contact admin@example.com for support.")
        assert "admin@example.com" not in result.content
        assert "[REDACTED_EMAIL]" in result.content
        assert result.pii_redactions >= 1

    def test_pii_phone_redacted(self):
        result = ingest_text("Call us at 555-123-4567 for help.")
        assert "555-123-4567" not in result.content
        assert result.pii_redactions >= 1

    def test_pii_ssn_redacted(self):
        result = ingest_text("SSN: 123-45-6789")
        assert "123-45-6789" not in result.content
        assert result.pii_redactions >= 1

    def test_source_label_preserved(self):
        result = ingest_text("content", source_label="my-doc")
        assert result.source == "my-doc"

    def test_oversized_text_raises(self):
        big_text = "x" * (MAX_FILE_SIZE_BYTES + 1)
        with pytest.raises(IngestError, match="exceeds"):
            ingest_text(big_text)


class TestIngestFile:
    def test_valid_txt_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("This is a valid model card for testing.", encoding="utf-8")
        result = ingest_file(f)
        assert result.content == "This is a valid model card for testing."
        assert result.size_bytes == f.stat().st_size

    def test_valid_markdown_file(self, tmp_path):
        f = tmp_path / "model_card.md"
        f.write_text("# Model Card\n\nThis model does X.", encoding="utf-8")
        result = ingest_file(f)
        assert "Model Card" in result.content

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(IngestError, match="not found"):
            ingest_file(tmp_path / "nonexistent.txt")

    def test_empty_file_raises(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        with pytest.raises(IngestError, match="empty"):
            ingest_file(f)

    def test_disallowed_extension_raises(self, tmp_path):
        f = tmp_path / "script.exe"
        f.write_bytes(b"MZ\x90\x00")
        with pytest.raises(IngestError, match="Unsupported"):
            ingest_file(f)

    def test_oversized_file_raises(self, tmp_path):
        f = tmp_path / "big.txt"
        f.write_bytes(b"x" * (MAX_FILE_SIZE_BYTES + 1))
        with pytest.raises(IngestError, match="exceeds"):
            ingest_file(f)

    def test_directory_raises(self, tmp_path):
        with pytest.raises(IngestError, match="not a regular file"):
            ingest_file(tmp_path)

    def test_pii_redacted_in_file(self, tmp_path):
        f = tmp_path / "doc.txt"
        f.write_text("Contact: user@corp.com — SSN 123-45-6789", encoding="utf-8")
        result = ingest_file(f)
        assert "user@corp.com" not in result.content
        assert result.pii_redactions >= 1


class TestPIIRedaction:
    def test_no_pii(self):
        text, count = _redact_pii("This document contains no PII.")
        assert count == 0
        assert text == "This document contains no PII."

    def test_multiple_emails_redacted(self):
        text, count = _redact_pii("alice@a.com and bob@b.org are contacts.")
        assert "alice@a.com" not in text
        assert "bob@b.org" not in text
        assert count >= 2

    def test_ip_address_redacted(self):
        text, count = _redact_pii("Server IP: 192.168.1.100")
        assert "192.168.1.100" not in text
        assert count >= 1

    def test_idempotent(self):
        text = "Test doc with email user@example.com"
        t1, c1 = _redact_pii(text)
        t2, c2 = _redact_pii(t1)
        # Second pass should not find new PII in redacted text
        assert t1 == t2
