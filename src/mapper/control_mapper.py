"""
Maps document content to framework controls using keyword and semantic matching.

Two strategies are available:
  1. KeywordMapper  — fast, zero-dependency TF-IDF-style keyword scoring.
  2. SemanticMapper — higher quality using sentence-transformers (optional dep).

The public `map_document` function auto-selects the best available strategy.
"""
from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Protocol

from src.frameworks.loader import Control, Framework

logger = logging.getLogger(__name__)


@dataclass
class ControlMatch:
    control: Control
    score: float          # 0.0 – 1.0 relevance score
    matched_keywords: list[str] = field(default_factory=list)
    evidence_snippets: list[str] = field(default_factory=list)


class _MapperProtocol(Protocol):
    def match(self, text: str, controls: list[Control]) -> list[ControlMatch]:
        ...


# ---------------------------------------------------------------------------
# Keyword mapper (always available)
# ---------------------------------------------------------------------------

class KeywordMapper:
    """
    Scores each control against the document by counting keyword hits.
    Normalises by document length to avoid penalising short docs.
    Extracts short evidence snippets around each hit.
    """

    SNIPPET_RADIUS = 120  # characters around a match to extract as evidence

    def match(self, text: str, controls: list[Control]) -> list[ControlMatch]:
        text_lower = text.lower()
        words = re.findall(r"\b\w+\b", text_lower)
        total_words = max(len(words), 1)

        results = []
        for control in controls:
            matched_kws = []
            snippets: list[str] = []

            for kw in control.keywords:
                kw_lower = kw.lower()
                if kw_lower in text_lower:
                    matched_kws.append(kw)
                    snippet = self._extract_snippet(text, kw_lower)
                    if snippet and snippet not in snippets:
                        snippets.append(snippet)

            # Score: fraction of keywords matched, log-normalised
            if matched_kws:
                raw = len(matched_kws) / max(len(control.keywords), 1)
                score = min(raw * math.log(1 + total_words / 100), 1.0)
            else:
                score = 0.0

            results.append(
                ControlMatch(
                    control=control,
                    score=round(score, 4),
                    matched_keywords=matched_kws,
                    evidence_snippets=snippets[:3],
                )
            )

        return sorted(results, key=lambda m: m.score, reverse=True)

    def _extract_snippet(self, text: str, keyword: str) -> str | None:
        idx = text.lower().find(keyword)
        if idx == -1:
            return None
        start = max(0, idx - self.SNIPPET_RADIUS)
        end = min(len(text), idx + len(keyword) + self.SNIPPET_RADIUS)
        snippet = text[start:end].strip()
        # Clean whitespace
        snippet = re.sub(r"\s+", " ", snippet)
        return f"...{snippet}..."


# ---------------------------------------------------------------------------
# Semantic mapper (requires sentence-transformers)
# ---------------------------------------------------------------------------

class SemanticMapper:
    """
    Uses sentence-transformers cosine similarity for control matching.
    Falls back to KeywordMapper if the library is unavailable.
    """

    _model = None

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._keyword_fallback = KeywordMapper()

    def _load_model(self):  # pragma: no cover
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer  # type: ignore
                self.__class__._model = SentenceTransformer(self.model_name)
                logger.info("Loaded sentence-transformers model '%s'", self.model_name)
            except ImportError:
                logger.warning(
                    "sentence-transformers not installed. Falling back to keyword matching."
                )

    def match(self, text: str, controls: list[Control]) -> list[ControlMatch]:  # pragma: no cover
        self._load_model()
        if self._model is None:
            return self._keyword_fallback.match(text, controls)

        import numpy as np  # type: ignore

        # Embed document (use first 512 tokens worth of text)
        doc_embedding = self._model.encode([text[:4000]], convert_to_numpy=True)[0]

        # Embed control descriptions
        control_texts = [
            f"{c.name}. {c.description} Keywords: {', '.join(c.keywords)}"
            for c in controls
        ]
        control_embeddings = self._model.encode(control_texts, convert_to_numpy=True)

        results = []
        kw_mapper = KeywordMapper()
        kw_results = {m.control.id: m for m in kw_mapper.match(text, controls)}

        for i, control in enumerate(controls):
            cos_sim = float(
                np.dot(doc_embedding, control_embeddings[i])
                / (np.linalg.norm(doc_embedding) * np.linalg.norm(control_embeddings[i]) + 1e-9)
            )
            score = max(0.0, min(cos_sim, 1.0))

            kw_match = kw_results.get(control.id)
            results.append(
                ControlMatch(
                    control=control,
                    score=round(score, 4),
                    matched_keywords=kw_match.matched_keywords if kw_match else [],
                    evidence_snippets=kw_match.evidence_snippets if kw_match else [],
                )
            )

        return sorted(results, key=lambda m: m.score, reverse=True)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def map_document(
    text: str,
    framework: Framework,
    strategy: str = "auto",
    coverage_threshold: float = 0.15,
) -> list[ControlMatch]:
    """
    Map document text to all controls in the given framework.

    Args:
        text: Sanitised document content.
        framework: Loaded Framework object.
        strategy: 'keyword', 'semantic', or 'auto' (tries semantic, falls back).
        coverage_threshold: Minimum score to consider a control "addressed".

    Returns:
        List of ControlMatch objects sorted by score descending.
    """
    controls = framework.all_controls
    if not controls:
        return []

    mapper: _MapperProtocol
    if strategy == "semantic":
        mapper = SemanticMapper()
    elif strategy == "keyword":
        mapper = KeywordMapper()
    else:  # auto
        mapper = SemanticMapper()  # will fall back internally if deps missing

    matches = mapper.match(text, controls)
    logger.info(
        "Mapped %d controls for framework '%s' (threshold=%.2f)",
        len(matches),
        framework.id,
        coverage_threshold,
    )
    return matches
