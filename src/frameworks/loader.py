"""
Load and validate compliance framework definitions from YAML files.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml

logger = logging.getLogger(__name__)

FRAMEWORKS_DIR = Path(__file__).parent

SeverityLevel = Literal["HIGH", "MEDIUM", "LOW"]

AVAILABLE_FRAMEWORKS = {
    "nist_ai_rmf": FRAMEWORKS_DIR / "nist_ai_rmf.yaml",
    "eu_ai_act": FRAMEWORKS_DIR / "eu_ai_act.yaml",
    "iso_42001": FRAMEWORKS_DIR / "iso_42001.yaml",
}


@dataclass
class Control:
    id: str
    name: str
    description: str
    keywords: list[str]
    severity: SeverityLevel
    article: str | None = None


@dataclass
class Category:
    id: str
    name: str
    description: str
    controls: list[Control] = field(default_factory=list)


@dataclass
class Framework:
    id: str
    name: str
    version: str
    url: str
    categories: list[Category] = field(default_factory=list)

    @property
    def all_controls(self) -> list[Control]:
        return [c for cat in self.categories for c in cat.controls]

    @property
    def control_count(self) -> int:
        return len(self.all_controls)


class FrameworkLoadError(Exception):
    pass


def load_framework(framework_id: str) -> Framework:
    """
    Load a framework by ID.

    Args:
        framework_id: One of 'nist_ai_rmf', 'eu_ai_act', 'iso_42001'.

    Returns:
        Parsed Framework object.

    Raises:
        FrameworkLoadError: If the framework is unknown or the YAML is invalid.
    """
    if framework_id not in AVAILABLE_FRAMEWORKS:
        raise FrameworkLoadError(
            f"Unknown framework '{framework_id}'. "
            f"Available: {', '.join(AVAILABLE_FRAMEWORKS)}"
        )

    path = AVAILABLE_FRAMEWORKS[framework_id]
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise FrameworkLoadError(f"Failed to load {path}: {exc}") from exc

    return _parse_framework(raw)


def load_all_frameworks() -> list[Framework]:
    """Load all bundled frameworks."""
    frameworks = []
    for fid in AVAILABLE_FRAMEWORKS:
        try:
            frameworks.append(load_framework(fid))
        except FrameworkLoadError as exc:
            logger.error("Failed to load framework %s: %s", fid, exc)
    return frameworks


def _parse_framework(raw: dict) -> Framework:
    meta = raw.get("framework", {})
    categories = []
    for cat_data in raw.get("categories", []):
        controls = []
        for ctrl_data in cat_data.get("controls", []):
            controls.append(
                Control(
                    id=ctrl_data["id"],
                    name=ctrl_data["name"],
                    description=ctrl_data["description"].strip(),
                    keywords=ctrl_data.get("keywords", []),
                    severity=ctrl_data.get("severity", "MEDIUM"),
                    article=ctrl_data.get("article"),
                )
            )
        categories.append(
            Category(
                id=cat_data["id"],
                name=cat_data["name"],
                description=cat_data.get("description", ""),
                controls=controls,
            )
        )
    return Framework(
        id=meta["id"],
        name=meta["name"],
        version=str(meta.get("version", "unknown")),
        url=meta.get("url", ""),
        categories=categories,
    )
