"""
ai-policy-auditor CLI

Usage examples:
  python -m src.cli audit docs/model_card.md --framework nist_ai_rmf
  python -m src.cli audit docs/model_card.md --framework eu_ai_act --no-enrich
  python -m src.cli audit docs/model_card.md --output-dir reports/
  python -m src.cli list-frameworks
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=level,
    )


def cmd_list_frameworks(_args: argparse.Namespace) -> int:
    from src.frameworks.loader import AVAILABLE_FRAMEWORKS, load_framework

    print("\nAvailable frameworks:\n")
    for fid in AVAILABLE_FRAMEWORKS:
        try:
            fw = load_framework(fid)
            print(f"  {fw.id:20s}  {fw.name} (v{fw.version}) — {fw.control_count} controls")
        except Exception as exc:
            print(f"  {fid:20s}  [ERROR: {exc}]")
    print()
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    from src.ingest.document import ingest_file, IngestError
    from src.frameworks.loader import load_framework, FrameworkLoadError
    from src.mapper.control_mapper import map_document
    from src.analyser.gap_analyser import analyse
    from src.output.reporter import generate_json_report, generate_markdown_report

    # --- Ingest ---
    try:
        ingest_result = ingest_file(args.document)
    except IngestError as exc:
        print(f"[ERROR] Ingest failed: {exc}", file=sys.stderr)
        return 2

    if ingest_result.warnings:
        for w in ingest_result.warnings:
            print(f"[WARN] {w}", file=sys.stderr)

    # --- Load framework ---
    try:
        framework = load_framework(args.framework)
    except FrameworkLoadError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    print(
        f"[INFO] Auditing '{Path(args.document).name}' against "
        f"{framework.name} ({framework.control_count} controls)..."
    )

    # --- Map and analyse ---
    matches = map_document(
        ingest_result.content,
        framework,
        strategy=args.strategy,
    )
    result = analyse(
        matches,
        framework,
        document_source=str(args.document),
        document_sha256=ingest_result.sha256,
        pii_redactions=ingest_result.pii_redactions,
        warnings=ingest_result.warnings,
    )

    # --- LLM enrichment ---
    if args.enrich:
        from src.llm.enricher import enrich_audit_result
        print("[INFO] Running LLM enrichment (Claude)...")
        result = enrich_audit_result(result, ingest_result.content[:3000])

    # --- Output ---
    output_dir = Path(args.output_dir) if args.output_dir else Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    stem = Path(args.document).stem
    json_path = output_dir / f"{stem}_{args.framework}_audit.json"
    md_path = output_dir / f"{stem}_{args.framework}_audit.md"

    generate_json_report(result, json_path)
    generate_markdown_report(result, md_path)

    # --- Summary ---
    risk_icons = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
    icon = risk_icons.get(result.risk_label, "")
    print(
        f"\n{'='*55}\n"
        f"  AUDIT COMPLETE\n"
        f"{'='*55}\n"
        f"  Framework : {result.framework_name}\n"
        f"  Coverage  : {result.overall_coverage_pct}%\n"
        f"  Risk      : {icon} {result.risk_label} ({result.risk_score}/100)\n"
        f"  Addressed : {result.addressed_count}/{result.total_controls}\n"
        f"  Partial   : {result.partial_count}/{result.total_controls}\n"
        f"  Missing   : {result.missing_count}/{result.total_controls}\n"
        f"{'='*55}\n"
        f"  Reports saved to:\n"
        f"    {json_path}\n"
        f"    {md_path}\n"
    )

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ai-policy-auditor",
        description="Audit AI documentation against governance frameworks.",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    sub = parser.add_subparsers(dest="command", required=True)

    # --- list-frameworks ---
    sub.add_parser("list-frameworks", help="List available compliance frameworks.")

    # --- audit ---
    audit_p = sub.add_parser("audit", help="Audit a document.")
    audit_p.add_argument("document", help="Path to document file (.txt, .md, .pdf).")
    audit_p.add_argument(
        "--framework", "-f",
        choices=["nist_ai_rmf", "eu_ai_act", "iso_42001"],
        default="nist_ai_rmf",
        help="Compliance framework to audit against (default: nist_ai_rmf).",
    )
    audit_p.add_argument(
        "--strategy", "-s",
        choices=["auto", "keyword", "semantic"],
        default="auto",
        help="Mapping strategy (default: auto).",
    )
    audit_p.add_argument(
        "--no-enrich",
        dest="enrich",
        action="store_false",
        default=True,
        help="Skip LLM enrichment (faster, no API calls).",
    )
    audit_p.add_argument(
        "--output-dir", "-o",
        default="reports",
        help="Directory for output reports (default: reports/).",
    )

    args = parser.parse_args()
    _setup_logging(args.verbose)

    if args.command == "list-frameworks":
        return cmd_list_frameworks(args)
    elif args.command == "audit":
        return cmd_audit(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
