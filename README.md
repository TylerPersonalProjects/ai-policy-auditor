# 🔐 AI Policy Auditor

[![CI](https://github.com/your-org/ai-policy-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/ai-policy-auditor/actions/workflows/ci.yml)
[![CodeQL](https://github.com/your-org/ai-policy-auditor/actions/workflows/codeql.yml/badge.svg)](https://github.com/your-org/ai-policy-auditor/actions/workflows/codeql.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Automatically audit AI system documentation against major governance frameworks — NIST AI RMF, EU AI Act, and ISO 42001 — and generate gap analysis reports with LLM-powered risk narratives.**

Built for AI Trust & Safety, GRC, and compliance teams who need to assess model cards, system cards, and AI deployment documentation at scale.

---

## ✨ Features

- 📋 **Multi-framework support** — NIST AI RMF 1.0, EU AI Act (2024), ISO/IEC 42001:2023
- 🔍 **Intelligent control mapping** — keyword matching + optional semantic similarity via `sentence-transformers`
- 🤖 **LLM-powered narratives** — Claude generates executive summaries, gap explanations, and remediation guidance
- 📊 **Structured reports** — JSON (machine-readable) and Markdown (human-readable) output
- 🔌 **REST API** — FastAPI with rate limiting and API key auth for CI/CD integration
- 🔒 **Secure by design** — PII redaction, prompt injection defence, MIME allowlisting, secret scanning in CI

---

## 🏗️ Architecture

```
Document (model card, policy doc, DPA)
        │
        ▼
┌─────────────────────┐
│  Secure Ingest      │  File validation, PII redaction, SHA-256 integrity
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐     ┌──────────────────────┐
│  Framework Loader   │────▶│  Control Mapper       │  Keyword + semantic scoring
│  NIST / EU / ISO    │     └──────────┬───────────┘
└─────────────────────┘               │
                                       ▼
                              ┌──────────────────────┐
                              │  Gap Analyser         │  Risk scoring, coverage %
                              └──────────┬───────────┘
                                         │
                                         ▼
                              ┌──────────────────────┐
                              │  Claude API           │  Narratives, remediation
                              └──────────┬───────────┘
                                         │
                              ┌──────────┴───────────┐
                              │  Reports              │
                              │  JSON  •  Markdown    │
                              └──────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- An [Anthropic API key](https://console.anthropic.com/) (optional — LLM enrichment only)

### Installation

```bash
# Clone the repo
git clone https://github.com/your-org/ai-policy-auditor.git
cd ai-policy-auditor

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install
pip install -e .

# Configure secrets
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### Audit a document

```bash
# Audit a model card against NIST AI RMF
python -m src.cli audit docs/my_model_card.md --framework nist_ai_rmf

# Audit against the EU AI Act
python -m src.cli audit docs/my_model_card.md --framework eu_ai_act

# Skip LLM enrichment (no API key needed)
python -m src.cli audit docs/my_model_card.md --no-enrich

# Save reports to a custom directory
python -m src.cli audit docs/my_model_card.md --output-dir reports/q3-audit/

# List all available frameworks
python -m src.cli list-frameworks
```

Sample output:

```
=======================================================
  AUDIT COMPLETE
=======================================================
  Framework : NIST AI Risk Management Framework
  Coverage  : 68.2%
  Risk      : 🟡 MEDIUM (38/100)
  Addressed : 15/22
  Partial   : 3/22
  Missing   : 4/22
=======================================================
  Reports saved to:
    reports/my_model_card_nist_ai_rmf_audit.json
    reports/my_model_card_nist_ai_rmf_audit.md
```

---

## 📖 Supported Frameworks

| Framework | ID | Controls | Reference |
|-----------|-----|----------|-----------|
| NIST AI Risk Management Framework 1.0 | `nist_ai_rmf` | 16 | [airc.nist.gov](https://airc.nist.gov/RMF) |
| EU Artificial Intelligence Act (2024) | `eu_ai_act` | 17 | [EUR-Lex](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689) |
| ISO/IEC 42001:2023 AI Management System | `iso_42001` | 16 | [ISO](https://www.iso.org/standard/81230.html) |

---

## 🔌 REST API

Start the API server:

```bash
# Set optional API key for auth
export AUDITOR_API_KEY=your-secret-key

uvicorn src.api.app:app --reload
```

Audit via HTTP:

```bash
# Audit plain text
curl -X POST http://localhost:8000/audit/text \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key" \
  -d '{
    "text": "This model card describes...",
    "framework": "nist_ai_rmf",
    "enrich": true
  }'

# Audit a file
curl -X POST http://localhost:8000/audit/file \
  -H "X-API-Key: your-secret-key" \
  -F "file=@docs/model_card.md" \
  -F "framework=eu_ai_act"
```

Interactive docs: `http://localhost:8000/docs`

### Docker

```bash
docker build -t ai-policy-auditor .
docker run -p 8000:8000 \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -e AUDITOR_API_KEY=$AUDITOR_API_KEY \
  ai-policy-auditor
```

---

## 🛡️ Security Design

This project follows defence-in-depth. Key controls:

| Layer | Control |
|-------|---------|
| **Input** | MIME type allowlist, 5 MB size cap, path traversal protection |
| **PII** | Regex-based redaction of emails, SSNs, phone numbers, IPs, tokens before any LLM call |
| **LLM** | Document content passed as a clearly delimited message, never interpolated into system prompt |
| **Output** | LLM responses length-capped, schema-validated, and secret-scanned before storage |
| **API** | Rate limiting (10 req/min), API key auth via `secrets.compare_digest`, no raw stack traces in responses |
| **Secrets** | `.env.example` only in repo; pre-commit hook blocks `.env` commits; Gitleaks in CI |
| **Dependencies** | `pip-audit` on every CI run; Dependabot enabled |
| **Container** | Non-root user, read-only app files, no shell in CMD |
| **SAST** | Bandit + CodeQL on every PR |

See [SECURITY.md](.github/SECURITY.md) for the vulnerability disclosure policy.

---

## 🧪 Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/unit/ -v

# Run linter
ruff check src/ tests/

# Run SAST
bandit -r src/

# Scan dependencies
pip-audit --requirement requirements.txt
```

### Semantic mapping (optional)

For higher-quality control matching, install `sentence-transformers`:

```bash
pip install -e ".[semantic]"
```

The mapper will automatically use semantic similarity when the library is available,
falling back to keyword matching otherwise.

### Adding a new framework

1. Create a new YAML file in `src/frameworks/` following the structure of `nist_ai_rmf.yaml`
2. Add the framework ID and path to `AVAILABLE_FRAMEWORKS` in `src/frameworks/loader.py`
3. Add test fixtures in `tests/fixtures/`

---

## 📁 Project Structure

```
ai-policy-auditor/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml           # Lint, test, SAST, secret scan on every PR
│   │   └── codeql.yml       # GitHub CodeQL analysis
│   └── SECURITY.md          # Vulnerability disclosure policy
├── src/
│   ├── ingest/              # Secure document ingestion and PII redaction
│   ├── frameworks/          # NIST, EU AI Act, ISO 42001 YAML definitions + loader
│   ├── mapper/              # Keyword and semantic control mapping
│   ├── analyser/            # Gap scoring and risk calculation
│   ├── llm/                 # Claude API client with security guardrails
│   ├── output/              # JSON and Markdown report generators
│   ├── api/                 # FastAPI REST API
│   └── cli.py               # Command-line interface
├── tests/
│   ├── unit/                # Unit tests (no external deps)
│   ├── integration/         # Integration tests
│   └── fixtures/            # Sample documents for testing
├── .env.example             # Environment variable template
├── Dockerfile               # Distroless-style secure container
├── pyproject.toml           # Project metadata and dependencies
└── requirements.txt         # Pinned runtime dependencies
```

---

## 🗺️ Roadmap

- [ ] OSCAL output format support
- [ ] ISO 27001 / SOC 2 framework definitions
- [ ] GitHub Action for PR-level model card auditing
- [ ] Web UI for report visualisation
- [ ] Multi-document batch auditing
- [ ] Continuous monitoring mode (watch a directory for new docs)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repo and create a feature branch
2. Run `ruff check` and `pytest` before submitting a PR
3. Include tests for new functionality
4. Update framework YAML definitions via PR with references to the source standard

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

## ⚠️ Disclaimer

This tool provides automated analysis as a starting point. It does not constitute legal advice and should not be the sole basis for compliance decisions. Always consult qualified legal and compliance professionals for regulatory obligations.
