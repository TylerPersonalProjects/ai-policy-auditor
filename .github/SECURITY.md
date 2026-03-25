# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability, please report it via one of:

1. **GitHub Private Security Advisory** — [Report a vulnerability](../../security/advisories/new) (preferred)
2. **Email** — security@your-org.com (PGP key available on request)

### What to include

- Description of the vulnerability and its potential impact
- Steps to reproduce (proof of concept if possible)
- Any mitigations you've identified

### Response timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix or mitigation | Within 30 days for critical, 90 days for others |
| Disclosure | Coordinated with reporter |

We follow responsible disclosure. We will credit you in the release notes unless you prefer to remain anonymous.

## Scope

In scope:
- Prompt injection vulnerabilities in the LLM enrichment pipeline
- PII leakage through the API or reports
- Authentication/authorisation bypasses in the REST API
- Path traversal or arbitrary file read in the ingest module
- Dependency vulnerabilities with a known CVE

Out of scope:
- Vulnerabilities in third-party dependencies (please report upstream)
- Rate limiting bypass via distributed IPs
- Social engineering attacks

## Security Design Principles

This project follows a defence-in-depth approach:

1. **Input validation** — files are type- and size-checked before reading
2. **PII redaction** — document content is scrubbed before any LLM call
3. **Prompt injection defence** — document content is passed as a clearly delimited user turn, never interpolated into the system prompt
4. **Output sanitisation** — LLM responses are length-capped and validated before storage
5. **Secret hygiene** — API keys are read from environment variables only; pre-commit hooks block accidental commits
6. **Least privilege** — the Docker container runs as a non-root user with read-only source files
7. **Dependency scanning** — `pip-audit` runs on every CI build; Dependabot monitors for new CVEs
