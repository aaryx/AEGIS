# Contributing to AEGIS

Thank you for your interest in contributing to AEGIS! AEGIS is an open-source, multi-tenant SIEM and SOAR platform built for security intelligence, detection engineering, and resilient incident response.

To maintain our high bar for security, code quality, and architectural integrity, all contributors are requested to adhere to the following guidelines.

---

## 1. Code of Conduct

AEGIS is dedicated to providing a welcoming, inclusive, and professional environment for all contributors. Treat fellow maintainers and contributors with respect and constructive feedback.

---

## 2. Getting Started

### Prerequisites
- **Python:** `>= 3.12`
- **Node.js:** `>= 24.0.0`
- **Docker & Docker Compose:** Required for integration and multi-service drills
- **Git:** Git 2.40+ configured with standard LF normalization

### Local Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/aaryx/AEGIS.git
   cd AEGIS
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux / macOS:
   source .venv/bin/activate
   ```

3. **Install dependencies with pinned lockfile:**
   ```bash
   python scripts/dev.py install
   ```

4. **Initialize local development configuration:**
   ```bash
   python scripts/configure.py
   ```
   *Note: This generates a local `.env` with random cryptographically secure secrets. Never commit this file.*

---

## 3. Branching & Commit Conventions

### Branch Strategy
- Main branch: `main` (protected production release baseline).
- Feature branches: `feature/<feature-name>` or `fix/<fix-name>`.
- Qualification branches: `feature/ironclad-qualification` (active candidate branch).

### Commit Messages
We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat(...)`: A new user-facing feature or API capability
- `fix(...)`: A bug fix or security patch
- `docs(...)`: Documentation improvements or validation reports
- `test(...)`: Adding or updating unit, integration, or regression tests
- `refactor(...)`: Code refactoring without changing functionality
- `chore(...)`: Tooling, build pipeline, or dependency maintenance

*Example:* `fix(security): resolve web dependency cves in next, vitest, undici, and vite`

---

## 4. Coding Standards

### Python
- **Code Formatter & Linter:** Ruff (`ruff format`, `ruff check`). Line length limit: **110 characters**.
- **Type Checking:** Mypy strict mode (`mypy aegis`). All source code must be fully type-annotated.
- **Security Scanner:** Bandit (`bandit -r aegis scripts -ll -q`). Zero Medium/High security findings permitted.
- **Dependency Audit:** `pip-audit --skip-editable`. Zero unpatched CVEs permitted.

### TypeScript / Frontend
- **Framework:** Next.js 16 (App Router) with React 19 and TypeScript.
- **Type Checking:** `npm --prefix web run typecheck` (`tsc --noEmit`).
- **Tests:** Vitest (`npm --prefix web test`).
- **Security:** `npm audit`. Zero vulnerabilities permitted.

---

## 5. Security & Architectural Invariants

Every contribution must preserve these non-negotiable invariants:
1. **Never Commit Secrets:** Never commit `.env`, private keys, passwords, bearer tokens, or real production credentials. All test credentials must use synthetic dummies.
2. **Server-Side Enforcement:** Never rely on frontend client checks for access control. Every mutating API route must enforce `Depends(require(...))`.
3. **Multi-Tenant Isolation:** All database reads and writes must be scoped to `organization_id`.
4. **Tamper-Evident Auditability:** Critical entity modifications (users, incidents, playbooks, containment) must append to the HMAC-SHA256 audit log chain.
5. **Fail-Closed Active Response:** SOAR playbooks and endpoint containment must fail closed and require appropriate human-in-the-loop approvals.

---

## 6. Pre-Commit Verification Checklist

Before opening a pull request, run the canonical project verification commands:

```bash
# 1. Lint and style checks
python scripts/dev.py lint

# 2. Type checking
python scripts/dev.py typecheck

# 3. Security audits (Bandit, pip-audit, npm audit)
python scripts/dev.py security

# 4. Backend unit & regression tests
pytest --cov=aegis

# 5. Detection rules tests
aegis rules test --all

# 6. Frontend tests & production build
npm --prefix web test
npm --prefix web run build
```

All gates must exit with code `0`.

---

## 7. Submitting a Pull Request

1. Push your branch to GitHub.
2. Open a Pull Request targeting `main` (or the active feature branch).
3. Complete the [Pull Request Template](.github/pull_request_template.md).
4. Ensure all GitHub Actions verification checks pass.
5. Address reviewer feedback constructively.
