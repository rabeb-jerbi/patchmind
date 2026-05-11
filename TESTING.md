# PatchMind — Test Suite

## Overview

The test suite covers ~200 tests across 13 modules.  
No real Semgrep, GitLeaks, Snyk, or LLM API key is required; all external calls are mocked.

---

## Quick start

```bash
# From the patchmind/ directory
pip install pytest pytest-cov
pytest
```

---

## Install test dependencies

```bash
pip install -r requirements.txt
```

Key test dependencies:

| Package | Purpose |
|---------|---------|
| `pytest>=7.4` | Test runner |
| `pytest-cov>=4.1` | Coverage reports |
| `werkzeug` | Flask test client helpers |

---

## Running tests

### All tests

```bash
cd patchmind
pytest
```

### Specific file

```bash
pytest tests/test_rbac.py -v
pytest tests/test_routes.py -v
```

### By marker

```bash
pytest -m "not slow"        # skip slow tests
pytest -m "not e2e"         # skip browser tests
```

### Stop on first failure

```bash
pytest -x
```

---

## Coverage

```bash
# Terminal report
pytest --cov=. --cov-report=term-missing

# HTML report (opens in browser)
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

---

## Test structure

```
tests/
├── conftest.py            # Fixtures: app, client, auth_client, admin_client, viewer_client
├── test_rbac.py           # RBAC role/permission matrix (35+ tests)
├── test_validator.py      # syntax_check, _regression_check, _scan_file_for_secrets
├── test_confidence.py     # _compute_confidence() scoring weights
├── test_json_io.py        # read_json, write_json, locked_update (concurrent safety)
├── test_security.py       # HTTP headers, auth enforcement, session config
├── test_upload.py         # Extension allowlist, ZIP traversal, filename sanitisation
├── test_github_security.py # _validate_git_url() SSRF/injection guard
├── test_tools.py          # ToolRegistry, adapters (Bandit, Pylint, ESLint, etc.)
├── test_routes.py         # HTTP status codes for all public/protected routes
├── test_scanners.py       # detect_language, run_scan (mocked semgrep), gitleaks fallback
├── test_integration.py    # End-to-end workflows: auth, upload, tool recommendation
├── test_ai_validation.py  # validate_patch() with mocked subprocess
├── test_performance.py    # Cache hits, rate limiter, response time bounds
└── test_database.py       # SQLAlchemy models: CRUD, to_dict, from_dict, constraints
```

---

## What is mocked

| Component | How it's mocked |
|-----------|----------------|
| Semgrep | `patch("subprocess.run")` returning pre-built JSON |
| GitLeaks binary | `patch("subprocess.run", side_effect=FileNotFoundError)` |
| Snyk binary | `patch("subprocess.run", side_effect=FileNotFoundError)` |
| Pipeline (run_pipeline) | `patch("dashboard.app.run_pipeline")` no-op |
| LLM / generate_patch | Not called in unit/integration tests |
| Email sending | Not called (SMTP not configured in test env) |
| External tool adapters | `patch("subprocess.run")` with fixture JSON output |

---

## conftest.py — key fixtures

| Fixture | Scope | Description |
|---------|-------|-------------|
| `app` | session | Flask app with `TESTING=True`, temp SQLite DB |
| `client` | function | Unauthenticated test client |
| `auth_client` | function | Client pre-logged-in as `analyst` |
| `admin_client` | function | Client pre-logged-in as `admin` |
| `viewer_client` | function | Client pre-logged-in as `viewer` |
| `zip_bytes` | function | Valid ZIP with one `.py` file |
| `traversal_zip_bytes` | function | ZIP with `../../../evil.py` entry |
| `dangerous_zip_bytes` | function | ZIP with a `.exe` entry |

Environment variables set before Flask import:

```python
os.environ["DATABASE_URL"] = f"sqlite:///{_db_path}"   # temp file
os.environ["PATCHMIND_SECRET"] = "test-secret-for-pytest-32-chars!!"
os.environ["TESTING"] = "True"
```

---

## pytest.ini options

```ini
[pytest]
testpaths = tests
addopts = -v --tb=short -p no:warnings
markers =
    e2e: end-to-end tests requiring a browser
    slow: tests that take longer than usual
```

---

## Limitations

- **E2E tests** (`@pytest.mark.e2e`) require Playwright and a running server — not included in CI by default.
- **Real scanner results** are never validated; only mocked output parsing is tested.
- **LLM patch quality** is not tested — only that the pipeline calls `generate_patch` and handles its output.
- **Email delivery** is not tested — SMTP is not configured in the test environment.
- **Windows-only paths** (`SEMGREP_PATH = .../venv/Scripts/semgrep.exe`) may cause skips on Linux CI for integration tests that don't mock subprocess.

---

## Known issues

- `test_database.py::TestMigrationIdempotency` requires `scripts/import_json_to_db.py` to exist; it is skipped if the script is not present.
- `test_performance.py` timing assertions are loose (< 200 ms, < 500 ms) and may flake under heavy I/O load.
