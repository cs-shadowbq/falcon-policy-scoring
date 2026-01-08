# Testing Guide for Falcon Policy Audit

Comprehensive testing documentation for the Falcon Policy Audit tool. This guide covers our three-tier testing strategy, how to run tests, VCR cassette usage, and best practices.

## Quick Start

```bash
# Run all tests (unit + integration, excluding E2E)
make test

# Run unit tests only (fastest)
make test-unit

# Run integration tests only
make test-integration

# Generate coverage report
make test-coverage
```

## Three-Tier Testing Strategy

This project uses a three-tier testing strategy to balance comprehensive coverage with CI/CD practicality:

### 1. Unit Tests (Required for CI/CD)
**What:** Test individual components in isolation with mocked dependencies.

**Characteristics:**
- Fast execution (< 1 second total)
- No external dependencies
- All external APIs mocked
- No network calls
- No credentials required

**Examples:**
- `test_grading_engine.py` - Grading logic with mocked policies
- `test_cli_operations.py` - CLI commands with mocked API
- `test_falconapi/test_hosts.py` - Hosts API with mocked FalconPy
- `test_database_adapters.py` - Database adapters with temp DBs
- `test_daemon.py` - Daemon components with time mocking (freezegun)

**Run with:** `make test-unit` or `pytest tests/ -m unit`

### 2. Integration Tests (Required for CI/CD)
**What:** Test multiple components working together, external APIs still mocked.

**Characteristics:**
- Tests workflows across layers (CLI → operations → data_fetcher → adapter)
- Multiple components interact
- External APIs (CrowdStrike) still mocked
- Database operations use real temp databases
- No credentials required
- Slightly slower than unit tests (1-5 seconds)

**Examples:**
- `test_integration_workflows.py` - Full fetch→grade→export workflows
- `test_database_integration.py` - Database CRUD operations with real SQLite

**Run with:** `make test-integration` or `pytest tests/ -m integration`

### 3. E2E Smoke Tests (Optional, Manual Only)
**What:** Test against real CrowdStrike API using VCR cassettes.

**Characteristics:**
- Uses VCR to record/replay real API interactions
- Requires real credentials (for recording)
- Can replay from cassettes without credentials
- Skipped by default in CI/CD
- Only run manually or in special CI jobs with secrets
- Includes cassette metadata (.meta.yaml files) with CID, BASE_URL

**Examples:**
- `test_e2e_smoke.py` - Real API calls with VCR cassettes
- Actual fetch hosts from production tenant
- Real policy grading with live data

**Run with:** `make test-e2e-replay` (replay) or `make test-e2e-record` (record with credentials)

## Why This Approach?

### Problems Solved:

1. **CI/CD Can't Use Real APIs**
   - Solution: Unit + Integration tests use mocks (no credentials needed)
   - E2E tests are optional and skipped in CI

2. **VCR Cassettes Can't Work in Public CI**
   - Solution: E2E tests with VCR are marked and skipped
   - Can be run locally or in secure CI with secrets

3. **Need Real Integration Testing**
   - Solution: Integration tests verify components work together
   - Still use mocks for external APIs (testable in CI)

4. **Fast Feedback Loops**
   - Solution: Unit tests run in < 1 second
   - Integration tests add 1-5 seconds
   - E2E tests are optional

## Test Organization

```
tests/
├── conftest.py                 # Shared pytest fixtures
├── pytest.ini                  # Pytest configuration and markers
├── fixtures/                   # Shared test data
│   ├── configs/                # Config file fixtures (minimal, maximal, etc.)
│   ├── env_files/              # .env file fixtures
│   └── vcr_cassettes_e2e/      # VCR cassettes for E2E tests
├── test_grading_engine.py      # Grading logic tests
├── test_grading_rollup.py      # Grading rollup/propagation tests
├── test_database_adapters.py   # Database adapter compliance tests
├── test_cli_operations.py      # CLI business logic tests
├── test_config_validation.py   # Config validation tests
├── test_env_overlay.py         # ENV var overlay tests
├── test_daemon.py              # Daemon components (scheduler, rate limiter, health check)
├── test_e2e_smoke.py           # E2E smoke tests with VCR (@pytest.mark.e2e)
├── adapters/                   # Database adapter tests
│   ├── test_sqlite_adapter.py  # SQLite-specific tests
│   └── test_tinydb_adapter.py  # TinyDB-specific tests
└── test_falconapi/             # FalconAPI module tests
    ├── test_hosts.py           # Hosts API (pagination, scroll, rate limiting)
    └── test_policies.py        # Policies API (all policy types)
```

## Test Markers

Tests are organized using pytest markers (defined in `pytest.ini`):

- `@pytest.mark.unit` - Fast unit tests with mocks (no external dependencies)
- `@pytest.mark.integration` - Integration tests with multiple components (mocked external APIs)
- `@pytest.mark.e2e` - End-to-end smoke tests with real API calls (requires credentials, skipped in CI)
- `@pytest.mark.smoke` - Alias for e2e tests
- `@pytest.mark.cli` - Tests for CLI functionality
- `@pytest.mark.daemon` - Tests for daemon functionality
- `@pytest.mark.requires_cassettes` - Tests that require VCR cassettes to be present
- `@pytest.mark.slow` - Tests that take longer to execute

## Running Tests

### All Tests (Except E2E)
```bash
# Using make (recommended)
make test

# Using pytest directly
pytest tests/
pytest tests/ -v                  # Verbose output
pytest tests/ --tb=short          # Short traceback format
```

### Unit Tests Only
```bash
# Using make (recommended)
make test-unit

# Using pytest directly
pytest tests/ -m unit
```

### Integration Tests Only
```bash
# Using make (recommended)
make test-integration

# Using pytest directly
pytest tests/ -m integration
```

### E2E Smoke Tests

**Replay from cassettes (no credentials needed):**
```bash
# Using make (recommended)
make test-e2e-replay

# Using pytest directly
pytest tests/ -m e2e --vcr-record=none
```

**Record new cassettes (requires credentials):**
```bash
# Set credentials first
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
export FALCON_BASE_URL="https://api.crowdstrike.com"  # or US1, US2, EU1, etc.

# Using make (recommended)
make test-e2e-record

# Using pytest directly
pytest tests/ -m e2e --vcr-record=all
```

**Add new episodes to existing cassettes:**
```bash
pytest tests/ -m e2e --vcr-record=new_episodes
```

### Specific Test Categories
```bash
pytest tests/test_grading_*.py           # All grading tests
pytest tests/test_cli_*.py               # All CLI tests
pytest tests/test_falconapi/             # All FalconAPI tests
pytest tests/adapters/                   # All adapter tests
pytest tests/test_daemon.py              # Daemon tests
```

### Re-run Failed Tests Only
```bash
# Using make (recommended)
make test-failed

# Using pytest directly
pytest --lf
```

### Coverage Reports
```bash
# Generate HTML + terminal coverage report
make test-coverage

# Serve coverage report at http://localhost:8089
make test-coverage-serve
```

### Clean Test Artifacts
```bash
make clean-test
```

## VCR Cassettes for E2E Tests

### What are VCR Cassettes?

VCR cassettes are recordings of real API HTTP interactions. They allow E2E tests to replay API responses without making live API calls, making tests:
- **Fast** - No network latency (~37x faster: 3.79s → 0.14s)
- **Reliable** - Tests don't fail due to API rate limits or network issues
- **Repeatable** - Same responses every time
- **Safe** - No risk of modifying production data

### ⚠️ Cassettes Are NOT Committed to This Repository

**VCR cassettes contain sensitive data and MUST be stored in a separate private repository:**
- Customer IDs (CIDs)
- Device IDs (AIDs)
- API endpoints and base URLs
- Policy configurations
- Hostnames and internal network information

**This repository excludes cassettes via `.gitignore`:**
```gitignore
# Test VCR cassettes - contain sensitive API data, do not commit
tests/vcr_cassette*/
*.cassette.yaml
*.cassette.json
```

### Cassette Metadata System

Each cassette has a companion `.meta.yaml` file that stores:
- **CID** - Customer ID used for recording
- **BASE_URL** - API base URL (e.g., `api.us-2.crowdstrike.com`)
- **timestamp** - When the cassette was recorded

This metadata allows tests to replay without credentials by using the recorded environment details.

**Both cassette files (.yaml) AND metadata files (.meta.yaml) should be stored in your private repository.**

### Setting Up Private Cassettes Repository (Recommended)

Maintain cassettes in a separate private Git repository and overlay them into your workspace:

#### 1. Create Private Repository Structure:
```bash
# Create private repo with same structure
private-cassettes/
└── tests/
    └── fixtures/
        └── vcr_cassettes_e2e/
            ├── TestHostsAPIE2E.test_fetch_workstation_device_ids.yaml
            ├── TestHostsAPIE2E.test_fetch_workstation_device_ids.meta.yaml
            └── ... (other cassettes and metadata)
```

#### 2. Clone Private Repository:
```bash
# Clone alongside your main repo
cd /path/to/projects
git clone git@github.com:yourorg/falcon-policy-audit-private-cassettes.git private-cassettes
```

#### 3. Create Symlink to Overlay Cassettes:
```bash
# From your main repo directory
cd /path/to/your-project

# Create symlink to private cassettes directory
ln -s ../private-cassettes/tests/fixtures/vcr_cassettes_e2e tests/fixtures/vcr_cassettes_e2e
```

#### 4. Verify Setup:
```bash
# Check symlink exists
ls -la tests/fixtures/vcr_cassettes_e2e
# Should show: tests/fixtures/vcr_cassettes_e2e -> ../private-cassettes/tests/fixtures/vcr_cassettes_e2e

# Verify cassettes are accessible
ls tests/fixtures/vcr_cassettes_e2e/
# Should list: *.yaml and *.meta.yaml files
```

#### 5. Test with Private Cassettes:
```bash
# Replay from private cassettes (no credentials needed)
make test-e2e-replay
```

### Alternative: Local Private Directory

If you prefer not to use a separate git repository:

```bash
# Store cassettes in a secure local directory
mkdir -p ~/secure-cassettes/your-project

# Create symlink
ln -s ~/secure-cassettes/your-project tests/fixtures/vcr_cassettes_e2e

# Record cassettes (they'll be stored in ~/secure-cassettes/your-project)
make test-e2e-record
```

### VCR Recording Modes

Control cassette recording behavior with the `--vcr-record` flag:

- **`none`** - Only replay existing cassettes, never record. Tests requiring missing cassettes will fail.
  ```bash
  pytest tests/ -m e2e --vcr-record=none
  ```

- **`once`** (default) - Record cassettes that don't exist, replay existing ones.
  ```bash
  pytest tests/ -m e2e --vcr-record=once
  ```

- **`new_episodes`** - Record new interactions not in cassette, replay existing ones.
  ```bash
  pytest tests/ -m e2e --vcr-record=new_episodes
  ```

- **`all`** - Always re-record all cassettes (overwrites existing).
  ```bash
  pytest tests/ -m e2e --vcr-record=all
  ```

### Security & Data Sanitization

VCR configuration in `tests/conftest.py` automatically filters sensitive data **from cassettes**:

**Request Filtering:**
- `Authorization` headers → `REDACTED`
- `client_id` in OAuth requests → `REDACTED`
- `client_secret` in OAuth requests → `REDACTED`

**OAuth Tokens:**
- Visible in cassettes but **expire in 30 minutes** (not usable)

**While credentials are filtered, cassettes still contain sensitive customer data (CIDs, AIDs, policy configs) and MUST be stored in a private repository separate from this codebase.**

### Recording New Cassettes

1. **Set Environment Variables:**
   ```bash
   export FALCON_CLIENT_ID="your-client-id"
   export FALCON_CLIENT_SECRET="your-client-secret"
   export FALCON_BASE_URL="https://api.crowdstrike.com"  # or US1, US2, EU1, etc.
   ```

2. **Record Cassettes:**
   ```bash
   make test-e2e-record
   ```

3. **Cassettes Created:**
   ```
   tests/fixtures/vcr_cassettes_e2e/
   ├── TestHostsAPIE2E.test_fetch_workstation_device_ids.yaml
   ├── TestHostsAPIE2E.test_fetch_workstation_device_ids.meta.yaml
   └── ... (other cassettes and metadata)
   ```

4. **Commit to Private Repository:**
   ```bash
   # If using private repo overlay (recommended)
   cd ../private-cassettes
   git add tests/fixtures/vcr_cassettes_e2e/*.yaml
   git add tests/fixtures/vcr_cassettes_e2e/*.meta.yaml
   git commit -m "Update VCR cassettes"
   git push
   
   # Cassettes are now in private repo, NOT in main repo
   ```

### Replaying from Cassettes

No credentials needed - uses cassette metadata from your private repository:

```bash
make test-e2e-replay
```

Tests will:
1. Load cassette metadata (.meta.yaml) from private repo overlay
2. Use recorded CID and BASE_URL
3. Replay HTTP interactions from cassette
4. Skip real API calls entirely

**Note:** Ensure your private cassettes are overlaid via symlink before running replay tests.

### Re-recording Cassettes

When API responses change or you need fresh recordings:

```bash
# Delete old cassettes in your private repo
rm -rf tests/fixtures/vcr_cassettes_e2e/*.yaml

# Re-record with real API
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
export FALCON_BASE_URL="US2"
make test-e2e-record

# Commit updated cassettes to private repo
cd ../private-cassettes
git add tests/fixtures/vcr_cassettes_e2e/*.yaml
git commit -m "Re-record VCR cassettes"
git push
```

### Performance Comparison

| Mode | API Calls | Time | Use Case |
|------|-----------|------|----------|
| **Record** (`--vcr-record=all`) | ✅ Real | ~3.79s | Initial recording, updating cassettes |
| **Replay** (`--vcr-record=none`) | ❌ None | ~0.14s | CI/CD, local testing, no credentials needed |

## CI/CD Configuration

### What Runs in CI/CD:
- ✅ All unit tests
- ✅ All integration tests (with mocked APIs)
- ❌ E2E smoke tests (skipped, no credentials)

### pytest.ini Configuration:
```ini
[pytest]
markers =
    unit: Unit tests that run fast without external dependencies (default)
    integration: Integration tests with multiple components (mocked external APIs)
    e2e: End-to-end smoke tests with real API calls (requires credentials, skipped in CI)
```

### GitHub Actions Workflow (.github/workflows/test.yml):
```yaml
- name: Run tests
  run: |
    pytest tests/ -m "not e2e" --tb=short -v
```

Tests run on:
- Push/PR to `main`, `dev`, `ver_*` branches
- Python versions: 3.13, 3.14
- Timeout: 15 minutes
- Uses pip caching for faster builds

## Test Statistics

- **Total Tests:** 424
- **Unit Tests:** 251
- **Integration Tests:** 13
- **E2E Tests:** 7
- **Database Adapters:** SQLite, TinyDB (MariaDB planned)

## Writing New Tests

### Unit Test Example:
```python
import pytest

@pytest.mark.unit
def test_grade_prevention_policy():
    """Unit test - mocked data."""
    policy_data = {'id': 'p1', 'settings': [...]}
    result = grade_policy(policy_data, grading_config)
    assert result['passed'] is True
```

### Integration Test Example:
```python
import pytest
from unittest.mock import patch

@pytest.mark.integration
def test_fetch_and_grade_workflow(test_adapter, mock_falcon):
    """Integration test - multiple components, mocked API."""
    # Mock external API
    with patch('falcon_policy_scoring.falconapi.hosts.Hosts') as mock:
        mock.return_value.get_device_ids.return_value = ['aid1']
        
        # Test full workflow
        fetch_and_store_hosts(mock_falcon, test_adapter, 'cid', [], config, ctx)
        result = fetch_and_grade_all_policies(mock_falcon, test_adapter, 'cid', ['prevention'], ctx)
        
        # Verify database state
        assert test_adapter.get_hosts('cid')['total'] > 0
        assert result['prevention']['total'] > 0
```

### E2E Test Example:
```python
import pytest

@pytest.mark.e2e
@pytest.mark.vcr()
def test_fetch_real_hosts(real_falcon_client):
    """E2E test - real API with VCR cassette."""
    from falcon_policy_scoring.falconapi.hosts import Hosts
    
    hosts_api = Hosts(real_falcon_client)
    device_ids = hosts_api.get_device_ids(product_types=['Workstation'])
    
    assert len(device_ids) > 0
    assert all(isinstance(aid, str) for aid in device_ids)
```

### Time-Based Test Example (Daemon):
```python
import pytest
from freezegun import freeze_time

@pytest.mark.unit
def test_scheduler_execution():
    """Test with time manipulation using freezegun."""
    scheduler = Scheduler()
    
    # Add task to run at 10:00
    with freeze_time("2026-01-08 09:59:00"):
        scheduler.add_task("task_name", mock_func, "0 10 * * *")
    
    # Execute at 10:00
    with freeze_time("2026-01-08 10:00:00"):
        results = scheduler.check_and_run_tasks()
        assert "task_name" in results
```

## Test Configuration Matrix

Tests use multiple configuration variations to ensure compatibility:

1. **minimal** - Basic settings, short TTLs
2. **maximal** - All features enabled (ZTA, host groups, long TTLs)
3. **tinydb** - TinyDB database backend
4. **custom_ttl** - Custom TTL configurations
5. **empty** - Empty configuration (tests defaults)
6. **invalid_*** - Various invalid configs for error testing

Configuration fixtures are available in `tests/conftest.py`:
```python
def test_with_config(minimal_config_file):
    # Test uses minimal configuration
    pass
```

## Database Testing

Tests run against both SQLite and TinyDB using parametrized fixtures:

```python
@pytest.fixture(params=['sqlite', 'tiny_db'])
def db_adapter(request):
    # Tests run twice: once with SQLite, once with TinyDB
    pass
```

This ensures compatibility for future MariaDB support.

## Troubleshooting

### Test Fails: "VCR cassette not found"

```
E       CannotOverwriteExistingCassetteException: cassette file not found...
```

**Solution:** Set up private cassettes repository or record new cassettes:
```bash
# Option 1: Set up private repo overlay (recommended)
cd /path/to/projects
git clone git@github.com:yourorg/falcon-policy-audit-private-cassettes.git private-cassettes
cd your-project
ln -s ../private-cassettes/tests/fixtures/vcr_cassettes_e2e tests/fixtures/vcr_cassettes_e2e

# Option 2: Record new cassettes (requires credentials)
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
export FALCON_BASE_URL="US2"
make test-e2e-record

# Option 3: Skip E2E tests
make test
```

### Import Errors

```
ModuleNotFoundError: No module named 'falcon_policy_scoring'
```

**Solution:** Install package in development mode:
```bash
pip install -e ".[test]"
```

### Freezegun Time Issues (Daemon Tests)

**Problem:** Tasks not executing at expected times in tests.

**Solution:** Add tasks BEFORE the scheduled time, then freeze time AT the scheduled time:
```python
# Add task at 09:59
with freeze_time("2026-01-08 09:59:00"):
    scheduler.add_task("task", func, "0 10 * * *")

# Execute at 10:00
with freeze_time("2026-01-08 10:00:00"):
    results = scheduler.check_and_run_tasks()
```

### Database Permission Errors

**Solution:** Tests use temporary databases in temp directories with proper cleanup. If issues persist:
```bash
# Clean up any stale test data
rm -rf /tmp/falcon_test_*
make clean-test
```

### Coverage Not Generated

**Solution:** Ensure pytest-cov is installed:
```bash
pip install -e ".[test]"
make test-coverage
```

### VCR Base URL Mismatch

**Problem:** VCR cassette not matching requests during replay.

**Solution:** Ensure test fixtures use the same BASE_URL as the cassette was recorded with. Check `.meta.yaml` files for recorded BASE_URL.

## Best Practices

1. **Keep unit tests fast** - Use mocks, avoid I/O
2. **Mark tests appropriately** - Use correct pytest markers (`@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.e2e`)
3. **Parametrize when possible** - Test multiple configurations/databases
4. **Write isolated tests** - Each test should be independent
5. **Clean up resources** - Use fixtures for setup/teardown
6. **Test edge cases** - Include boundary conditions and error scenarios
7. **Use freezegun for time-based tests** - Mock time instead of using sleep()
8. **Document complex tests** - Add docstrings explaining test purpose
9. **Keep cassettes up-to-date** - Re-record when APIs change
10. **Store cassettes in private repo** - Never commit to public/main repository (excluded via .gitignore)
11. **Use symlinks for overlay** - Link private cassettes into tests/fixtures/vcr_cassettes_e2e/

## Key Testing Tools

- **pytest** (9.0.2) - Test framework
- **pytest-cov** (7.0.0) - Coverage reporting
- **pytest-vcr** (1.0.2) - VCR cassette integration
- **vcrpy** (8.1.1) - HTTP interaction recording
- **freezegun** (1.5.5) - Time mocking for daemon tests
- **jsonschema** (4.26.0) - JSON schema validation

## Additional Resources

- [pytest documentation](https://docs.pytest.org/)
- [VCR.py documentation](https://vcrpy.readthedocs.io/)
- [freezegun documentation](https://github.com/spulec/freezegun)
- [CrowdStrike FalconPy SDK](https://github.com/CrowdStrike/falconpy)
