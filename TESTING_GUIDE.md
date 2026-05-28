# Testing Guide

How to run the Active Directory MCP test suite locally and against a real LDAP backend.

## Test categories

### 1. Unit tests (mocked)

No real LDAP server required. Uses mocks to exercise tool logic.

```bash
pytest tests/test_user_tools.py tests/test_group_tools.py -v
pytest tests/ -v -k "not integration"
```

### 2. Integration tests (Samba AD via Docker)

The repo ships a `docker-compose-ad.yml` that boots a Samba AD container plus an MCP container. Both run on a private subnet so the integration tests can hit a real LDAP backend without touching production.

```bash
docker compose -f docker-compose-ad.yml up -d

# Wait for AD to be ready (about 30s)
docker compose -f docker-compose-ad.yml logs -f openldap-ad | grep "slapd starting"

# Run the integration suite
AD_MCP_CONFIG=$(pwd)/ad-config/ad-config.example.json \
  pytest tests/test_integration.py -v

docker compose -f docker-compose-ad.yml down -v
```

### 3. Live smoke tests (HTTP server)

With the HTTP server running and a real tenant config:

```bash
# Health
curl -X POST http://localhost:8813/activedirectory-mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ad_health_check_mcp_server","arguments":{}},"id":1}'

# Tools listing
curl -X POST http://localhost:8813/activedirectory-mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":2}'
```

## Coverage

```bash
pytest --cov=src/active_directory_mcp --cov-report=term-missing
pytest --cov=src/active_directory_mcp --cov-report=html  # open htmlcov/index.html
```

## Lint and format

```bash
ruff check .
ruff format .
mypy src/active_directory_mcp/  # optional
```

## Continuous Integration

A minimal GitHub Actions workflow should run, on every PR:

1. `pip install -e ".[dev]"`
2. `ruff check .`
3. `pytest tests/ -v -k "not integration"` (unit only &mdash; integration requires docker-compose)

## Test data conventions

- Mock fixtures live in `tests/conftest.py`.
- Sample user attributes use `test.local` and `jsmith@test.local`-style emails &mdash; never real domains.
- Performance fixtures (`tests/test_performance.py`) create N synthetic users, all under the `test.local` mock domain.

## Writing new tests

- Match the existing pattern: one `tests/test_<module>.py` per source module under `src/active_directory_mcp/tools/`.
- Use `pytest.mark.integration` for tests that require the Samba AD container.
- Mock LDAP with `unittest.mock` &mdash; don't introduce extra dependencies just for mocking.
- When adding a new tool, add at minimum: one happy-path test, one validation-error test, and one LDAP-error test.

## Acceptance gate

Before opening a PR, confirm:

- [ ] `ruff check .` passes
- [ ] `pytest tests/` (unit) passes
- [ ] Integration tests pass against the Samba AD container if you touched LDAP-facing code
- [ ] New public tools are documented in [`README.md`](README.md) tool tables
- [ ] No real domain, IP, password, or email is committed
