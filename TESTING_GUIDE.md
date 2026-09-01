# Testing Guide

How to run the Active Directory MCP test suite locally and against a real LDAP backend.

## Test categories

### 1. Unit tests (mocked)

No real LDAP server required. Uses mocks to exercise tool logic. This is most of the suite: `pytest tests/ -v` (no `AD_MCP_API_TOKEN` in the environment) runs 221 tests in a few seconds &mdash; 213 pass and 8 skip (the live smoke tests, see #3 below).

```bash
pytest tests/test_user_tools.py tests/test_group_tools.py -v
pytest tests/ -v -k "not integration"
```

Two files worth knowing about beyond the per-module tests:

- `tests/test_entrada_de_modelo_fraco.py` &mdash; asserts the server absorbs the malformed inputs a weak LLM tends to send (stringified lists/booleans, DN/UPN/`DOMAIN\user` usernames, out-of-range `days`, a missing required parameter, an OU from another domain, a tool name with a hub prefix) as structured refusals, never as a Python traceback.
- `tests/test_multi_ad.py` &mdash; exercises `AD_MCP_MODE=multi` against mocked directories, including `test_multi_so_acrescenta_o_catalogo`, which fails if a tool is ever added to one mode's registry (single/multi) without appearing in the other.

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

`tests/test_smoke_ao_vivo.py` drives a running `server_fastapi.py` instance (`multi` mode by default) end to end: catalogue doesn't leak credentials, every configured directory connects, a read against a named directory returns data, a read with no `ad_server` fans out to every directory, a write without `ad_server` and a write without confirmation are both refused, and a batch of malformed inputs never breaks the JSON-RPC envelope. It self-skips unless `AD_MCP_API_TOKEN` is exported and the instance answers `tools/list`:

```bash
export AD_MCP_API_TOKEN=your-real-token
# Optional: point at a different instance (default http://127.0.0.1:8853/mcp)
export AD_MCP_SMOKE_URL=http://localhost:8820/mcp

pytest tests/test_smoke_ao_vivo.py -v
```

For a quick manual check against any running instance (`--host`/`--port` from `server_fastapi.py`, default port `8820`):

```bash
# Health (no auth)
curl http://localhost:8820/health

# Tools listing
curl -X POST http://localhost:8820/mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
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

- Mock fixtures are defined per test file (`@pytest.fixture` in each `tests/test_<module>.py`), not centralized. `tests/conftest.py` only holds the autouse fixture that strips `AD_MCP_*` environment variables before every test, so a unit test can never accidentally pick up a real `AD_MCP_CONFIG`/`AD_MCP_SERVERS` left over in the shell.
- Sample user attributes use `test.local` and `jsmith@test.local`-style emails &mdash; never real domains.
- Performance fixtures (`tests/test_performance.py`) create N synthetic users, all under the `test.local` mock domain.

## Writing new tests

- Match the existing pattern: one `tests/test_<module>.py` per source module under `src/active_directory_mcp/tools/`.
- There is no `integration` pytest marker registered (`--strict-markers` is on); `-k "not integration"` works by keyword-matching `tests/test_integration.py`'s file name, not a marker. A test that needs the Samba AD container should live in that file, or gate itself the way `tests/test_smoke_ao_vivo.py` does (`pytestmark = pytest.mark.skipif(...)`).
- Mock LDAP with `unittest.mock` &mdash; don't introduce extra dependencies just for mocking.
- When adding a new tool, add at minimum: one happy-path test, one validation-error test, and one LDAP-error test.

## Acceptance gate

Before opening a PR, confirm:

- [ ] `ruff check .` passes
- [ ] `pytest tests/` (unit) passes
- [ ] Integration tests pass against the Samba AD container if you touched LDAP-facing code
- [ ] New public tools are documented in [`README.md`](README.md) tool tables
- [ ] No real domain, IP, password, or email is committed
