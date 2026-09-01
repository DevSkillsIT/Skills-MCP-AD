"""Test-wide isolation from the operator's environment.

Discovered by running the suite in a shell where multi/.env had been sourced:
test_http_server_initialization builds a server without passing `mode`, so it
read AD_MCP_MODE=multi and AD_MCP_SERVERS from the environment and loaded the
eight real customer directories. A unit test must never depend on -- let alone
reach -- production, and whether it does must not hinge on which shell ran it.

test_smoke_ao_vivo.py is the deliberate exception: it reads AD_MCP_API_TOKEN
before this fixture applies (at import time) and skips itself when absent.
"""

import pytest

VARIAVEIS_DE_AMBIENTE = (
    "AD_MCP_MODE",
    "AD_MCP_CONFIG",
    "AD_MCP_SERVERS",
    "AD_MCP_LOG_LEVEL",
    "AD_MCP_LOG_FILE",
)


@pytest.fixture(autouse=True)
def ambiente_limpo(monkeypatch, request):
    """Every test starts without AD_MCP_* leaking in from the shell."""
    if request.node.fspath.basename == "test_smoke_ao_vivo.py":
        return
    for nome in VARIAVEIS_DE_AMBIENTE:
        monkeypatch.delenv(nome, raising=False)
