"""Smoke test against a running multi-AD instance.

Replaces the old test_scripts/test_http_server.py, which drove a server that no
longer exists (FastMCP on port 8813) and whose README was in Turkish, inherited
from the upstream project.

Skipped unless the instance answers. To run it:

    set -a; . /caminho/para/a/instancia/.env; set +a
    .venv/bin/python -m pytest tests/test_smoke_ao_vivo.py -q

Point AD_MCP_SMOKE_URL somewhere else to smoke a different instance.
"""

import json
import os
import urllib.error
import urllib.request

import pytest

URL = os.getenv("AD_MCP_SMOKE_URL", "http://127.0.0.1:8853/mcp")
TOKEN = os.getenv("AD_MCP_API_TOKEN", "")


def _rpc(method, params, timeout=120):
    corpo = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    req = urllib.request.Request(
        URL, data=corpo.encode(),
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _tool(nome, **args):
    r = _rpc("tools/call", {"name": nome, "arguments": args})
    assert "error" not in r, r["error"]
    return json.loads(r["result"]["content"][0]["text"])


def _instancia_responde():
    if not TOKEN:
        return False
    try:
        _rpc("tools/list", {}, timeout=10)
        return True
    except (urllib.error.URLError, OSError, TimeoutError):
        return False


pytestmark = pytest.mark.skipif(
    not _instancia_responde(),
    reason="instancia multi-AD nao esta no ar ou AD_MCP_API_TOKEN nao foi exportado",
)


@pytest.fixture(scope="module")
def servidores():
    catalogo = _tool("ad_list_ad_servers")
    assert catalogo["total"] >= 1
    return [s["ad_server"] for s in catalogo["servidores"] if s["habilitado"]]


def test_catalogo_nao_expoe_credenciais():
    bruto = json.dumps(_tool("ad_list_ad_servers"))
    assert "password" not in bruto and "bind_dn" not in bruto


def test_catalogo_traz_o_controlador_de_dominio():
    for s in _tool("ad_list_ad_servers")["servidores"]:
        assert s["controlador_de_dominio"] != "nao informado", s["ad_server"]
        assert s["host"], s["ad_server"]


def test_toda_conexao_esta_de_pe(servidores):
    quebrados = []
    for nome in servidores:
        estado = _tool("ad_test_ldap_connection_status", ad_server=nome)
        if not (estado.get("connected") and estado.get("search_test")):
            quebrados.append((nome, estado.get("error") or estado))
    assert not quebrados, f"servidores sem conexao: {quebrados}"


def test_leitura_devolve_dados_do_dominio_pedido(servidores):
    for nome in servidores:
        payload = _tool("ad_list_users_with_filters", ad_server=nome,
                        attributes=["sAMAccountName"])
        assert payload.get("success") is not False, (nome, payload.get("error"))
        assert payload["count"] >= 1, nome


def test_busca_em_todos_os_servidores(servidores):
    payload = _tool("ad_get_user_details_by_username", username="Administrator")
    assert payload["modo_de_busca"] == "TODOS OS SERVIDORES"
    assert payload["servidores_consultados"] == len(servidores)
    assert payload["encontrado_em"], "Administrator existe em todo AD"


def test_escrita_sem_servidor_e_recusada():
    payload = _tool("ad_delete_user_account_permanently", username="__nao_execute__")
    assert payload["sucesso"] is False
    assert payload["erro"] == "AD_SERVER_OBRIGATORIO_PARA_ESCRITA"


def test_escrita_sem_confirmacao_e_recusada(servidores):
    payload = _tool("ad_modify_user_attributes", ad_server=servidores[0],
                    username="__nao_execute__", attributes={})
    assert payload.get("permitted") is False
    assert payload.get("confirm_with")


def test_entrada_torta_nao_vira_excecao(servidores):
    """A weak model's mistakes must come back as instructions, not tracebacks."""
    casos = [
        ("ad_get_user_details_by_username", {"ad_server": [servidores[0]],
                                             "username": "Administrator"}),
        ("ad_get_inactive_users_by_days", {"ad_server": servidores[0], "days": "90"}),
        ("ad_list_users_with_filters", {"ad_server": servidores[0],
                                        "attributes": '["sAMAccountName"]'}),
        ("ad_get_user_details_by_username", {"ad_server": servidores[0]}),
        ("ad-multi-ad_list_ad_servers", {}),
    ]
    for nome, args in casos:
        r = _rpc("tools/call", {"name": nome, "arguments": args})
        assert "error" not in r, f"{nome} quebrou o protocolo: {r.get('error')}"
        json.loads(r["result"]["content"][0]["text"])  # sempre JSON utilizavel
