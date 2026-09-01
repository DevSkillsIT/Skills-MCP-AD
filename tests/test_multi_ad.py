"""Tests for the multi-AD layer (one process, N directories).

These tests never touch a real directory: no LDAP connection is opened because
the pool builds a server's connection only when a tool targets it, and the
routing decisions under test happen before that point.
"""

import asyncio
import json

import pytest

from active_directory_mcp.config.multi_loader import (
    MultiConfigError,
    load_multi_config,
    normalize_name,
)
from active_directory_mcp.core.ad_pool import ADServerPool
from active_directory_mcp.server_fastapi import ActiveDirectoryMCPFastAPI


def _ad_block(domain: str, host: str, label: str, aliases):
    base_dn = ",".join(f"DC={p}" for p in domain.split("."))
    return {
        "label": label,
        "aliases": aliases,
        "enabled": True,
        "active_directory": {
            "server": f"ldaps://{host}:636",
            "use_ssl": True,
            "domain": domain,
            "base_dn": base_dn,
            "bind_dn": f"CN=svc-mcp,{base_dn}",
            "password": "senha-de-teste-nao-usada",
            "timeout": 5,
        },
        "organizational_units": {
            "users_ou": f"OU=Users,{base_dn}",
            "groups_ou": f"OU=Groups,{base_dn}",
            "computers_ou": f"OU=Computers,{base_dn}",
            "service_accounts_ou": f"OU=Services,{base_dn}",
        },
        "client": {"name": label, "slug": label.lower().replace(" ", "-"), "type": "cliente"},
    }


@pytest.fixture
def servers_file(tmp_path):
    payload = {
        "version": 1,
        "servers": {
            "alfa": _ad_block("alfa.local", "10.0.0.1", "Cliente Alfa", ["alfinha"]),
            "beta": _ad_block("beta.local", "10.0.0.2", "Cliente Beta", ["betinha"]),
        },
    }
    path = tmp_path / "ad-servers.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


@pytest.fixture
def server(servers_file):
    return ActiveDirectoryMCPFastAPI(port=0, servers_path=servers_file, mode="multi")


@pytest.fixture
def single_server(monkeypatch, tmp_path):
    """A single-AD instance with the LDAP layer stubbed out."""
    import active_directory_mcp.server_fastapi as mod

    class FakeLDAP:
        def __init__(self, *a, **k):
            pass

        def test_connection(self):
            return {"connected": True, "server": "fake"}

        def disconnect(self):
            pass

    config = _ad_block("solo.local", "10.0.0.9", "Solo", [])
    for meta in ("label", "aliases", "enabled"):
        config.pop(meta)
    path = tmp_path / "ad-config.json"
    path.write_text(json.dumps(config), encoding="utf-8")

    monkeypatch.setattr(mod, "LDAPManager", FakeLDAP)
    return mod.ActiveDirectoryMCPFastAPI(config_path=str(path), port=0, mode="single")


def call(server, name, **arguments):
    result = asyncio.run(
        server.handle_tools_call({"name": name, "arguments": arguments})
    )
    return json.loads(result["content"][0]["text"])


# ------------------------------------------------------------------ resolution

def test_resolve_aceita_slug_alias_dominio_e_nome(servers_file):
    pool = ADServerPool(load_multi_config(servers_file))
    for wanted in ["alfa", "alfinha", "alfa.local", "Cliente Alfa", "ALFA", "cliente-alfa"]:
        bundle, error = pool.resolve_or_error(wanted)
        assert error is None, f"{wanted!r} deveria resolver: {error}"
        assert bundle.key == "alfa"


def test_servidor_desconhecido_nao_cai_em_outro(servers_file):
    pool = ADServerPool(load_multi_config(servers_file))
    bundle, error = pool.resolve_or_error("gama")
    assert bundle is None
    assert error["erro"] == "AD_SERVER_DESCONHECIDO"
    # The refusal must carry the catalogue, so the model can correct itself.
    assert {s["ad_server"] for s in error["servidores_disponiveis"]} == {"alfa", "beta"}


def test_prefixo_ambiguo_nao_escolhe_um(tmp_path):
    payload = {"version": 1, "servers": {
        "cliente-norte": _ad_block("norte.local", "10.0.0.3", "Cliente Norte", []),
        "cliente-sul": _ad_block("sul.local", "10.0.0.4", "Cliente Sul", []),
    }}
    path = tmp_path / "s.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    pool = ADServerPool(load_multi_config(str(path)))
    bundle, error = pool.resolve_or_error("cliente")
    assert bundle is None
    assert error["erro"] == "AD_SERVER_AMBIGUO"
    assert sorted(error["candidatos"]) == ["cliente-norte", "cliente-sul"]


def test_alias_repetido_derruba_o_boot(tmp_path):
    alfa = _ad_block("alfa.local", "10.0.0.1", "Cliente Alfa", ["matriz"])
    beta = _ad_block("beta.local", "10.0.0.2", "Cliente Beta", ["matriz"])
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"version": 1, "servers": {"alfa": alfa, "beta": beta}}),
                    encoding="utf-8")
    with pytest.raises(MultiConfigError, match="ambiguo"):
        load_multi_config(str(path))


def test_servidor_invalido_fica_visivel_e_recusado(tmp_path):
    quebrado = _ad_block("gama.local", "10.0.0.5", "Cliente Gama", [])
    quebrado["active_directory"].pop("base_dn")          # required field
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"version": 1, "servers": {
        "alfa": _ad_block("alfa.local", "10.0.0.1", "Cliente Alfa", []),
        "gama": quebrado,
    }}), encoding="utf-8")

    entries = load_multi_config(str(path))
    assert "gama" in entries, "servidor invalido nao pode sumir da listagem"
    assert not entries["gama"].valid

    pool = ADServerPool(entries)
    bundle, error = pool.resolve_or_error("gama")
    assert bundle is None
    assert error["erro"] == "AD_SERVER_CONFIG_INVALIDA"
    listed = {s["ad_server"]: s["status"] for s in pool.list_servers()["servidores"]}
    assert listed["gama"] == "configuracao_invalida"


def test_normalizacao_ignora_acento_e_caixa():
    assert normalize_name("MAGALHÃES") == normalize_name("magalhaes")
    assert normalize_name("Cliente Exemplo") == "cliente-exemplo"


# ---------------------------------------------------------------------- schema

def test_ad_server_obrigatorio_so_na_escrita(server):
    """Reads may omit the server (meaning "all"); writes may not."""
    for name, tool in server.tools.items():
        schema = tool["inputSchema"]
        if tool.get("global"):
            assert "ad_server" not in schema.get("properties", {}), name
            continue
        assert "ad_server" in schema["properties"], name
        obrigatorio = "ad_server" in (schema.get("required") or [])
        assert obrigatorio == bool(tool.get("write")), (
            f"{name}: escrita={tool.get('write')} mas required={obrigatorio}"
        )


def test_multi_so_acrescenta_o_catalogo(server, single_server):
    """Parity guard: the two modes share one registry.

    A tool added later shows up in both automatically; if the sets ever differ
    by anything other than the catalogue tool, this fails.
    """
    assert server.tools["ad_list_ad_servers"]["global"] is True
    assert server.tools["ad_check_ad_server_configured"]["global"] is True
    # Multi trades the two client-shaped catalogue tools for two server-shaped ones.
    assert set(server.tools) - set(single_server.tools) == {
        "ad_list_ad_servers", "ad_check_ad_server_configured",
    }
    assert set(single_server.tools) - set(server.tools) == {
        "ad_list_configured_clients", "ad_check_client_configuration",
    }


def test_check_por_nome_de_cliente_devolve_o_ad_server(server):
    achou = call(server, "ad_check_ad_server_configured", server_name="Cliente Beta")
    assert achou["exists"] is True
    assert achou["ad_server"] == "beta"

    nao = call(server, "ad_check_ad_server_configured", server_name="Cliente Gama")
    assert nao["exists"] is False
    assert nao["erro"] == "AD_SERVER_DESCONHECIDO"


def test_modo_single_nao_ganha_o_parametro(single_server):
    """Single-AD keeps the schema it always had -- the layer is opt-in."""
    assert single_server.multi is False
    assert "ad_list_ad_servers" not in single_server.tools
    for name, tool in single_server.tools.items():
        assert "ad_server" not in tool["inputSchema"].get("properties", {}), name
        assert "ad_server" not in (tool["inputSchema"].get("required") or []), name


# --------------------------------------------------------------------- routing

def test_leitura_sem_ad_server_roda_em_todos(server):
    """The convenience the user asked for: no server named means look everywhere."""
    server.tools["ad_list_users_with_filters"]["handler"] = lambda p: {"users": [{"cn": "x"}]}
    payload = call(server, "ad_list_users_with_filters")
    assert payload["modo_de_busca"] == "TODOS OS SERVIDORES"
    assert set(payload["encontrado_em"]) == {"alfa", "beta"}
    assert "nao foi informado" in payload["nota"]


def test_escrita_sem_ad_server_e_recusada(server):
    """A write must never fan out, and must never pick a directory on its own."""
    payload = call(server, "ad_delete_user_account_permanently", username="joao")
    assert payload["sucesso"] is False
    assert payload["erro"] == "AD_SERVER_OBRIGATORIO_PARA_ESCRITA"
    assert {s["ad_server"] for s in payload["servidores_disponiveis"]} == {"alfa", "beta"}


def test_servidor_desconhecido_continua_recusado(server):
    payload = call(server, "ad_list_users_with_filters", ad_server="nao-existe")
    assert payload["sucesso"] is False
    assert payload["erro"] == "AD_SERVER_DESCONHECIDO"


def test_roteamento_liga_o_diretorio_pedido(server):
    """The bound directory must be the one named, for every call."""
    seen = []

    def spy(params):
        seen.append((server._bound_server, server.config.active_directory.domain))
        return {"ok": True}

    server.tools["ad_test_ldap_connection_status"]["handler"] = spy

    call(server, "ad_test_ldap_connection_status", ad_server="beta")
    call(server, "ad_test_ldap_connection_status", ad_server="alfinha")
    call(server, "ad_test_ldap_connection_status", ad_server="alfa.local")

    assert seen == [
        ("beta", "beta.local"),
        ("alfa", "alfa.local"),
        ("alfa", "alfa.local"),
    ]


def test_estado_do_cliente_nao_sobrevive_a_chamada(server):
    """After a call nothing stays bound: no implicit default directory."""
    server.tools["ad_test_ldap_connection_status"]["handler"] = lambda p: {"ok": True}
    call(server, "ad_test_ldap_connection_status", ad_server="alfa")

    for attr in ActiveDirectoryMCPFastAPI._TENANT_ATTRS:
        assert getattr(server, attr) is None, attr
    assert server._bound_server is None


def test_tool_global_responde_sem_ad_server(server):
    payload = call(server, "ad_list_ad_servers")
    assert payload["total"] == 2
    assert {s["ad_server"] for s in payload["servidores"]} == {"alfa", "beta"}


# -------------------------------------------------------------------- security

def test_catalogo_nao_expoe_credenciais(server):
    raw = json.dumps(call(server, "ad_list_ad_servers"))
    assert "senha-de-teste-nao-usada" not in raw
    assert "password" not in raw
    assert "bind_dn" not in raw
    assert "CN=svc-mcp" not in raw


def test_escrita_exige_confirmacao_do_cliente_certo(server):
    negado = call(server, "ad_create_user_account", ad_server="alfa",
                  username="teste", password="x", first_name="T", last_name="T")
    assert negado["permitted"] is False
    assert negado["mode"] == "requires_confirmation"

    errado = call(server, "ad_create_user_account", ad_server="alfa",
                  username="teste", password="x", first_name="T", last_name="T",
                  client_confirmation="beta")
    assert errado["permitted"] is False
    assert errado["mode"] == "wrong_confirmation"


def test_health_nao_afirma_saude_de_quem_nao_foi_usado(server):
    health = server._handle_health({})
    assert health["mode"] == "multi"
    assert health["total_servidores"] == 2
    assert {s["status"] for s in health["servidores"]} == {"nao_conectado"}


# ------------------------------------------------- configuracao por ambiente
# conftest.py clears AD_MCP_* so no test accidentally reaches production. That
# isolation would also hide a broken env-var contract, so the contract gets
# explicit tests that set the variables on purpose.

def test_modo_vem_do_ambiente(monkeypatch, servers_file):
    monkeypatch.setenv("AD_MCP_MODE", "multi")
    monkeypatch.setenv("AD_MCP_SERVERS", servers_file)
    servidor = ActiveDirectoryMCPFastAPI(port=0)
    assert servidor.multi is True
    assert servidor.servers_path == servers_file


def test_sem_ambiente_o_padrao_e_single(monkeypatch, tmp_path):
    import active_directory_mcp.server_fastapi as mod

    class FakeLDAP:
        def __init__(self, *a, **k):
            pass

        def test_connection(self):
            return {"connected": True, "server": "fake"}

        def disconnect(self):
            pass

    config = _ad_block("solo.local", "10.0.0.9", "Solo", [])
    for meta in ("label", "aliases", "enabled"):
        config.pop(meta)
    caminho = tmp_path / "ad-config.json"
    caminho.write_text(json.dumps(config), encoding="utf-8")

    monkeypatch.setattr(mod, "LDAPManager", FakeLDAP)
    monkeypatch.setenv("AD_MCP_CONFIG", str(caminho))
    servidor = mod.ActiveDirectoryMCPFastAPI(port=0)
    assert servidor.mode == "single"
    assert servidor.multi is False


def test_modo_invalido_no_ambiente_e_recusado(monkeypatch, servers_file):
    monkeypatch.setenv("AD_MCP_MODE", "multiplo")
    monkeypatch.setenv("AD_MCP_SERVERS", servers_file)
    with pytest.raises(ValueError, match="AD_MCP_MODE"):
        ActiveDirectoryMCPFastAPI(port=0)


def test_multi_sem_arquivo_de_servidores_falha_claro(monkeypatch):
    monkeypatch.setenv("AD_MCP_MODE", "multi")
    monkeypatch.delenv("AD_MCP_SERVERS", raising=False)
    with pytest.raises(MultiConfigError, match="AD_MCP_SERVERS"):
        ActiveDirectoryMCPFastAPI(port=0)


def test_parametro_explicito_vence_o_ambiente(monkeypatch, servers_file):
    """An explicit mode= must win, or a stray shell variable steers the process."""
    monkeypatch.setenv("AD_MCP_MODE", "multi")
    monkeypatch.setenv("AD_MCP_SERVERS", servers_file)
    servidor = ActiveDirectoryMCPFastAPI(port=0, servers_path=servers_file, mode="multi")
    assert servidor.multi is True
