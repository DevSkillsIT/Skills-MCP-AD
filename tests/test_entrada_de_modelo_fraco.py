"""The server must absorb what a weak model actually sends.

Measured against the live instance before this hardening existed:

  username faltando          -> JSON-RPC error with the message "'username'"
  days="90"                  -> "unsupported type for timedelta days component: str"
  attributes='["cn"]'        -> "invalid attribute type [\"cn\"]"
  attributes=["cn", None]    -> "argument of type 'NoneType' is not iterable"
  days=-5                    -> accepted, answering "inactive for -5 days"
  ou de outro dominio        -> "invalid server address" (says nothing about the OU)
  username="CN=x,DC=..."     -> "not found", though the account plainly exists
  tool "ad-multi-ad_..."     -> "Unknown tool"

None of these are the model's fault to fix at call time: the server knows its
own schema and can coerce, or refuse with a sentence that says what to do.
"""

import asyncio
import json

import pytest

from active_directory_mcp.server_fastapi import ActiveDirectoryMCPFastAPI


@pytest.fixture
def servidor(tmp_path):
    bloco = {
        "label": "Alfa", "aliases": ["alfinha"], "enabled": True,
        "active_directory": {
            "server": "ldaps://10.0.0.1:636", "domain": "alfa.local",
            "base_dn": "DC=alfa,DC=local", "bind_dn": "CN=svc,DC=alfa,DC=local",
            "password": "x", "timeout": 5},
        "organizational_units": {
            "users_ou": "CN=Users,DC=alfa,DC=local", "groups_ou": "CN=Users,DC=alfa,DC=local",
            "computers_ou": "CN=Computers,DC=alfa,DC=local",
            "service_accounts_ou": "CN=Users,DC=alfa,DC=local"},
    }
    caminho = tmp_path / "s.json"
    caminho.write_text(json.dumps({"version": 1, "servers": {"alfa": bloco}}), encoding="utf-8")
    return ActiveDirectoryMCPFastAPI(port=0, servers_path=str(caminho), mode="multi")


def chamar(servidor, nome, **args):
    r = asyncio.run(servidor.handle_tools_call({"name": nome, "arguments": args}))
    return json.loads(r["content"][0]["text"])


def espiar(servidor, tool_name):
    """Replace a handler with a spy so we can see the sanitized arguments."""
    visto = {}

    def spy(params):
        visto.update(params)
        return {"ok": True}

    servidor.tools[tool_name]["handler"] = spy
    return visto


# ------------------------------------------------------------- tipos trocados

def test_lista_de_um_elemento_no_ad_server(servidor):
    espiar(servidor, "ad_get_user_details_by_username")
    r = chamar(servidor, "ad_get_user_details_by_username", ad_server=["alfa"], username="joao")
    assert r.get("ok") is True, r


def test_inteiro_como_string(servidor):
    visto = espiar(servidor, "ad_get_inactive_users_by_days")
    chamar(servidor, "ad_get_inactive_users_by_days", ad_server="alfa", days="90")
    assert visto["days"] == 90 and isinstance(visto["days"], int)


def test_lista_como_string_json(servidor):
    visto = espiar(servidor, "ad_list_users_with_filters")
    chamar(servidor, "ad_list_users_with_filters", ad_server="alfa",
           attributes='["sAMAccountName", "mail"]')
    assert visto["attributes"] == ["sAMAccountName", "mail"]


def test_lista_como_string_simples(servidor):
    visto = espiar(servidor, "ad_list_users_with_filters")
    chamar(servidor, "ad_list_users_with_filters", ad_server="alfa", attributes="sAMAccountName")
    assert visto["attributes"] == ["sAMAccountName"]


def test_none_dentro_da_lista_some(servidor):
    visto = espiar(servidor, "ad_list_users_with_filters")
    chamar(servidor, "ad_list_users_with_filters", ad_server="alfa",
           attributes=["sAMAccountName", None, "mail"])
    assert visto["attributes"] == ["sAMAccountName", "mail"]


def test_objeto_como_string_json(servidor):
    visto = espiar(servidor, "ad_modify_user_attributes")
    chamar(servidor, "ad_modify_user_attributes", ad_server="alfa", username="joao",
           attributes='{"title": "chefe"}', client_confirmation="alfa")
    assert visto["attributes"] == {"title": "chefe"}


# ------------------------------------------------- identificadores mal-formados

@pytest.mark.parametrize("entrada", [
    "CN=Joao Silva,CN=Users,DC=alfa,DC=local",
    "ALFA\\joao.silva",
    "joao.silva@alfa.local",
    "  joao.silva  ",
])
def test_username_em_qualquer_formato_vira_o_login(servidor, entrada):
    visto = espiar(servidor, "ad_get_user_details_by_username")
    chamar(servidor, "ad_get_user_details_by_username", ad_server="alfa", username=entrada)
    assert visto["username"] in ("joao.silva", "Joao Silva"), visto


# ------------------------------------------------------- recusas com instrucao

def test_parametro_obrigatorio_ausente_explica_o_que_falta(servidor):
    r = chamar(servidor, "ad_get_user_details_by_username", ad_server="alfa")
    assert r["sucesso"] is False
    assert r["erro"] == "PARAMETRO_OBRIGATORIO_AUSENTE"
    assert "username" in r["parametros_faltando"]
    assert "username" in r["mensagem"]


def test_dias_negativos_sao_recusados(servidor):
    r = chamar(servidor, "ad_get_inactive_users_by_days", ad_server="alfa", days=-5)
    assert r["sucesso"] is False
    assert r["erro"] == "PARAMETRO_INVALIDO"


def test_dias_absurdos_sao_recusados(servidor):
    r = chamar(servidor, "ad_get_inactive_users_by_days", ad_server="alfa", days=999999)
    assert r["sucesso"] is False
    assert r["erro"] == "PARAMETRO_INVALIDO"


def test_ad_server_nao_textual_diz_o_que_esperava(servidor):
    r = chamar(servidor, "ad_get_user_details_by_username", ad_server=7, username="joao")
    assert r["sucesso"] is False
    assert "texto" in r["mensagem"].lower()


def test_ou_de_outro_dominio_e_recusada_com_o_motivo(servidor):
    r = chamar(servidor, "ad_list_users_with_filters", ad_server="alfa",
               ou="OU=Users,DC=beta,DC=local")
    assert r["sucesso"] is False
    assert r["erro"] == "OU_FORA_DO_DOMINIO"
    assert "DC=alfa,DC=local" in r["mensagem"]


# ------------------------------------------------------------ nome da tool

def test_nome_de_tool_com_prefixo_do_hub(servidor):
    r = asyncio.run(servidor.handle_tools_call(
        {"name": "ad-multi-ad_list_ad_servers", "arguments": {}}))
    payload = json.loads(r["content"][0]["text"])
    assert payload.get("total") == 1


def test_tool_inexistente_sugere_as_parecidas(servidor):
    r = asyncio.run(servidor.handle_tools_call(
        {"name": "ad_listar_usuarios", "arguments": {}}))
    payload = json.loads(r["content"][0]["text"])
    assert payload["erro"] == "TOOL_DESCONHECIDA"
    assert payload["tools_parecidas"]


# --------------------------------------------------------------- confirmacao

def test_confirmacao_aceita_o_dominio_completo(servidor):
    espiar(servidor, "ad_modify_user_attributes")
    r = chamar(servidor, "ad_modify_user_attributes", ad_server="alfa", username="joao",
               attributes={"title": "x"}, client_confirmation="alfa.local")
    assert r.get("ok") is True, r
