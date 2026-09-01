"""Regression test: creating without an explicit OU must work.

group.py and computer.py read self.ldap.ad_config.organizational_units, a field
that does not exist on ActiveDirectoryConfig. Creating a group or a computer
without passing `ou` therefore raised AttributeError, and the configured
users_ou / groups_ou / computers_ou never had any effect at all.

The unit tests hid this by mocking ad_config with a Mock(), which happily
answers any attribute.
"""

from unittest.mock import Mock

import pytest

from active_directory_mcp.config.models import (
    ActiveDirectoryConfig, OrganizationalUnitsConfig)
from active_directory_mcp.tools.computer import ComputerTools
from active_directory_mcp.tools.group import GroupTools
from active_directory_mcp.tools.user import UserTools

BASE = "DC=exemplo,DC=local"


def _ldap(ou_config=None):
    """A fake manager carrying the REAL config objects, not a bare Mock."""
    m = Mock()
    m.ad_config = ActiveDirectoryConfig(
        server="ldap://exemplo.local:389", domain="exemplo.local", base_dn=BASE,
        bind_dn=f"CN=svc,{BASE}", password="x")
    m.ou_config = ou_config
    m.search.return_value = []
    m.add.return_value = True
    return m


OUS = OrganizationalUnitsConfig(
    users_ou=f"OU=Pessoas,{BASE}", groups_ou=f"OU=Grupos,{BASE}",
    computers_ou=f"OU=Maquinas,{BASE}", service_accounts_ou=f"OU=Servicos,{BASE}")


@pytest.mark.parametrize("classe,tipo,esperado", [
    (UserTools, "users", f"OU=Pessoas,{BASE}"),
    (GroupTools, "groups", f"OU=Grupos,{BASE}"),
    (ComputerTools, "computers", f"OU=Maquinas,{BASE}"),
])
def test_ou_configurada_e_respeitada(classe, tipo, esperado):
    """What the config declares is what gets used."""
    assert classe(_ldap(OUS))._default_ou(tipo) == esperado


@pytest.mark.parametrize("classe,tipo,esperado", [
    (UserTools, "users", f"CN=Users,{BASE}"),
    (GroupTools, "groups", f"CN=Users,{BASE}"),
    (ComputerTools, "computers", f"CN=Computers,{BASE}"),
])
def test_sem_config_cai_no_container_padrao_do_ad(classe, tipo, esperado):
    """No OU configured: the AD default containers, which always exist."""
    assert classe(_ldap(None))._default_ou(tipo) == esperado


def test_criar_grupo_sem_ou_nao_estoura():
    """The actual crash: create_group(ou=None) raised AttributeError."""
    tools = GroupTools(_ldap(OUS))
    resultado = tools.create_group("grupo-teste", description="x")
    import json
    payload = json.loads(resultado[0].text)
    assert payload.get("success") is not False, payload.get("error")
    assert "OU=Grupos" in payload.get("dn", ""), payload


def test_criar_computador_sem_ou_nao_estoura():
    tools = ComputerTools(_ldap(OUS))
    resultado = tools.create_computer("PC-TESTE")
    import json
    payload = json.loads(resultado[0].text)
    assert payload.get("success") is not False, payload.get("error")
    assert "OU=Maquinas" in payload.get("dn", ""), payload
