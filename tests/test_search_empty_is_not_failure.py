"""Regression test: an empty LDAP search is not a failed LDAP search.

ldap3's Connection.search() returns False for a BASE search whose filter simply
does not match, while connection.result['result'] is 0 (success). LDAPManager
raised LDAPException on the boolean alone, so a legitimate "no match" became an
error.

Measured against a live domain: audit_admin_accounts walks every member of each
privileged group with a BASE (objectClass=user) search. One member that is a
nested group -- not a user -- raised, aborting the remaining members of that
group. The audit reported 0 administrative accounts for a domain with 13
members in Domain Admins alone.
"""

from unittest.mock import MagicMock, patch

import pytest
from ldap3.core.exceptions import LDAPException

from active_directory_mcp.config.models import (
    ActiveDirectoryConfig, PerformanceConfig, SecurityConfig)
from active_directory_mcp.core.ldap_manager import LDAPManager


@pytest.fixture
def manager():
    m = LDAPManager(
        ActiveDirectoryConfig(
            server="ldap://exemplo.local:389", domain="exemplo.local",
            base_dn="DC=exemplo,DC=local",
            bind_dn="CN=svc,DC=exemplo,DC=local", password="x"),
        SecurityConfig(enable_tls=False),
        PerformanceConfig(),
    )
    yield m
    m._stop_keepalive()


def _conexao(retorno_search, codigo_result):
    conn = MagicMock()
    conn.bound = True
    conn.search.return_value = retorno_search
    conn.entries = []
    conn.result = {"result": codigo_result, "description":
                   "success" if codigo_result == 0 else "operationsError"}
    return conn


def test_busca_sem_resultado_devolve_lista_vazia(manager):
    """search() False + result 0 = nothing matched, not an error."""
    with patch.object(manager, "_ensure_connection", return_value=_conexao(False, 0)):
        assert manager.search("CN=Alguem,DC=exemplo,DC=local",
                              "(objectClass=user)", search_scope="BASE") == []


def test_dn_inexistente_devolve_lista_vazia(manager):
    """noSuchObject (32) is an absent object, not a broken query."""
    with patch.object(manager, "_ensure_connection", return_value=_conexao(False, 32)):
        assert manager.search("CN=Sumiu,DC=exemplo,DC=local",
                              "(objectClass=user)", search_scope="BASE") == []


def test_erro_real_continua_levantando(manager):
    """A genuine LDAP error must still raise -- silence would be worse."""
    with patch.object(manager, "_ensure_connection", return_value=_conexao(False, 1)):
        with pytest.raises(LDAPException):
            manager.search("DC=exemplo,DC=local", "(objectClass=user)")
