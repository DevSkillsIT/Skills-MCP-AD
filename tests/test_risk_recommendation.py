"""Regression test: the recommendation must match the risk level.

_assess_user_security produces 'high'/'medium'/'low' and handed it to
_get_security_recommendation, which compared against 'HIGH'/'MEDIUM'. The
comparison never matched, so every account -- including a Domain Admin with a
non-expiring password -- got the low-risk advice.

Measured against a live domain, on its built-in Administrator account:
  risk_level: high
  risk_factors: ['Privileged account with non-expiring password',
                 'Member of 5 privileged groups']
  recommendation: "Monitor account activity and maintain current security posture"
"""

import pytest

from active_directory_mcp.tools.security import SecurityTools


class FakeLDAP:
    class ad_config:
        base_dn = "DC=exemplo,DC=local"


@pytest.fixture
def tools():
    return SecurityTools(FakeLDAP())


def test_conta_privilegiada_recebe_acao_imediata(tools):
    resultado = tools._assess_user_security(
        {"enabled": True, "password_not_required": False,
         "password_never_expires": True},
        [{"name": "Domain Admins"}],
    )
    assert resultado["risk_level"] == "high"
    assert "Immediate action" in resultado["recommendation"], (
        f"risco alto recebeu conselho de risco baixo: {resultado['recommendation']}"
    )


def test_conta_de_risco_medio_recebe_revisao(tools):
    resultado = tools._assess_user_security(
        {"enabled": True, "password_not_required": False,
         "password_never_expires": False},
        [{"name": "Backup Operators"}],
    )
    assert resultado["risk_level"] == "medium"
    assert "Review account permissions" in resultado["recommendation"]


def test_conta_comum_recebe_monitoramento(tools):
    resultado = tools._assess_user_security(
        {"enabled": True, "password_not_required": False,
         "password_never_expires": False},
        [],
    )
    assert resultado["risk_level"] == "low"
    assert "Monitor account activity" in resultado["recommendation"]


@pytest.mark.parametrize("grafia", ["high", "HIGH", "High"])
def test_recomendacao_nao_depende_da_caixa(tools, grafia):
    """Two spellings live in this file; the advice must not hinge on which."""
    assert "Immediate action" in tools._get_security_recommendation(grafia, [])


def test_niveis_de_risco_sao_os_anunciados_no_schema(tools):
    """get_schema_info advertises lowercase; every producer must agree."""
    anunciados = set(tools.get_schema_info()["risk_levels"])
    produzidos = {
        tools._calculate_admin_risk_level(["Password not required"], None),
        tools._calculate_admin_risk_level(["Password never expires"], None),
        tools._calculate_admin_risk_level([], None),
        tools._assess_user_security(
            {"enabled": True, "password_not_required": True,
             "password_never_expires": False}, [])["risk_level"],
    }
    assert produzidos <= anunciados, (
        f"niveis produzidos fora do schema: {produzidos - anunciados}"
    )
