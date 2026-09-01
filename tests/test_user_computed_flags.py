"""Regression tests: the computed flags of ad_get_user_details_by_username.

ldap3 surfaces pwdLastSet and accountExpires as datetime, not as the raw
FILETIME int the code compared against. Both flags therefore answered False for
every user -- silently, because a bare except swallowed the TypeError.

Measured on production before the fix:
  - Guest (pwdLastSet 1601-01-01) -> password_expired False
  - a real account expired in 2018 -> account_expired False
"""

from datetime import datetime, timezone

from active_directory_mcp.tools.user import UserTools


class FakeLDAP:
    class ad_config:
        base_dn = "DC=exemplo,DC=local"


def tools():
    return UserTools(FakeLDAP())


# ------------------------------------------------------------ password_expired

def test_pwd_last_set_zero_como_int_expira():
    assert tools()._is_password_expired({"pwdLastSet": 0}) is True


def test_pwd_last_set_zero_como_datetime_1601_tambem_expira():
    """ldap3 renders FILETIME 0 as the 1601 epoch."""
    valor = datetime(1601, 1, 1, tzinfo=timezone.utc)
    assert tools()._is_password_expired({"pwdLastSet": valor}) is True


def test_senha_definida_nao_expira():
    valor = datetime(2024, 5, 1, tzinfo=timezone.utc)
    assert tools()._is_password_expired({"pwdLastSet": valor}) is False


# ------------------------------------------------------------- account_expired

def test_conta_expirada_no_passado_como_datetime():
    """The case that mattered: expired in 2018 and reported as not expired."""
    valor = datetime(2018, 10, 2, tzinfo=timezone.utc)
    assert tools()._is_account_expired({"accountExpires": valor}) is True


def test_conta_expirada_no_passado_como_int():
    filetime_2018 = int((datetime(2018, 10, 2) - datetime(1601, 1, 1)).total_seconds() * 10**7)
    assert tools()._is_account_expired({"accountExpires": filetime_2018}) is True


def test_nunca_expira_em_todas_as_formas():
    t = tools()
    assert t._is_account_expired({"accountExpires": 0}) is False
    assert t._is_account_expired({"accountExpires": 9223372036854775807}) is False
    # ldap3 renders the sentinel as year 9999
    assert t._is_account_expired(
        {"accountExpires": datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)}) is False


def test_expiracao_futura_nao_conta():
    futuro = datetime(2099, 1, 1, tzinfo=timezone.utc)
    assert tools()._is_account_expired({"accountExpires": futuro}) is False
