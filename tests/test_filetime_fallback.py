"""Regression test: an unconvertible timestamp is not "now".

_convert_filetime_to_datetime ended with `return datetime.now()`. Any value it
did not recognise -- notably the ISO string that comes back after a JSON round
trip -- became the current time, so a computer that had not logged on for
months reported 0 days of inactivity and never showed up as stale.

An unknown value must read as unknown, never as the most reassuring value.
"""

from datetime import datetime, timedelta, timezone

import pytest

from active_directory_mcp.tools.computer import ComputerTools


class FakeLDAP:
    class ad_config:
        base_dn = "DC=exemplo,DC=local"
    ou_config = None


@pytest.fixture
def tools():
    return ComputerTools(FakeLDAP())


def test_valor_ilegivel_nao_vira_agora(tools):
    assert tools._convert_filetime_to_datetime("nao-e-uma-data") is None
    assert tools._convert_filetime_to_datetime(None) is None
    assert tools._convert_filetime_to_datetime(0) is None


def test_string_iso_e_entendida(tools):
    quando = datetime(2020, 3, 4, 15, 30)
    assert tools._convert_filetime_to_datetime(quando.isoformat()) == quando


def test_datetime_e_int_continuam_funcionando(tools):
    agora = datetime(2024, 1, 2, 3, 4)
    assert tools._convert_filetime_to_datetime(agora) == agora
    ticks = int((agora - datetime(1601, 1, 1)).total_seconds() * 10**7)
    assert tools._convert_filetime_to_datetime(ticks) == agora


def test_computador_parado_ha_90_dias_e_stale(tools):
    """The case measured: after a JSON round trip lastLogon is a string."""
    parado = (datetime.now() - timedelta(days=90)).isoformat()
    item = {"sAMAccountName": "VELHOPC$", "lastLogon": parado}
    assert tools._get_days_since_last_logon(item) >= 89
    assert tools._is_computer_stale(item, 30) is True


def test_computador_de_hoje_nao_e_stale(tools):
    hoje = (datetime.now() - timedelta(hours=2)).isoformat()
    item = {"sAMAccountName": "NOVOPC$", "lastLogon": hoje}
    assert tools._is_computer_stale(item, 30) is False
