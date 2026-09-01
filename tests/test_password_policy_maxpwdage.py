"""Regression test: maxPwdAge is a timedelta, not a list.

ldap3 decodes the AD Interval syntax (maxPwdAge, minPwdAge, lockoutDuration)
into datetime.timedelta. Indexing it with [0] raises TypeError and the whole
tool answers success=false, so no password policy violation is ever reported.
"""

import json
from datetime import datetime, timedelta, timezone

from active_directory_mcp.tools.security import SecurityTools


class FakeADConfig:
    base_dn = "DC=exemplo,DC=local"


class FakeLDAP:
    """Returns what ldap3 really returns for an AD domain object."""

    ad_config = FakeADConfig()

    def search(self, search_base, search_filter, attributes=None, **kwargs):
        if "objectClass=domain" in search_filter:
            return [{
                "dn": self.ad_config.base_dn,
                # AD stores maxPwdAge as a negative interval; ldap3 hands over a
                # timedelta, NOT a list.
                "attributes": {"maxPwdAge": timedelta(days=-42),
                               "minPwdAge": timedelta(days=-1)},
            }]
        old = datetime(2000, 1, 1)
        return [{
            "dn": f"CN=Antigo,{self.ad_config.base_dn}",
            "attributes": {
                "sAMAccountName": "antigo",
                "displayName": "Usuario Antigo",
                "pwdLastSet": old,
                "userAccountControl": 512,
                "accountExpires": 0,
            },
        }]


def _payload(result):
    return json.loads(result[0].text)


def test_maxpwdage_timedelta_nao_quebra_a_tool():
    tools = SecurityTools(FakeLDAP())
    payload = _payload(tools.get_password_policy_violations())

    assert payload.get("success") is not False, (
        f"a tool falhou em vez de avaliar a politica: {payload.get('error')}"
    )
    assert "password_violations" in payload
    assert payload["count"] >= 1, "senha de 2000 sob politica de 42 dias deve violar"
    assert any("expired" in v.lower()
               for violation in payload["password_violations"]
               for v in violation["violations"])


class FakeLDAPAware(FakeLDAP):
    """Some directories hand ldap3 timezone-aware datetimes."""

    def search(self, search_base, search_filter, attributes=None, **kwargs):
        results = super().search(search_base, search_filter, attributes, **kwargs)
        for row in results:
            for key, value in row["attributes"].items():
                if isinstance(value, datetime):
                    row["attributes"][key] = value.replace(tzinfo=timezone.utc)
        return results


def test_datetime_com_fuso_nao_quebra_a_comparacao():
    tools = SecurityTools(FakeLDAPAware())
    payload = _payload(tools.get_password_policy_violations())
    assert payload.get("success") is not False, payload.get("error")
    assert payload["count"] >= 1
