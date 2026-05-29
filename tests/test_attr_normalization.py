"""Regression tests for LDAP attribute normalization and timezone-safe date math.

These cover bugs found during the ad-skills black-box validation (2026-05):
- Single-valued LDAP attributes returned by ldap3 as a scalar (str) instead of a
  list, causing len()/iteration over characters (groups with exactly 1 member).
- days_since_last_logon / password_age_days returning None because
  ``datetime.now()`` (naive) was subtracted from a tz-aware ldap3 datetime.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from active_directory_mcp.tools.group import GroupTools
from active_directory_mcp.tools.computer import ComputerTools
from active_directory_mcp.tools.security import SecurityTools


@pytest.fixture
def mock_ldap_manager():
    manager = Mock()
    manager.ad_config = Mock()
    manager.ad_config.base_dn = "DC=test,DC=local"
    return manager


@pytest.fixture
def group_tools(mock_ldap_manager):
    return GroupTools(mock_ldap_manager)


@pytest.fixture
def computer_tools(mock_ldap_manager):
    return ComputerTools(mock_ldap_manager)


@pytest.fixture
def security_tools(mock_ldap_manager):
    return SecurityTools(mock_ldap_manager)


class TestGetAttrList:
    """_get_attr_list must normalize None/scalar/list to a list."""

    def test_missing_attribute_returns_empty_list(self, group_tools):
        assert group_tools._get_attr_list({}, "member") == []

    def test_none_value_returns_empty_list(self, group_tools):
        assert group_tools._get_attr_list({"member": None}, "member") == []

    def test_scalar_string_is_wrapped_in_list(self, group_tools):
        dn = "CN=Administrator,CN=Users,DC=test,DC=local"
        result = group_tools._get_attr_list({"member": dn}, "member")
        assert result == [dn]
        # Critical: must NOT iterate the string char-by-char.
        assert len(result) == 1

    def test_list_value_is_returned_as_is(self, group_tools):
        dns = ["CN=a,DC=test", "CN=b,DC=test"]
        assert group_tools._get_attr_list({"member": dns}, "member") == dns


class TestSingleMemberGroupRegression:
    """A group with exactly one member must report member_count == 1."""

    def test_member_count_with_scalar_member(self, group_tools, mock_ldap_manager):
        single_dn = "CN=Administrator,CN=Users,DC=test,DC=local"
        mock_ldap_manager.search.return_value = [
            {
                "dn": "CN=Schema Admins,CN=Users,DC=test,DC=local",
                "attributes": {
                    "sAMAccountName": "Schema Admins",
                    "groupType": -2147483640,
                    "member": single_dn,            # scalar, as ldap3 returns it
                    "memberOf": "CN=Denied,DC=test",
                },
            }
        ]
        import json
        payload = json.loads(group_tools.get_group("Schema Admins")[0].text)
        assert payload["computed"]["member_count"] == 1
        assert payload["computed"]["parent_groups_count"] == 1

    def test_add_first_member_to_empty_group(self, group_tools, mock_ldap_manager):
        # Empty group: ldap3 may return member as None -> must not raise TypeError.
        mock_ldap_manager.search.return_value = [
            {"dn": "CN=NewGroup,DC=test,DC=local", "attributes": {"member": None}}
        ]
        mock_ldap_manager.modify.return_value = True
        import json
        payload = json.loads(
            group_tools.add_member("NewGroup", "CN=user,DC=test,DC=local")[0].text
        )
        assert payload["success"] is True


class TestTimezoneSafeDateMath:
    """Day calculations must work with tz-aware ldap3 datetimes."""

    def test_days_since_last_logon_with_aware_datetime(self, computer_tools):
        ten_days_ago = datetime.now(timezone.utc) - timedelta(days=10)
        days = computer_tools._get_days_since_last_logon({"lastLogon": ten_days_ago})
        assert days is not None
        assert days == 10

    def test_password_age_with_aware_datetime(self, computer_tools):
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        age = computer_tools._get_password_age_days({"pwdLastSet": thirty_days_ago})
        assert age is not None
        assert age == 30

    def test_security_days_since_last_logon_with_aware_datetime(self, security_tools):
        five_days_ago = datetime.now(timezone.utc) - timedelta(days=5)
        days = security_tools._get_days_since_last_logon({"lastLogon": five_days_ago})
        assert days == 5

    def test_zero_last_logon_returns_none(self, computer_tools):
        assert computer_tools._get_days_since_last_logon({"lastLogon": 0}) is None

    def test_epoch_1601_is_never(self, computer_tools):
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        assert computer_tools._get_days_since_last_logon({"lastLogon": epoch}) is None

    def test_calculate_password_age_aware(self, security_tools):
        ninety = datetime.now(timezone.utc) - timedelta(days=90)
        assert security_tools._calculate_password_age({"pwdLastSet": ninety}) == 90

    def test_logon_or_never_handles_epoch_and_real(self, security_tools):
        assert security_tools._logon_or_never(0) == "Never"
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        assert security_tools._logon_or_never(epoch) == "Never"
        real = datetime.now(timezone.utc)
        assert security_tools._logon_or_never(real) == real


class TestEscapeLdapFilter:
    """Backslash must be escaped first so introduced escapes aren't corrupted."""

    def test_asterisk_escape_not_double_escaped(self, group_tools):
        # 'a*b' must become 'a\2ab', NOT 'a\5c2ab'.
        assert group_tools._escape_ldap_filter("a*b") == r"a\2ab"

    def test_literal_backslash_escaped_once(self, group_tools):
        assert group_tools._escape_ldap_filter("a\\b") == r"a\5cb"

    def test_plain_value_unchanged(self, group_tools):
        assert group_tools._escape_ldap_filter("Sales Team") == "Sales Team"


class TestMemberOfNormalizationOtherEndpoints:
    """memberOf single-value must not be iterated char-by-char elsewhere."""

    def test_assess_account_risk_with_scalar_memberof(self, security_tools):
        # Single privileged group as scalar string must be detected (risk >= admin).
        data = {"memberOf": "CN=Domain Admins,CN=Users,DC=test,DC=local"}
        # Should not raise and should add admin risk -> not 'low'.
        assert security_tools._assess_account_risk(data) in ("high", "medium")
