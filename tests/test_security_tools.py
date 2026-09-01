"""Tests for security and audit tools."""

import pytest
from unittest.mock import Mock, patch
import json
import base64
from datetime import datetime, timedelta

from active_directory_mcp.tools.security import SecurityTools
from mcp.types import TextContent


@pytest.fixture
def mock_ldap_manager():
    """Mock LDAP manager for testing."""
    manager = Mock()
    manager.ad_config = Mock()
    manager.ad_config.base_dn = "DC=test,DC=local"
    manager.ad_config.domain = "test.local"
    return manager


@pytest.fixture
def security_tools(mock_ldap_manager):
    """Security tools instance for testing."""
    return SecurityTools(mock_ldap_manager)


class TestSecurityTools:
    """Test security and audit functionality."""
    
    def test_get_domain_info_success(self, security_tools, mock_ldap_manager):
        """Test successful domain information retrieval."""
        # Mock domain object search
        mock_domain_result = [
            {
                'dn': 'DC=test,DC=local',
                'attributes': {
                    'name': ['test'],
                    'dc': ['test'],
                    'objectSid': [b'\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00'],
                    'whenCreated': [datetime.now() - timedelta(days=365)],
                    'whenChanged': [datetime.now() - timedelta(days=1)],
                    'lockoutThreshold': [5],
                    'lockoutDuration': [-18000000000],  # 30 minutes in 100ns intervals
                    'maxPwdAge': [-36288000000000],  # 42 days
                    'minPwdAge': [-864000000000],  # 1 day
                    'minPwdLength': [8],
                    'pwdHistoryLength': [24],
                    'functionalLevel': [7]  # Windows Server 2008 R2
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_domain_result
        
        # Test get_domain_info
        result = security_tools.get_domain_info()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['name'] == 'test'
        assert response_data['domain_component'] == 'test'
        assert 'password_policy' in response_data
        
        password_policy = response_data['password_policy']
        assert password_policy['min_password_length'] == 8
        assert password_policy['password_history_length'] == 24
        assert password_policy['lockout_threshold'] == 5
        
        # Verify LDAP search was called
        mock_ldap_manager.search.assert_called_once()
    
    def test_get_privileged_groups_success(self, security_tools, mock_ldap_manager):
        """Test successful privileged group retrieval."""
        # Mock privileged groups search results
        mock_results = [
            {
                'dn': 'CN=Domain Admins,CN=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Domain Admins'],
                    'displayName': ['Domain Admins'],
                    'description': ['Designated administrators of the domain'],
                    'member': [
                        'CN=Administrator,CN=Users,DC=test,DC=local',
                        'CN=Admin User,OU=Users,DC=test,DC=local'
                    ],
                    'whenCreated': [datetime.now() - timedelta(days=365)],
                    'adminCount': [1]
                }
            },
            {
                'dn': 'CN=Enterprise Admins,CN=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Enterprise Admins'],
                    'displayName': ['Enterprise Admins'],
                    'description': ['Designated administrators of the enterprise'],
                    'member': ['CN=Administrator,CN=Users,DC=test,DC=local'],
                    'adminCount': [1]
                }
            },
            {
                'dn': 'CN=Backup Operators,CN=Builtin,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Backup Operators'],
                    'displayName': ['Backup Operators'],
                    'description': ['Backup Operators can override security restrictions'],
                    'member': ['CN=Backup Service,OU=Service Accounts,DC=test,DC=local']
                }
            }
        ]
        
        # get_privileged_groups looks each group up BY NAME. Returning the whole
        # list for every lookup multiplied the answer by the number of names.
        def por_nome(*args, **kwargs):
            f = kwargs.get('search_filter', '')
            return [g for g in mock_results
                    if f"sAMAccountName={g['attributes']['sAMAccountName'][0]})" in f]

        mock_ldap_manager.search.side_effect = por_nome
        
        # Test get_privileged_groups
        result = security_tools.get_privileged_groups()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['total_groups'] == 3
        assert len(response_data['privileged_groups']) == 3
        
        # Check specific groups
        # The payload uses snake_case keys, not the raw LDAP attribute names.
        groups = {group['sam_account_name']: group for group in response_data['privileged_groups']}
        assert 'Domain Admins' in groups
        assert 'Enterprise Admins' in groups
        assert 'Backup Operators' in groups
        
        # This tool describes the groups; risk classification per account is
        # audit_admin_accounts' job, so there is no risk_level here.
        domain_admins = groups['Domain Admins']
        assert domain_admins['member_count'] == 2
        assert 'Designated administrators' in domain_admins['description']
        
        enterprise_admins = groups['Enterprise Admins']
        assert enterprise_admins['member_count'] == 1
        assert 'risk_level' not in enterprise_admins
    
    def test_audit_admin_accounts_success(self, security_tools, mock_ldap_manager):
        """Test successful admin account audit."""
        # Mock admin account search results
        mock_results = [
            {
                'dn': 'CN=Administrator,CN=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Administrator'],
                    'displayName': ['Built-in Administrator'],
                    'userAccountControl': [512],  # Enabled
                    'lastLogon': [datetime.now() - timedelta(days=1)],
                    'pwdLastSet': [datetime.now() - timedelta(days=30)],
                    'adminCount': [1],
                    'memberOf': [
                        'CN=Domain Admins,CN=Users,DC=test,DC=local',
                        'CN=Enterprise Admins,CN=Users,DC=test,DC=local'
                    ],
                    'whenCreated': [datetime.now() - timedelta(days=365)]
                }
            },
            {
                'dn': 'CN=Admin User,OU=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['admin.user'],
                    'displayName': ['Admin User'],
                    'userAccountControl': [512],  # Enabled
                    'lastLogon': [datetime.now() - timedelta(days=90)],  # Stale
                    'pwdLastSet': [datetime.now() - timedelta(days=180)],  # Old password
                    'adminCount': [1],
                    'memberOf': ['CN=Domain Admins,CN=Users,DC=test,DC=local']
                }
            },
            {
                'dn': 'CN=Service Admin,OU=Service Accounts,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['svc.admin'],
                    'displayName': ['Service Admin Account'],
                    'userAccountControl': [66048],  # Enabled, password never expires
                    'lastLogon': [datetime.now()],
                    'pwdLastSet': [datetime.now() - timedelta(days=365)],  # Very old password
                    'adminCount': [1],
                    'servicePrincipalName': ['HTTP/service.test.local']
                }
            }
        ]
        
        # audit_admin_accounts resolves each privileged group by name and then
        # reads every member with a BASE search on the member's own DN. Without
        # a branch for that second search the audit found nobody.
        por_dn = {c['dn']: c for c in mock_results}
        grupo_membros = {
            'Domain Admins': [c['dn'] for c in mock_results],
        }

        def busca(*args, **kwargs):
            f = kwargs.get('search_filter', '')
            base = kwargs.get('search_base', '')
            if f == '(objectClass=user)' and base in por_dn:
                return [por_dn[base]]
            if 'objectClass=group' in f:
                for nome, membros in grupo_membros.items():
                    if f"sAMAccountName={nome})" in f:
                        return [{'dn': f'CN={nome},CN=Users,DC=test,DC=local',
                                 'attributes': {'member': membros}}]
                return []
            return mock_results

        mock_ldap_manager.search.side_effect = busca
        
        # Test audit_admin_accounts
        result = security_tools.audit_admin_accounts()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['total_admin_accounts'] == 3
        
        # Real shape: a list of accounts plus one counter per risk level.
        contas = response_data['admin_accounts']
        assert len(contas) == response_data['total_admin_accounts']
        assert sum(response_data[k] for k in
                   ('high_risk_count', 'medium_risk_count', 'low_risk_count')) == len(contas)
        assert any(c['security_issues'] for c in contas), "nenhuma conta com achado"
        
        # Verify specific accounts
        accounts = {acc['sam_account_name']: acc for acc in contas}
        
        # Built-in administrator should be active
        admin = accounts['Administrator']
        assert admin['enabled'] is True
        assert admin['risk_level'] in ['low', 'medium', 'high']
        
        # Service account with old password should be flagged
        svc_admin = accounts['svc.admin']
        assert svc_admin['security_issues'], "conta de servico sem nenhum achado"
        assert svc_admin['risk_level'] == 'high'
    
    def test_check_password_policy_success(self, security_tools, mock_ldap_manager):
        """Test password policy compliance check."""
        # Mock domain policy search
        mock_results = [
            {
                'dn': 'DC=test,DC=local',
                'attributes': {
                    'maxPwdAge': [-36288000000000],  # 42 days
                    'minPwdAge': [-864000000000],  # 1 day
                    'minPwdLength': [8],
                    'pwdHistoryLength': [24],
                    'pwdProperties': [1],  # DOMAIN_PASSWORD_COMPLEX
                    'lockoutThreshold': [5],
                    'lockoutDuration': [-18000000000]  # 30 minutes
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test check_password_policy
        result = security_tools.check_password_policy()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        # Real shape: policy_compliant + recommendations + the two policies,
        # each already humanized by _convert_time_interval.
        assert 'password_policy' in response_data
        assert 'policy_compliant' in response_data
        assert 'recommendations' in response_data
        assert isinstance(response_data['policy_compliant'], bool)
        # A weak policy must produce advice, not an empty list.
        if not response_data['policy_compliant']:
            assert response_data['recommendations']
        
        # There is no numeric score here: compliance is a boolean plus advice.
        # generate_security_report is what computes overall_security_score.
        assert 'compliance_status' not in response_data
        assert 'lockout_policy' in response_data
    
    
    
    
    
    def test_generate_security_report_success(self, security_tools, mock_ldap_manager):
        """Test comprehensive security report generation."""
        # Mock multiple search results for comprehensive report
        # This test would typically call multiple other methods
        
        with patch.object(security_tools, 'get_domain_info') as mock_domain, \
             patch.object(security_tools, 'audit_admin_accounts') as mock_admin_audit, \
             patch.object(security_tools, 'check_password_policy') as mock_password_policy, \
             patch.object(security_tools, 'get_privileged_groups') as mock_grupos:
            
            # Mock return values for each component
            mock_domain.return_value = [TextContent(type="text", text='{"domain": "test.local"}')]
            mock_admin_audit.return_value = [TextContent(type="text", text='{"total_admin_accounts": 5}')]
            mock_password_policy.return_value = [TextContent(type="text", text='{"compliance_status": {"overall_score": 85}}')]
            mock_grupos.return_value = [TextContent(type="text", text='{"total_groups": 2}')]
            
            # Test generate_security_report
            result = security_tools.generate_security_report()
            
            # Verify result
            assert len(result) == 1
            assert isinstance(result[0], TextContent)
            
            # Parse JSON response
            response_data = json.loads(result[0].text)
            assert 'report_timestamp' in response_data
            assert 'executive_summary' in response_data
            assert 'detailed_findings' in response_data
            
            # Verify all sub-reports were called
            mock_domain.assert_called_once()
            mock_admin_audit.assert_called_once()
            mock_password_policy.assert_called_once()
            mock_grupos.assert_called_once()
    
    def test_security_risk_assessment(self, security_tools):
        """Test security risk assessment logic."""
        # Test different risk scenarios
        
        # High risk: Multiple privileged groups + old password
        high_risk_account = {
            'memberOf': [
                'CN=Domain Admins,CN=Users,DC=test,DC=local',
                'CN=Enterprise Admins,CN=Users,DC=test,DC=local'
            ],
            'pwdLastSet': [datetime.now() - timedelta(days=200)],
            'lastLogon': [datetime.now() - timedelta(days=90)]
        }
        risk = security_tools._assess_account_risk(high_risk_account)
        # Lowercase everywhere: it is what get_schema_info advertises.
        assert risk == 'high'
        
        # Medium risk: One privileged group + recent activity
        medium_risk_account = {
            'memberOf': ['CN=Domain Admins,CN=Users,DC=test,DC=local'],
            'pwdLastSet': [datetime.now() - timedelta(days=30)],
            'lastLogon': [datetime.now() - timedelta(days=1)]
        }
        risk = security_tools._assess_account_risk(medium_risk_account)
        assert risk == 'medium'
        
        # Low risk: Regular user
        low_risk_account = {
            'memberOf': ['CN=Domain Users,CN=Users,DC=test,DC=local'],
            'pwdLastSet': [datetime.now() - timedelta(days=15)],
            'lastLogon': [datetime.now()]
        }
        risk = security_tools._assess_account_risk(low_risk_account)
        assert risk == 'low'
    
    def test_password_age_calculation(self, security_tools):
        """Test password age calculation."""
        # Test recent password
        recent_date = datetime.now() - timedelta(days=10)
        age = security_tools._calculate_password_age({'pwdLastSet': [recent_date]})
        assert age == 10
        
        # Test old password
        old_date = datetime.now() - timedelta(days=365)
        age = security_tools._calculate_password_age({'pwdLastSet': [old_date]})
        assert age == 365
        
        # Test never set password
        age = security_tools._calculate_password_age({'pwdLastSet': [None]})
        assert age == -1
        
        # Test missing attribute
        age = security_tools._calculate_password_age({})
        assert age == -1
    
    def test_is_privileged_group(self, security_tools):
        """Test privileged group detection."""
        # Test high-privilege groups
        assert security_tools._is_privileged_group('Domain Admins') == True
        assert security_tools._is_privileged_group('Enterprise Admins') == True
        assert security_tools._is_privileged_group('Schema Admins') == True
        assert security_tools._is_privileged_group('Backup Operators') == True
        
        # Test regular groups
        assert security_tools._is_privileged_group('Domain Users') == False
        assert security_tools._is_privileged_group('Sales Team') == False
        assert security_tools._is_privileged_group('Regular Group') == False
    
    def test_ldap_error_handling(self, security_tools, mock_ldap_manager):
        """Test LDAP error handling."""
        # Mock LDAP exception
        from ldap3.core.exceptions import LDAPException
        mock_ldap_manager.search.side_effect = LDAPException("Connection failed")
        
        # Test get_domain_info with error
        result = security_tools.get_domain_info()
        
        # Verify error handling
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'Connection failed' in response_data['error']
        assert response_data['type'] == 'LDAPException'
    
    def test_get_schema_info(self, security_tools):
        """Test schema information retrieval."""
        schema = security_tools.get_schema_info()
        
        assert 'operations' in schema
        assert 'security_attributes' in schema
        assert 'risk_levels' in schema
        assert 'required_permissions' in schema
        
        # Check some expected operations
        operations = schema['operations']
        assert 'get_domain_info' in operations
        assert 'audit_admin_accounts' in operations
        assert 'check_password_policy' in operations
        assert 'generate_security_report' in operations
        # find_weak_passwords / analyze_permissions / detect_privilege_escalation
        # / check_service_accounts were stubs returning invented audit data and
        # were removed; the real coverage is get_privileged_groups,
        # audit_admin_accounts, get_password_policy_violations and
        # get_user_permissions.
        for removida in ('find_weak_passwords', 'analyze_permissions',
                         'detect_privilege_escalation', 'check_service_accounts'):
            assert removida not in operations, (
                f"{removida} voltou ao schema; era um stub que inventava dados")
        
        # Check risk levels
        # One spelling only: lowercase, matching every producer in the file.
        assert 'low' in schema['risk_levels']
        assert 'medium' in schema['risk_levels']
        assert 'high' in schema['risk_levels']
        assert 'critical' in schema['risk_levels']

