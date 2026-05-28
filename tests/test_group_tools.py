"""Tests for group management tools."""

import pytest
from unittest.mock import Mock, patch
import json

from active_directory_mcp.tools.group import GroupTools
from mcp.types import TextContent


@pytest.fixture
def mock_ldap_manager():
    """Mock LDAP manager for testing."""
    manager = Mock()
    manager.ad_config = Mock()
    manager.ad_config.base_dn = "DC=test,DC=local"
    manager.ad_config.organizational_units = Mock()
    manager.ad_config.organizational_units.groups_ou = "OU=Groups,DC=test,DC=local"
    return manager


@pytest.fixture
def group_tools(mock_ldap_manager):
    """Group tools instance for testing."""
    return GroupTools(mock_ldap_manager)


class TestGroupTools:
    """Test group management functionality."""
    
    def test_list_groups_success(self, group_tools, mock_ldap_manager):
        """Test successful group listing."""
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'CN=Domain Admins,CN=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Domain Admins'],
                    'displayName': ['Domain Admins'],
                    'description': ['Designated administrators of the domain'],
                    'groupType': [-2147483646],  # Security group, Global scope
                    'member': ['CN=Administrator,CN=Users,DC=test,DC=local']
                }
            },
            {
                'dn': 'CN=Sales Team,OU=Groups,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['SalesTeam'],
                    'displayName': ['Sales Team'],
                    'description': ['Sales department group'],
                    'groupType': [-2147483646],
                    'member': [
                        'CN=John Doe,OU=Users,DC=test,DC=local',
                        'CN=Jane Smith,OU=Users,DC=test,DC=local'
                    ]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test list_groups
        result = group_tools.list_groups()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['count'] == 2
        assert len(response_data['groups']) == 2
        
        # Check first group
        group1 = response_data['groups'][0]
        assert group1['sAMAccountName'] == 'Domain Admins'
        assert group1['displayName'] == 'Domain Admins'
        assert group1['scope'] == 'Global'
        assert group1['type'] == 'Security'
        assert group1['memberCount'] == 1
        
        # Check second group
        group2 = response_data['groups'][1]
        assert group2['sAMAccountName'] == 'SalesTeam'
        assert group2['memberCount'] == 2
        
        # Verify LDAP search was called
        mock_ldap_manager.search.assert_called_once()
    
    def test_get_group_success(self, group_tools, mock_ldap_manager):
        """Test successful group retrieval."""
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'CN=Sales Team,OU=Groups,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['SalesTeam'],
                    'displayName': ['Sales Team'],
                    'description': ['Sales department group'],
                    'groupType': [-2147483646],
                    'member': [
                        'CN=John Doe,OU=Users,DC=test,DC=local',
                        'CN=Jane Smith,OU=Users,DC=test,DC=local'
                    ],
                    'memberOf': [
                        'CN=All Employees,OU=Groups,DC=test,DC=local'
                    ],
                    'managedBy': ['CN=Manager,OU=Users,DC=test,DC=local']
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test get_group
        result = group_tools.get_group('SalesTeam')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['dn'] == 'CN=Sales Team,OU=Groups,DC=test,DC=local'
        assert response_data['attributes']['sAMAccountName'] == ['SalesTeam']
        
        # Check computed fields
        computed = response_data['computed']
        assert computed['scope'] == 'Global'
        assert computed['type'] == 'Security'
        assert computed['member_count'] == 2
        assert computed['parent_groups_count'] == 1
        
        # Verify LDAP search was called with correct filter
        mock_ldap_manager.search.assert_called_once()
        call_args = mock_ldap_manager.search.call_args
        assert 'sAMAccountName=SalesTeam' in call_args[1]['search_filter']
    
    def test_get_group_not_found(self, group_tools, mock_ldap_manager):
        """Test group not found scenario."""
        # Mock empty search results
        mock_ldap_manager.search.return_value = []
        
        # Test get_group
        result = group_tools.get_group('nonexistent')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'not found' in response_data['error']
    
    def test_create_group_success(self, group_tools, mock_ldap_manager):
        """Test successful group creation."""
        # Mock search for existing group (empty result)
        mock_ldap_manager.search.return_value = []
        
        # Mock successful LDAP add operation
        mock_ldap_manager.add.return_value = True
        
        # Test create_group
        result = group_tools.create_group(
            group_name='NewGroup',
            display_name='New Test Group',
            description='A test group',
            group_scope='Global',
            group_type='Security'
        )
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert response_data['group_name'] == 'NewGroup'
        assert response_data['dn'] == 'CN=New Test Group,OU=Groups,DC=test,DC=local'
        assert response_data['scope'] == 'Global'
        assert response_data['type'] == 'Security'
        
        # Verify LDAP operations were called
        mock_ldap_manager.search.assert_called()  # Check for existing group
        mock_ldap_manager.add.assert_called_once()  # Create group
    
    def test_create_group_already_exists(self, group_tools, mock_ldap_manager):
        """Test group creation when group already exists."""
        # Mock search for existing group (group found)
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=Existing Group,OU=Groups,DC=test,DC=local'}
        ]
        
        # Test create_group
        result = group_tools.create_group(
            group_name='ExistingGroup',
            display_name='Existing Group'
        )
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'already exists' in response_data['error']
        
        # Verify no add operation was called
        mock_ldap_manager.add.assert_not_called()
    
    def test_modify_group_success(self, group_tools, mock_ldap_manager):
        """Test successful group modification."""
        # Mock search for group
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=Test Group,OU=Groups,DC=test,DC=local'}
        ]
        
        # Mock successful modify operation
        mock_ldap_manager.modify.return_value = True
        
        # Test modify_group
        attributes = {
            'description': 'Updated description',
            'displayName': 'Updated Display Name'
        }
        result = group_tools.modify_group('TestGroup', attributes)
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'modified successfully' in response_data['message']
        assert response_data['modified_attributes'] == ['description', 'displayName']
        
        # Verify LDAP modify was called
        mock_ldap_manager.modify.assert_called_once()
    
    def test_delete_group_success(self, group_tools, mock_ldap_manager):
        """Test successful group deletion."""
        # Mock search for group
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=Test Group,OU=Groups,DC=test,DC=local'}
        ]
        
        # Mock successful delete operation
        mock_ldap_manager.delete.return_value = True
        
        # Test delete_group
        result = group_tools.delete_group('TestGroup')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'deleted successfully' in response_data['message']
        
        # Verify LDAP delete was called
        mock_ldap_manager.delete.assert_called_once()
    
    def test_add_member_success(self, group_tools, mock_ldap_manager):
        """Test successful member addition to group."""
        # Mock search for group
        mock_ldap_manager.search.return_value = [
            {
                'dn': 'CN=Test Group,OU=Groups,DC=test,DC=local',
                'attributes': {
                    'member': ['CN=Existing Member,OU=Users,DC=test,DC=local']
                }
            }
        ]
        
        # Mock successful modify operation
        mock_ldap_manager.modify.return_value = True
        
        # Test add_member
        member_dn = 'CN=New Member,OU=Users,DC=test,DC=local'
        result = group_tools.add_member('TestGroup', member_dn)
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'Member added' in response_data['message']
        assert response_data['member_dn'] == member_dn
        
        # Verify LDAP modify was called with MODIFY_ADD
        mock_ldap_manager.modify.assert_called_once()
    
    def test_add_member_already_exists(self, group_tools, mock_ldap_manager):
        """Test adding member that already exists in group."""
        member_dn = 'CN=Existing Member,OU=Users,DC=test,DC=local'
        
        # Mock search for group with existing member
        mock_ldap_manager.search.return_value = [
            {
                'dn': 'CN=Test Group,OU=Groups,DC=test,DC=local',
                'attributes': {
                    'member': [member_dn]
                }
            }
        ]
        
        # Test add_member
        result = group_tools.add_member('TestGroup', member_dn)
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'already in group' in response_data['error']
        
        # Verify no modify operation was called
        mock_ldap_manager.modify.assert_not_called()
    
    def test_remove_member_success(self, group_tools, mock_ldap_manager):
        """Test successful member removal from group."""
        member_dn = 'CN=Member To Remove,OU=Users,DC=test,DC=local'
        
        # Mock search for group
        mock_ldap_manager.search.return_value = [
            {
                'dn': 'CN=Test Group,OU=Groups,DC=test,DC=local',
                'attributes': {
                    'member': [
                        member_dn,
                        'CN=Other Member,OU=Users,DC=test,DC=local'
                    ]
                }
            }
        ]
        
        # Mock successful modify operation
        mock_ldap_manager.modify.return_value = True
        
        # Test remove_member
        result = group_tools.remove_member('TestGroup', member_dn)
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'Member removed' in response_data['message']
        
        # Verify LDAP modify was called with MODIFY_DELETE
        mock_ldap_manager.modify.assert_called_once()
    
    def test_get_members_success(self, group_tools, mock_ldap_manager):
        """Test successful group member retrieval."""
        # Mock search for group
        group_search_result = [
            {
                'dn': 'CN=Test Group,OU=Groups,DC=test,DC=local',
                'attributes': {
                    'member': [
                        'CN=User1,OU=Users,DC=test,DC=local',
                        'CN=User2,OU=Users,DC=test,DC=local',
                        'CN=SubGroup,OU=Groups,DC=test,DC=local'
                    ]
                }
            }
        ]
        
        # Mock search for member details
        member_search_results = [
            # User1 details
            [
                {
                    'attributes': {
                        'objectClass': ['top', 'person', 'user'],
                        'sAMAccountName': ['user1'],
                        'displayName': ['User One']
                    }
                }
            ],
            # User2 details
            [
                {
                    'attributes': {
                        'objectClass': ['top', 'person', 'user'],
                        'sAMAccountName': ['user2'],
                        'displayName': ['User Two']
                    }
                }
            ],
            # SubGroup details
            [
                {
                    'attributes': {
                        'objectClass': ['top', 'group'],
                        'sAMAccountName': ['subgroup'],
                        'displayName': ['Sub Group'],
                        'member': []
                    }
                }
            ]
        ]
        
        # Configure mock to return different results for different calls
        mock_ldap_manager.search.side_effect = [group_search_result] + member_search_results
        
        # Test get_members
        result = group_tools.get_members('TestGroup')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['group_name'] == 'TestGroup'
        assert response_data['member_count'] == 3
        assert len(response_data['members']) == 3
        
        # Check member types
        members = response_data['members']
        user_members = [m for m in members if m['type'] == 'user']
        group_members = [m for m in members if m['type'] == 'group']
        
        assert len(user_members) == 2
        assert len(group_members) == 1
        assert user_members[0]['sAMAccountName'] == 'user1'
        assert group_members[0]['sAMAccountName'] == 'subgroup'
    
    def test_get_members_recursive(self, group_tools, mock_ldap_manager):
        """Test recursive member retrieval."""
        # Mock search for parent group
        parent_group_result = [
            {
                'dn': 'CN=Parent Group,OU=Groups,DC=test,DC=local',
                'attributes': {
                    'member': ['CN=Child Group,OU=Groups,DC=test,DC=local']
                }
            }
        ]
        
        # Mock search for child group details
        child_group_details = [
            {
                'attributes': {
                    'objectClass': ['top', 'group'],
                    'sAMAccountName': ['childgroup'],
                    'displayName': ['Child Group'],
                    'member': ['CN=User in Child,OU=Users,DC=test,DC=local']
                }
            }
        ]
        
        # Mock search for nested user details
        nested_user_details = [
            {
                'attributes': {
                    'objectClass': ['top', 'person', 'user'],
                    'sAMAccountName': ['nesteduser'],
                    'displayName': ['Nested User']
                }
            }
        ]
        
        # Configure mock for recursive calls
        mock_ldap_manager.search.side_effect = [
            parent_group_result,
            child_group_details,
            nested_user_details
        ]
        
        # Test get_members with recursive=True
        result = group_tools.get_members('ParentGroup', recursive=True)
        
        # Verify result
        response_data = json.loads(result[0].text)
        assert response_data['recursive'] == True
        assert response_data['member_count'] == 2  # Child group + nested user
        
        # Check level hierarchy
        members = response_data['members']
        level_0_members = [m for m in members if m['level'] == 0]
        level_1_members = [m for m in members if m['level'] == 1]
        
        assert len(level_0_members) == 1  # Child group
        assert len(level_1_members) == 1  # Nested user
    
    def test_group_scope_calculation(self, group_tools):
        """Test group scope calculation from groupType value."""
        # Test different group type values
        assert group_tools._get_group_scope(0x00000002) == "Global"  # Global group
        assert group_tools._get_group_scope(0x00000004) == "DomainLocal"  # Domain Local
        assert group_tools._get_group_scope(0x00000008) == "Universal"  # Universal
        assert group_tools._get_group_scope(0x12345678) == "Unknown"  # Unknown type
    
    def test_group_type_calculation(self, group_tools):
        """Test group type calculation from groupType value."""
        # Test security vs distribution groups
        assert group_tools._get_group_type(0x80000000) == "Security"  # Security group
        assert group_tools._get_group_type(0x00000002) == "Distribution"  # Distribution
    
    def test_calculate_group_type_value(self, group_tools):
        """Test calculation of groupType value from scope and type."""
        # Test Global Security group
        value = group_tools._calculate_group_type("Global", "Security")
        expected = 0x80000002  # Security enabled + Global scope
        assert value == expected
        
        # Test Domain Local Distribution group
        value = group_tools._calculate_group_type("DomainLocal", "Distribution")
        expected = 0x00000004  # Domain Local scope, no security flag
        assert value == expected
        
        # Test Universal Security group
        value = group_tools._calculate_group_type("Universal", "Security")
        expected = 0x80000008  # Security enabled + Universal scope
        assert value == expected
    
    def test_ldap_error_handling(self, group_tools, mock_ldap_manager):
        """Test LDAP error handling."""
        # Mock LDAP exception
        from ldap3.core.exceptions import LDAPException
        mock_ldap_manager.search.side_effect = LDAPException("Connection failed")
        
        # Test list_groups with error
        result = group_tools.list_groups()
        
        # Verify error handling
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'Connection failed' in response_data['error']
        assert response_data['type'] == 'LDAPException'
    
    def test_get_schema_info(self, group_tools):
        """Test schema information retrieval."""
        schema = group_tools.get_schema_info()
        
        assert 'operations' in schema
        assert 'group_attributes' in schema
        assert 'group_scopes' in schema
        assert 'group_types' in schema
        assert 'required_permissions' in schema
        
        # Check some expected operations
        operations = schema['operations']
        assert 'list_groups' in operations
        assert 'create_group' in operations
        assert 'modify_group' in operations
        assert 'delete_group' in operations
        assert 'add_member' in operations
        assert 'remove_member' in operations
        assert 'get_members' in operations
        
        # Check group scopes and types
        assert 'Global' in schema['group_scopes']
        assert 'DomainLocal' in schema['group_scopes']
        assert 'Universal' in schema['group_scopes']
        assert 'Security' in schema['group_types']
        assert 'Distribution' in schema['group_types']

