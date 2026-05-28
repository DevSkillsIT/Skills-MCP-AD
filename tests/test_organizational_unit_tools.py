"""Tests for organizational unit management tools."""

import pytest
from unittest.mock import Mock, patch
import json
from datetime import datetime, timedelta

from active_directory_mcp.tools.organizational_unit import OrganizationalUnitTools
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
def ou_tools(mock_ldap_manager):
    """OU tools instance for testing."""
    return OrganizationalUnitTools(mock_ldap_manager)


class TestOrganizationalUnitTools:
    """Test organizational unit management functionality."""
    
    def test_list_organizational_units_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU listing."""
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'OU=Users,DC=test,DC=local',
                'attributes': {
                    'name': ['Users'],
                    'description': ['Default Users container'],
                    'whenCreated': [datetime.now() - timedelta(days=365)],
                    'whenChanged': [datetime.now() - timedelta(days=30)],
                    'managedBy': ['CN=OU Manager,OU=Users,DC=test,DC=local'],
                    'gPLink': ['[LDAP://cn={12345678-1234-1234-1234-123456789ABC},cn=policies,cn=system,DC=test,DC=local;0]'],
                    'ou': ['Users']
                }
            },
            {
                'dn': 'OU=Computers,DC=test,DC=local',
                'attributes': {
                    'name': ['Computers'],
                    'description': ['Default Computers container'],
                    'whenCreated': [datetime.now() - timedelta(days=365)],
                    'whenChanged': [datetime.now() - timedelta(days=60)],
                    'ou': ['Computers']
                }
            },
            {
                'dn': 'OU=Sales,OU=Departments,DC=test,DC=local',
                'attributes': {
                    'name': ['Sales'],
                    'description': ['Sales department organizational unit'],
                    'whenCreated': [datetime.now() - timedelta(days=180)],
                    'whenChanged': [datetime.now() - timedelta(days=1)],
                    'managedBy': ['CN=Sales Manager,OU=Users,DC=test,DC=local'],
                    'ou': ['Sales']
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test list_organizational_units
        result = ou_tools.list_organizational_units()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['count'] == 3
        assert len(response_data['organizational_units']) == 3
        
        # Check first OU
        ou1 = response_data['organizational_units'][0]
        assert ou1['name'] == 'Users'
        assert ou1['description'] == 'Default Users container'
        assert ou1['dn'] == 'OU=Users,DC=test,DC=local'
        assert ou1['has_gpo_links'] == True
        
        # Check nested OU
        sales_ou = next(ou for ou in response_data['organizational_units'] if ou['name'] == 'Sales')
        assert 'OU=Departments' in sales_ou['dn']  # Should be nested under Departments
        
        # Verify LDAP search was called
        mock_ldap_manager.search.assert_called_once()
    
    def test_get_organizational_unit_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU retrieval."""
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'OU=Sales,OU=Departments,DC=test,DC=local',
                'attributes': {
                    'name': ['Sales'],
                    'description': ['Sales department organizational unit'],
                    'whenCreated': [datetime.now() - timedelta(days=180)],
                    'whenChanged': [datetime.now() - timedelta(days=1)],
                    'managedBy': ['CN=Sales Manager,OU=Users,DC=test,DC=local'],
                    'gPLink': [
                        '[LDAP://cn={12345678-1234-1234-1234-123456789ABC},cn=policies,cn=system,DC=test,DC=local;0]',
                        '[LDAP://cn={87654321-4321-4321-4321-CBA987654321},cn=policies,cn=system,DC=test,DC=local;0]'
                    ],
                    'ou': ['Sales'],
                    'street': ['123 Business Ave'],
                    'l': ['Business City'],  # locality
                    'postalCode': ['12345'],
                    'c': ['US']  # country
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test get_organizational_unit
        result = ou_tools.get_organizational_unit('OU=Sales,OU=Departments,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['dn'] == 'OU=Sales,OU=Departments,DC=test,DC=local'
        assert response_data['attributes']['name'] == ['Sales']
        
        # Check computed fields
        computed = response_data['computed']
        assert computed['gpo_count'] == 2
        assert computed['has_location_info'] == True
        assert computed['is_managed'] == True
        
        # Verify LDAP search was called with correct filter
        mock_ldap_manager.search.assert_called_once()
        call_args = mock_ldap_manager.search.call_args
        assert call_args[1]['search_base'] == 'OU=Sales,OU=Departments,DC=test,DC=local'
    
    def test_get_organizational_unit_not_found(self, ou_tools, mock_ldap_manager):
        """Test OU not found scenario."""
        # Mock empty search results
        mock_ldap_manager.search.return_value = []
        
        # Test get_organizational_unit
        result = ou_tools.get_organizational_unit('OU=NonExistent,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'not found' in response_data['error']
    
    def test_create_organizational_unit_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU creation."""
        # Mock search for existing OU (empty result)
        mock_ldap_manager.search.return_value = []
        
        # Mock successful LDAP add operation
        mock_ldap_manager.add.return_value = True
        
        # Test create_organizational_unit
        result = ou_tools.create_organizational_unit(
            name='Marketing',
            parent_dn='OU=Departments,DC=test,DC=local',
            description='Marketing department OU',
            manager_dn='CN=Marketing Manager,OU=Users,DC=test,DC=local'
        )
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert response_data['name'] == 'Marketing'
        assert response_data['dn'] == 'OU=Marketing,OU=Departments,DC=test,DC=local'
        assert response_data['description'] == 'Marketing department OU'
        
        # Verify LDAP operations were called
        mock_ldap_manager.search.assert_called()  # Check for existing OU
        mock_ldap_manager.add.assert_called_once()  # Create OU
        
        # Verify attributes passed to add operation
        add_call = mock_ldap_manager.add.call_args
        attributes = add_call[1]['attributes']
        assert attributes['objectClass'] == ['top', 'organizationalUnit']
        assert attributes['ou'] == 'Marketing'
        assert attributes['description'] == 'Marketing department OU'
        assert attributes['managedBy'] == 'CN=Marketing Manager,OU=Users,DC=test,DC=local'
    
    def test_create_organizational_unit_already_exists(self, ou_tools, mock_ldap_manager):
        """Test OU creation when OU already exists."""
        # Mock search for existing OU (OU found)
        mock_ldap_manager.search.return_value = [
            {'dn': 'OU=Existing,OU=Departments,DC=test,DC=local'}
        ]
        
        # Test create_organizational_unit
        result = ou_tools.create_organizational_unit(
            name='Existing',
            parent_dn='OU=Departments,DC=test,DC=local'
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
    
    def test_modify_organizational_unit_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU modification."""
        # Mock search for OU
        mock_ldap_manager.search.return_value = [
            {'dn': 'OU=TestOU,DC=test,DC=local'}
        ]
        
        # Mock successful modify operation
        mock_ldap_manager.modify.return_value = True
        
        # Test modify_organizational_unit
        attributes = {
            'description': 'Updated description',
            'managedBy': 'CN=New Manager,OU=Users,DC=test,DC=local',
            'street': '456 New Address',
            'l': 'New City'
        }
        result = ou_tools.modify_organizational_unit('OU=TestOU,DC=test,DC=local', attributes)
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'modified successfully' in response_data['message']
        assert set(response_data['modified_attributes']) == set(attributes.keys())
        
        # Verify LDAP modify was called
        mock_ldap_manager.modify.assert_called_once()
    
    def test_delete_organizational_unit_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU deletion."""
        # Mock search for OU (empty - no child objects)
        mock_ldap_manager.search.side_effect = [
            [{'dn': 'OU=EmptyOU,DC=test,DC=local'}],  # OU exists
            []  # No child objects
        ]
        
        # Mock successful delete operation
        mock_ldap_manager.delete.return_value = True
        
        # Test delete_organizational_unit
        result = ou_tools.delete_organizational_unit('OU=EmptyOU,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'deleted successfully' in response_data['message']
        
        # Verify LDAP operations were called
        assert mock_ldap_manager.search.call_count == 2  # Check OU exists + check for children
        mock_ldap_manager.delete.assert_called_once()
    
    def test_delete_organizational_unit_not_empty(self, ou_tools, mock_ldap_manager):
        """Test OU deletion when OU contains child objects."""
        # Mock search results
        mock_ldap_manager.search.side_effect = [
            [{'dn': 'OU=NotEmptyOU,DC=test,DC=local'}],  # OU exists
            [  # Has child objects
                {'dn': 'CN=Child User,OU=NotEmptyOU,DC=test,DC=local'},
                {'dn': 'OU=Child OU,OU=NotEmptyOU,DC=test,DC=local'}
            ]
        ]
        
        # Test delete_organizational_unit
        result = ou_tools.delete_organizational_unit('OU=NotEmptyOU,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'contains child objects' in response_data['error']
        assert response_data['child_count'] == 2
        
        # Verify no delete operation was called
        mock_ldap_manager.delete.assert_not_called()
    
    def test_move_organizational_unit_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU move operation."""
        # Mock search for source OU
        mock_ldap_manager.search.return_value = [
            {'dn': 'OU=MoveMe,OU=OldParent,DC=test,DC=local'}
        ]
        
        # Mock successful move operation
        mock_ldap_manager.move.return_value = True
        
        # Test move_organizational_unit
        result = ou_tools.move_organizational_unit(
            source_dn='OU=MoveMe,OU=OldParent,DC=test,DC=local',
            target_parent_dn='OU=NewParent,DC=test,DC=local'
        )
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'moved successfully' in response_data['message']
        assert response_data['old_dn'] == 'OU=MoveMe,OU=OldParent,DC=test,DC=local'
        assert response_data['new_dn'] == 'OU=MoveMe,OU=NewParent,DC=test,DC=local'
        
        # Verify LDAP move was called
        mock_ldap_manager.move.assert_called_once()
        call_args = mock_ldap_manager.move.call_args
        assert call_args[0][0] == 'OU=MoveMe,OU=OldParent,DC=test,DC=local'
        assert call_args[0][1] == 'OU=NewParent,DC=test,DC=local'
    
    def test_get_ou_children_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU children listing."""
        # Mock LDAP search results for child objects
        mock_results = [
            {
                'dn': 'CN=User1,OU=ParentOU,DC=test,DC=local',
                'attributes': {
                    'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                    'sAMAccountName': ['user1'],
                    'displayName': ['User One']
                }
            },
            {
                'dn': 'CN=Computer1,OU=ParentOU,DC=test,DC=local',
                'attributes': {
                    'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer'],
                    'sAMAccountName': ['COMPUTER1$'],
                    'dNSHostName': ['computer1.test.local']
                }
            },
            {
                'dn': 'OU=ChildOU,OU=ParentOU,DC=test,DC=local',
                'attributes': {
                    'objectClass': ['top', 'organizationalUnit'],
                    'name': ['ChildOU'],
                    'description': ['Child organizational unit']
                }
            },
            {
                'dn': 'CN=Group1,OU=ParentOU,DC=test,DC=local',
                'attributes': {
                    'objectClass': ['top', 'group'],
                    'sAMAccountName': ['Group1'],
                    'displayName': ['Group One'],
                    'groupType': [-2147483646]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test get_ou_children
        result = ou_tools.get_ou_children('OU=ParentOU,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['parent_dn'] == 'OU=ParentOU,DC=test,DC=local'
        assert response_data['total_children'] == 4
        
        # Check object type breakdown
        children_by_type = response_data['children_by_type']
        assert children_by_type['users'] == 1
        assert children_by_type['computers'] == 1
        assert children_by_type['groups'] == 1
        assert children_by_type['organizational_units'] == 1
        
        # Check individual child objects
        children = response_data['children']
        assert len(children) == 4
        
        user_child = next(child for child in children if child['object_type'] == 'user')
        assert user_child['name'] == 'User One'
        assert user_child['sAMAccountName'] == 'user1'
        
        ou_child = next(child for child in children if child['object_type'] == 'organizational_unit')
        assert ou_child['name'] == 'ChildOU'
    
    def test_get_ou_permissions_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU permissions retrieval."""
        # Mock LDAP search results with security descriptor
        import base64
        mock_results = [
            {
                'dn': 'OU=SecureOU,DC=test,DC=local',
                'attributes': {
                    'name': ['SecureOU'],
                    'nTSecurityDescriptor': [
                        base64.b64decode('AQAUhCQAAAAwAAAAAAAAABQAAAABABQALAAAADAADgAHAAEBAAAAAAAABQoAAAAqAA4ABwABAQAAAAAAAAUKAAAA')
                    ]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test get_ou_permissions
        result = ou_tools.get_ou_permissions('OU=SecureOU,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['ou_dn'] == 'OU=SecureOU,DC=test,DC=local'
        assert 'security_descriptor' in response_data
        assert 'permission_analysis' in response_data
    
    def test_delegate_ou_control_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU control delegation."""
        # Mock search for OU and user
        mock_ldap_manager.search.side_effect = [
            [{'dn': 'OU=DelegateOU,DC=test,DC=local'}],  # OU exists
            [{'dn': 'CN=Delegate User,OU=Users,DC=test,DC=local'}]  # User exists
        ]
        
        # Mock successful permission modification
        mock_ldap_manager.modify.return_value = True
        
        # Test delegate_ou_control
        result = ou_tools.delegate_ou_control(
            ou_dn='OU=DelegateOU,DC=test,DC=local',
            delegate_dn='CN=Delegate User,OU=Users,DC=test,DC=local',
            permissions=['reset_password', 'create_user', 'modify_user']
        )
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'delegation completed successfully' in response_data['message']
        assert response_data['delegated_permissions'] == ['reset_password', 'create_user', 'modify_user']
        
        # Verify LDAP operations were called
        assert mock_ldap_manager.search.call_count == 2  # Check OU and delegate existence
        mock_ldap_manager.modify.assert_called()  # Apply permissions
    
    def test_get_ou_statistics_success(self, ou_tools, mock_ldap_manager):
        """Test successful OU statistics retrieval."""
        # Mock search results for statistics
        mock_results = [
            # Users
            {'dn': 'CN=User1,OU=StatsOU,DC=test,DC=local', 'attributes': {'objectClass': ['user']}},
            {'dn': 'CN=User2,OU=StatsOU,DC=test,DC=local', 'attributes': {'objectClass': ['user']}},
            {'dn': 'CN=User3,OU=StatsOU,DC=test,DC=local', 'attributes': {'objectClass': ['user']}},
            # Computers
            {'dn': 'CN=Computer1,OU=StatsOU,DC=test,DC=local', 'attributes': {'objectClass': ['computer']}},
            {'dn': 'CN=Computer2,OU=StatsOU,DC=test,DC=local', 'attributes': {'objectClass': ['computer']}},
            # Groups
            {'dn': 'CN=Group1,OU=StatsOU,DC=test,DC=local', 'attributes': {'objectClass': ['group']}},
            # Child OUs
            {'dn': 'OU=Child1,OU=StatsOU,DC=test,DC=local', 'attributes': {'objectClass': ['organizationalUnit']}},
            {'dn': 'OU=Child2,OU=StatsOU,DC=test,DC=local', 'attributes': {'objectClass': ['organizationalUnit']}}
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test get_ou_statistics
        result = ou_tools.get_ou_statistics('OU=StatsOU,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['ou_dn'] == 'OU=StatsOU,DC=test,DC=local'
        
        # Check statistics
        stats = response_data['statistics']
        assert stats['total_objects'] == 8
        assert stats['users'] == 3
        assert stats['computers'] == 2
        assert stats['groups'] == 1
        assert stats['child_ous'] == 2
        
        # Check percentages
        breakdown = response_data['object_breakdown']
        assert breakdown['users_percentage'] == 37.5  # 3/8 * 100
        assert breakdown['computers_percentage'] == 25.0  # 2/8 * 100
    
    def test_ou_hierarchy_validation(self, ou_tools):
        """Test OU hierarchy validation logic."""
        # Test valid DN
        assert ou_tools._validate_ou_dn('OU=Test,DC=domain,DC=local') == True
        
        # Test invalid DN (not an OU)
        assert ou_tools._validate_ou_dn('CN=User,OU=Users,DC=domain,DC=local') == False
        
        # Test empty DN
        assert ou_tools._validate_ou_dn('') == False
        
        # Test malformed DN
        assert ou_tools._validate_ou_dn('invalid') == False
    
    def test_extract_ou_name(self, ou_tools):
        """Test OU name extraction from DN."""
        # Test normal OU DN
        name = ou_tools._extract_ou_name('OU=Marketing,OU=Departments,DC=test,DC=local')
        assert name == 'Marketing'
        
        # Test nested OU
        name = ou_tools._extract_ou_name('OU=Sales Team,OU=Sales,OU=Departments,DC=test,DC=local')
        assert name == 'Sales Team'
        
        # Test invalid DN
        name = ou_tools._extract_ou_name('CN=NotAnOU,DC=test,DC=local')
        assert name == ''
    
    def test_detect_object_type(self, ou_tools):
        """Test object type detection from objectClass."""
        # Test user object
        user_classes = ['top', 'person', 'organizationalPerson', 'user']
        assert ou_tools._detect_object_type(user_classes) == 'user'
        
        # Test computer object
        computer_classes = ['top', 'person', 'organizationalPerson', 'user', 'computer']
        assert ou_tools._detect_object_type(computer_classes) == 'computer'
        
        # Test group object
        group_classes = ['top', 'group']
        assert ou_tools._detect_object_type(group_classes) == 'group'
        
        # Test OU object
        ou_classes = ['top', 'organizationalUnit']
        assert ou_tools._detect_object_type(ou_classes) == 'organizational_unit'
        
        # Test unknown object
        unknown_classes = ['top', 'unknown']
        assert ou_tools._detect_object_type(unknown_classes) == 'other'
    
    def test_ldap_error_handling(self, ou_tools, mock_ldap_manager):
        """Test LDAP error handling."""
        # Mock LDAP exception
        from ldap3.core.exceptions import LDAPException
        mock_ldap_manager.search.side_effect = LDAPException("Connection failed")
        
        # Test list_organizational_units with error
        result = ou_tools.list_organizational_units()
        
        # Verify error handling
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'Connection failed' in response_data['error']
        assert response_data['type'] == 'LDAPException'
    
    def test_get_schema_info(self, ou_tools):
        """Test schema information retrieval."""
        schema = ou_tools.get_schema_info()
        
        assert 'operations' in schema
        assert 'ou_attributes' in schema
        assert 'delegation_permissions' in schema
        assert 'required_permissions' in schema
        
        # Check some expected operations
        operations = schema['operations']
        assert 'list_organizational_units' in operations
        assert 'create_organizational_unit' in operations
        assert 'modify_organizational_unit' in operations
        assert 'delete_organizational_unit' in operations
        assert 'move_organizational_unit' in operations
        assert 'get_ou_children' in operations
        assert 'delegate_ou_control' in operations
        assert 'get_ou_statistics' in operations
        
        # Check delegation permissions
        delegation_perms = schema['delegation_permissions']
        assert 'reset_password' in delegation_perms
        assert 'create_user' in delegation_perms
        assert 'modify_user' in delegation_perms
        assert 'delete_user' in delegation_perms

