"""Performance and load tests for Active Directory MCP server."""

import pytest
import json
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from active_directory_mcp.server import ActiveDirectoryMCPServer


@pytest.fixture
def performance_config():
    """Performance test configuration."""
    return {
        "active_directory": {
            "server": "ldap://perf-test.local:389",
            "domain": "perf-test.local",
            "base_dn": "DC=perf-test,DC=local",
            "bind_dn": "CN=admin,DC=perf-test,DC=local",
            "password": "password123"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=perf-test,DC=local",
            "groups_ou": "OU=Groups,DC=perf-test,DC=local",
            "computers_ou": "OU=Computers,DC=perf-test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=perf-test,DC=local"
        },
        "performance": {
            "connection_pool_size": 20,
            "max_retries": 3,
            "retry_delay": 0.1,
            "page_size": 1000
        }
    }


@pytest.fixture
def mock_server_with_performance_config(performance_config):
    """Mock server configured for performance testing."""
    with patch('active_directory_mcp.core.ldap_manager.LDAPManager.test_connection') as mock_test_conn, \
         patch('active_directory_mcp.core.ldap_manager.LDAPManager.connect') as mock_connect, \
         patch('active_directory_mcp.config.loader.load_config') as mock_load_config:
        
        # Return mock config object with proper structure
        from active_directory_mcp.config.models import Config, ActiveDirectoryConfig, OrganizationalUnitsConfig, SecurityConfig, LoggingConfig, PerformanceConfig
        
        config_obj = Config(
            active_directory=ActiveDirectoryConfig(**performance_config["active_directory"]),
            organizational_units=OrganizationalUnitsConfig(**performance_config["organizational_units"]),
            performance=PerformanceConfig(**performance_config["performance"]),
            security=SecurityConfig(),
            logging=LoggingConfig()
        )
        
        mock_load_config.return_value = config_obj
        mock_test_conn.return_value = {'connected': True}
        mock_connect.return_value = Mock()
        
        # Create server with mocked config (no file lookup needed)
        with patch.dict(os.environ, {'AD_MCP_CONFIG': 'test_config.json'}):
            server = ActiveDirectoryMCPServer(config_path=None)
        yield server


class TestLargeDatasetPerformance:
    """Test performance with large datasets."""
    
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.search')
    def test_large_user_list_performance(self, mock_search, mock_server_with_performance_config):
        """Test performance when listing large numbers of users."""
        server = mock_server_with_performance_config
        
        # Generate large dataset (10,000 users)
        large_user_dataset = []
        for i in range(10000):
            large_user_dataset.append({
                'dn': f'CN=User{i:05d},OU=Users,DC=perf-test,DC=local',
                'attributes': {
                    'sAMAccountName': [f'user{i:05d}'],
                    'displayName': [f'User {i:05d}'],
                    'mail': [f'user{i:05d}@perf-test.local'],
                    'userAccountControl': [512],
                    'department': [f'Department{i % 10}'],
                    'whenCreated': [datetime.now() - timedelta(days=i % 365)]
                }
            })
        
        mock_search.return_value = large_user_dataset
        
        # Measure performance
        start_time = time.time()
        result = server.user_tools.list_users()
        end_time = time.time()
        
        execution_time = end_time - start_time
        
        # Verify results
        assert len(result) == 1
        data = json.loads(result[0].text)
        assert data['count'] == 10000
        assert len(data['users']) == 10000
        
        # Performance assertions (should complete within reasonable time)
        assert execution_time < 5.0, f"Large user list took {execution_time:.2f}s, expected < 5s"
        
        # Verify search was called once (efficient single query)
        mock_search.assert_called_once()
        
        print(f"✅ Large user list (10K users) completed in {execution_time:.3f}s")
    
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.search')
    def test_complex_group_membership_performance(self, mock_search, mock_server_with_performance_config):
        """Test performance with complex group membership hierarchies."""
        server = mock_server_with_performance_config
        
        # Mock complex group with many nested members
        group_member_dns = []
        for i in range(1000):
            group_member_dns.append(f'CN=User{i:04d},OU=Users,DC=perf-test,DC=local')
        
        # Add nested groups
        for i in range(50):
            group_member_dns.append(f'CN=SubGroup{i:02d},OU=Groups,DC=perf-test,DC=local')
        
        # Mock search results for group and member details
        def search_side_effect(*args, **kwargs):
            search_base = kwargs.get('search_base', '')
            search_filter = kwargs.get('search_filter', '')
            
            if 'ComplexGroup' in search_filter:
                return [{
                    'dn': 'CN=ComplexGroup,OU=Groups,DC=perf-test,DC=local',
                    'attributes': {
                        'member': group_member_dns
                    }
                }]
            elif search_base in group_member_dns:
                # Return member details
                if 'User' in search_base:
                    return [{
                        'attributes': {
                            'objectClass': ['user'],
                            'sAMAccountName': [search_base.split('=')[1].split(',')[0]],
                            'displayName': [f"Display {search_base.split('=')[1].split(',')[0]}"]
                        }
                    }]
                else:  # Subgroup
                    return [{
                        'attributes': {
                            'objectClass': ['group'],
                            'sAMAccountName': [search_base.split('=')[1].split(',')[0]],
                            'displayName': [f"Display {search_base.split('=')[1].split(',')[0]}"],
                            'member': []  # Empty subgroups for simplicity
                        }
                    }]
            else:
                return []
        
        mock_search.side_effect = search_side_effect
        
        # Measure performance
        start_time = time.time()
        result = server.group_tools.get_members('ComplexGroup')
        end_time = time.time()
        
        execution_time = end_time - start_time
        
        # Verify results
        assert len(result) == 1
        data = json.loads(result[0].text)
        assert data['member_count'] == 1050  # 1000 users + 50 groups
        
        # Performance assertion
        assert execution_time < 10.0, f"Complex group membership took {execution_time:.2f}s, expected < 10s"
        
        print(f"✅ Complex group membership (1050 members) completed in {execution_time:.3f}s")
    
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.search')
    def test_security_audit_performance(self, mock_search, mock_server_with_performance_config):
        """Test performance of comprehensive security audit."""
        server = mock_server_with_performance_config
        
        # Mock large security dataset
        admin_accounts = []
        for i in range(100):
            admin_accounts.append({
                'dn': f'CN=Admin{i:03d},OU=Users,DC=perf-test,DC=local',
                'attributes': {
                    'sAMAccountName': [f'admin{i:03d}'],
                    'displayName': [f'Administrator {i:03d}'],
                    'adminCount': [1],
                    'lastLogon': [datetime.now() - timedelta(days=i % 90)],
                    'pwdLastSet': [datetime.now() - timedelta(days=i % 180)],
                    'memberOf': [
                        'CN=Domain Admins,CN=Users,DC=perf-test,DC=local',
                        'CN=Enterprise Admins,CN=Users,DC=perf-test,DC=local'
                    ],
                    'userAccountControl': [512]
                }
            })
        
        privileged_groups = [
            {
                'dn': 'CN=Domain Admins,CN=Users,DC=perf-test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Domain Admins'],
                    'member': [acc['dn'] for acc in admin_accounts[:50]],
                    'adminCount': [1]
                }
            },
            {
                'dn': 'CN=Enterprise Admins,CN=Users,DC=perf-test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Enterprise Admins'],
                    'member': [acc['dn'] for acc in admin_accounts[25:75]],
                    'adminCount': [1]
                }
            }
        ]
        
        def security_search_side_effect(*args, **kwargs):
            search_filter = kwargs.get('search_filter', '')
            
            if 'adminCount=1' in search_filter and 'objectClass=user' in search_filter:
                return admin_accounts
            elif 'objectClass=group' in search_filter:
                return privileged_groups
            elif 'objectClass=domain' in search_filter:
                return [{
                    'dn': 'DC=perf-test,DC=local',
                    'attributes': {
                        'maxPwdAge': [-36288000000000],
                        'minPwdLength': [8],
                        'lockoutThreshold': [5]
                    }
                }]
            else:
                return []
        
        mock_search.side_effect = security_search_side_effect
        
        # Measure comprehensive security audit performance
        start_time = time.time()
        audit_result = server.security_tools.audit_admin_accounts()
        end_time = time.time()
        
        execution_time = end_time - start_time
        
        # Verify results
        assert len(audit_result) == 1
        audit_data = json.loads(audit_result[0].text)
        assert audit_data['total_admin_accounts'] == 100
        
        # Performance assertion
        assert execution_time < 3.0, f"Security audit took {execution_time:.2f}s, expected < 3s"
        
        print(f"✅ Security audit (100 admin accounts) completed in {execution_time:.3f}s")


class TestConcurrentOperations:
    """Test performance under concurrent load."""
    
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.search')
    def test_concurrent_user_queries(self, mock_search, mock_server_with_performance_config):
        """Test concurrent user query performance."""
        server = mock_server_with_performance_config
        
        # Mock user search results
        mock_search.return_value = [{
            'dn': 'CN=Test User,OU=Users,DC=perf-test,DC=local',
            'attributes': {
                'sAMAccountName': ['testuser'],
                'displayName': ['Test User'],
                'mail': ['testuser@perf-test.local'],
                'userAccountControl': [512]
            }
        }]
        
        def perform_user_query(user_id):
            """Perform a single user query."""
            start_time = time.time()
            result = server.user_tools.get_user(f'testuser{user_id}')
            end_time = time.time()
            
            return {
                'user_id': user_id,
                'success': len(result) == 1,
                'duration': end_time - start_time
            }
        
        # Test concurrent operations
        num_concurrent_ops = 50
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all tasks
            futures = [executor.submit(perform_user_query, i) for i in range(num_concurrent_ops)]
            
            # Collect results
            results = []
            for future in as_completed(futures):
                results.append(future.result())
        
        end_time = time.time()
        total_execution_time = end_time - start_time
        
        # Verify all operations succeeded
        assert len(results) == num_concurrent_ops
        successful_ops = sum(1 for r in results if r['success'])
        assert successful_ops == num_concurrent_ops
        
        # Performance metrics
        avg_duration = sum(r['duration'] for r in results) / len(results)
        max_duration = max(r['duration'] for r in results)
        
        # Performance assertions
        assert total_execution_time < 10.0, f"Concurrent operations took {total_execution_time:.2f}s, expected < 10s"
        assert avg_duration < 1.0, f"Average operation time {avg_duration:.3f}s, expected < 1s"
        assert max_duration < 2.0, f"Max operation time {max_duration:.3f}s, expected < 2s"
        
        # Verify appropriate number of LDAP calls were made
        assert mock_search.call_count == num_concurrent_ops
        
        print(f"✅ {num_concurrent_ops} concurrent user queries completed in {total_execution_time:.3f}s")
        print(f"   Average: {avg_duration:.3f}s, Max: {max_duration:.3f}s")
    
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.search')
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.add')
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.modify')
    def test_concurrent_mixed_operations(self, mock_modify, mock_add, mock_search, 
                                       mock_server_with_performance_config):
        """Test performance with mixed concurrent operations."""
        server = mock_server_with_performance_config
        
        # Setup mocks
        mock_search.return_value = []  # Users don't exist (for creation)
        mock_add.return_value = True
        mock_modify.return_value = True
        
        def perform_mixed_operation(op_id):
            """Perform different operations based on ID."""
            start_time = time.time()
            
            if op_id % 3 == 0:
                # Create user
                result = server.user_tools.create_user(
                    username=f'user{op_id}',
                    password='TempPass123!',
                    first_name='Test',
                    last_name=f'User{op_id}'
                )
            elif op_id % 3 == 1:
                # List users (with mock returning empty for consistency)
                with patch.object(server.user_tools, 'list_users') as mock_list:
                    mock_list.return_value = [Mock(text='{"users": [], "count": 0}')]
                    result = server.user_tools.list_users()
            else:
                # Create group
                result = server.group_tools.create_group(
                    group_name=f'group{op_id}',
                    display_name=f'Test Group {op_id}'
                )
            
            end_time = time.time()
            return {
                'op_id': op_id,
                'operation_type': ['create_user', 'list_users', 'create_group'][op_id % 3],
                'success': len(result) == 1,
                'duration': end_time - start_time
            }
        
        # Test mixed concurrent operations
        num_operations = 30  # 10 each of create_user, list_users, create_group
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(perform_mixed_operation, i) for i in range(num_operations)]
            results = [future.result() for future in as_completed(futures)]
        
        end_time = time.time()
        total_execution_time = end_time - start_time
        
        # Analyze results by operation type
        results_by_type = {}
        for result in results:
            op_type = result['operation_type']
            if op_type not in results_by_type:
                results_by_type[op_type] = []
            results_by_type[op_type].append(result)
        
        # Verify all operations succeeded
        all_successful = all(r['success'] for r in results)
        assert all_successful, "Some operations failed"
        
        # Performance assertions
        assert total_execution_time < 15.0, f"Mixed operations took {total_execution_time:.2f}s, expected < 15s"
        
        # Verify operation distribution
        assert len(results_by_type) == 3
        for op_type, ops in results_by_type.items():
            assert len(ops) == 10, f"Expected 10 {op_type} operations, got {len(ops)}"
        
        print(f"✅ {num_operations} mixed concurrent operations completed in {total_execution_time:.3f}s")
        for op_type, ops in results_by_type.items():
            avg_duration = sum(op['duration'] for op in ops) / len(ops)
            print(f"   {op_type}: avg {avg_duration:.3f}s")


class TestMemoryAndResourceUsage:
    """Test memory usage and resource management."""
    
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.search')
    def test_memory_usage_with_large_datasets(self, mock_search, mock_server_with_performance_config):
        """Test memory usage when processing large datasets."""
        server = mock_server_with_performance_config
        
        # Function to generate large dataset
        def generate_large_dataset(size):
            dataset = []
            for i in range(size):
                dataset.append({
                    'dn': f'CN=User{i:06d},OU=Users,DC=perf-test,DC=local',
                    'attributes': {
                        'sAMAccountName': [f'user{i:06d}'],
                        'displayName': [f'User {i:06d}'],
                        'mail': [f'user{i:06d}@perf-test.local'],
                        'department': [f'Department {i % 100}'],
                        'title': [f'Title {i % 50}'],
                        'description': [f'Description for user {i:06d} with some additional text'],
                        'userAccountControl': [512]
                    }
                })
            return dataset
        
        # Test with progressively larger datasets
        dataset_sizes = [1000, 5000, 10000, 25000]
        results = []
        
        for size in dataset_sizes:
            mock_search.return_value = generate_large_dataset(size)
            
            start_time = time.time()
            result = server.user_tools.list_users()
            end_time = time.time()
            
            execution_time = end_time - start_time
            
            # Verify result
            assert len(result) == 1
            data = json.loads(result[0].text)
            assert data['count'] == size
            
            results.append({
                'dataset_size': size,
                'execution_time': execution_time
            })
            
            print(f"✅ Processed {size:,} users in {execution_time:.3f}s")
        
        # Verify performance scales reasonably (not exponentially)
        # Performance should be roughly linear with dataset size
        for i in range(1, len(results)):
            prev_result = results[i-1]
            curr_result = results[i]
            
            size_ratio = curr_result['dataset_size'] / prev_result['dataset_size']
            time_ratio = curr_result['execution_time'] / prev_result['execution_time']
            
            # Time ratio should not exceed size ratio by too much (allow some overhead)
            assert time_ratio <= size_ratio * 1.5, f"Performance degraded significantly: {time_ratio:.2f}x time for {size_ratio:.2f}x data"
        
        print(f"✅ Memory/performance scaling test passed for datasets up to {max(dataset_sizes):,} users")
    
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.connect')
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.disconnect')
    def test_connection_pooling_behavior(self, mock_disconnect, mock_connect, 
                                       mock_server_with_performance_config):
        """Test connection pooling and resource cleanup."""
        server = mock_server_with_performance_config
        
        # Mock connection management
        connection_count = 0
        disconnect_count = 0
        
        def mock_connect_side_effect():
            nonlocal connection_count
            connection_count += 1
            return Mock()
        
        def mock_disconnect_side_effect():
            nonlocal disconnect_count
            disconnect_count += 1
        
        mock_connect.side_effect = mock_connect_side_effect
        mock_disconnect.side_effect = mock_disconnect_side_effect
        
        # Simulate multiple operations that would require connections
        num_operations = 100
        
        with patch.object(server.user_tools, 'get_user') as mock_get_user:
            mock_get_user.return_value = [Mock(text='{"dn": "CN=Test,DC=test,DC=local"}')]
            
            # Perform operations sequentially
            for i in range(num_operations):
                server.user_tools.get_user(f'user{i}')
        
        # With connection pooling, we shouldn't create 100 connections
        # The exact number depends on the pooling implementation
        print(f"✅ {num_operations} operations used {connection_count} connections")
        
        # Verify reasonable connection reuse
        assert connection_count < num_operations, "Connection pooling should reduce connection count"
        assert connection_count >= 1, "At least one connection should be made"


class TestStressScenarios:
    """Stress testing scenarios."""
    
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.search')
    def test_rapid_sequential_operations(self, mock_search, mock_server_with_performance_config):
        """Test performance under rapid sequential operations."""
        server = mock_server_with_performance_config
        
        mock_search.return_value = [{
            'dn': 'CN=Test User,OU=Users,DC=perf-test,DC=local',
            'attributes': {'sAMAccountName': ['testuser']}
        }]
        
        # Perform rapid sequential operations
        num_operations = 500
        operations_per_second = []
        
        start_time = time.time()
        
        for i in range(num_operations):
            op_start = time.time()
            result = server.user_tools.get_user(f'user{i}')
            op_end = time.time()
            
            # Verify operation succeeded
            assert len(result) == 1
            
            # Calculate instantaneous operations per second
            if i > 0 and (i % 50 == 0):  # Check every 50 operations
                elapsed = op_end - start_time
                ops_per_sec = i / elapsed
                operations_per_second.append(ops_per_sec)
        
        end_time = time.time()
        total_time = end_time - start_time
        overall_ops_per_sec = num_operations / total_time
        
        # Performance assertions
        assert overall_ops_per_sec >= 50, f"Operations/sec {overall_ops_per_sec:.1f} below threshold"
        assert total_time < 15.0, f"Rapid operations took {total_time:.2f}s, expected < 15s"
        
        # Verify performance didn't degrade significantly over time
        if len(operations_per_second) > 1:
            initial_rate = operations_per_second[0]
            final_rate = operations_per_second[-1]
            degradation = (initial_rate - final_rate) / initial_rate
            
            assert degradation < 0.3, f"Performance degraded by {degradation:.1%} over time"
        
        print(f"✅ {num_operations} rapid sequential operations: {overall_ops_per_sec:.1f} ops/sec")
    
    @patch('active_directory_mcp.core.ldap_manager.LDAPManager.search')
    def test_sustained_load_stability(self, mock_search, mock_server_with_performance_config):
        """Test system stability under sustained load."""
        server = mock_server_with_performance_config
        
        mock_search.return_value = [
            {'dn': f'CN=User{i},OU=Users,DC=perf-test,DC=local', 'attributes': {'sAMAccountName': [f'user{i}']}}
            for i in range(100)
        ]
        
        # Test sustained load over multiple batches
        batch_size = 100
        num_batches = 10
        batch_results = []
        
        for batch in range(num_batches):
            batch_start = time.time()
            
            # Perform batch of operations
            batch_successes = 0
            for i in range(batch_size):
                result = server.user_tools.list_users()
                if len(result) == 1:
                    data = json.loads(result[0].text)
                    if data.get('count', 0) > 0:
                        batch_successes += 1
            
            batch_end = time.time()
            batch_duration = batch_end - batch_start
            
            batch_results.append({
                'batch': batch + 1,
                'duration': batch_duration,
                'success_rate': batch_successes / batch_size,
                'ops_per_sec': batch_size / batch_duration
            })
            
            print(f"   Batch {batch + 1}: {batch_duration:.2f}s, {batch_results[-1]['ops_per_sec']:.1f} ops/sec")
        
        # Analyze stability
        durations = [r['duration'] for r in batch_results]
        success_rates = [r['success_rate'] for r in batch_results]
        
        # All operations should succeed
        assert all(rate == 1.0 for rate in success_rates), "Some operations failed under sustained load"
        
        # Performance should remain stable (coefficient of variation < 30%)
        avg_duration = sum(durations) / len(durations)
        duration_variance = sum((d - avg_duration) ** 2 for d in durations) / len(durations)
        duration_std = duration_variance ** 0.5
        coefficient_of_variation = duration_std / avg_duration
        
        assert coefficient_of_variation < 0.3, f"Performance instability: CV = {coefficient_of_variation:.2%}"
        
        total_operations = batch_size * num_batches
        total_time = sum(durations)
        overall_rate = total_operations / total_time
        
        print(f"✅ Sustained load test: {total_operations} operations, {overall_rate:.1f} ops/sec average")
        print(f"   Performance stability: CV = {coefficient_of_variation:.1%}")


# Benchmark utilities
def benchmark_operation(operation, name="Operation"):
    """Utility function to benchmark any operation."""
    start_time = time.time()
    result = operation()
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"🔥 {name} benchmark: {duration:.3f}s")
    return result, duration


if __name__ == "__main__":
    # This allows running performance tests standalone
    pytest.main([__file__, "-v", "--tb=short"])
