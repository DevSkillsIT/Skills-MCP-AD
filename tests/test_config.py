"""Tests for configuration module."""

import pytest
import tempfile
import json
import os
from pathlib import Path

from active_directory_mcp.config.loader import load_config, validate_config
from active_directory_mcp.config.models import Config, ActiveDirectoryConfig


def test_load_config_from_file():
    """Test loading configuration from JSON file."""
    config_data = {
        "active_directory": {
            "server": "ldap://test.local:389",
            "domain": "test.local",
            "base_dn": "DC=test,DC=local",
            "bind_dn": "CN=admin,DC=test,DC=local",
            "password": "password123"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=test,DC=local",
            "groups_ou": "OU=Groups,DC=test,DC=local",
            "computers_ou": "OU=Computers,DC=test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=test,DC=local"
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name
    
    try:
        config = load_config(config_path)
        assert isinstance(config, Config)
        assert config.active_directory.server == "ldap://test.local:389"
        assert config.active_directory.domain == "test.local"
    finally:
        os.unlink(config_path)


def test_load_config_from_env():
    """Test loading configuration from environment variable."""
    config_data = {
        "active_directory": {
            "server": "ldap://env-test.local:389",
            "domain": "env-test.local",
            "base_dn": "DC=env-test,DC=local",
            "bind_dn": "CN=admin,DC=env-test,DC=local",
            "password": "envpassword123"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=env-test,DC=local",
            "groups_ou": "OU=Groups,DC=env-test,DC=local",
            "computers_ou": "OU=Computers,DC=env-test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=env-test,DC=local"
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_data, f)
        config_path = f.name
    
    try:
        # Set environment variable
        os.environ['AD_MCP_CONFIG'] = config_path
        
        config = load_config()
        assert isinstance(config, Config)
        assert config.active_directory.domain == "env-test.local"
    finally:
        os.unlink(config_path)
        if 'AD_MCP_CONFIG' in os.environ:
            del os.environ['AD_MCP_CONFIG']


def test_config_validation():
    """Test configuration validation."""
    config_data = {
        "active_directory": {
            "server": "ldap://test.local:389",
            "domain": "test.local", 
            "base_dn": "DC=test,DC=local",
            "bind_dn": "CN=admin,DC=test,DC=local",
            "password": "password123"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=test,DC=local",
            "groups_ou": "OU=Groups,DC=test,DC=local",
            "computers_ou": "OU=Computers,DC=test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=test,DC=local"
        }
    }
    
    config = Config(**config_data)
    # Should not raise exception
    validate_config(config)


def test_invalid_server_url():
    """Test validation of invalid server URL."""
    with pytest.raises(ValueError, match="Server must start with ldap:// or ldaps://"):
        ActiveDirectoryConfig(
            server="http://invalid.com",
            domain="test.local",
            base_dn="DC=test,DC=local",
            bind_dn="CN=admin,DC=test,DC=local",
            password="password123"
        )


def test_missing_config_file():
    """Test handling of missing configuration file."""
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.json")


def test_invalid_json():
    """Test handling of invalid JSON."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("invalid json content")
        config_path = f.name
    
    try:
        with pytest.raises(json.JSONDecodeError):
            load_config(config_path)
    finally:
        os.unlink(config_path)


def test_missing_required_fields():
    """Test validation of missing required fields."""
    config_data = {
        "active_directory": {
            "server": "ldap://test.local:389",
            # Missing required fields
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=test,DC=local",
            "groups_ou": "OU=Groups,DC=test,DC=local",
            "computers_ou": "OU=Computers,DC=test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=test,DC=local"
        }
    }
    
    with pytest.raises(ValueError):
        Config(**config_data)


def test_default_values():
    """Test default configuration values."""
    config_data = {
        "active_directory": {
            "server": "ldap://test.local:389",
            "domain": "test.local",
            "base_dn": "DC=test,DC=local",
            "bind_dn": "CN=admin,DC=test,DC=local",
            "password": "password123"
        },
        "organizational_units": {
            "users_ou": "OU=Users,DC=test,DC=local",
            "groups_ou": "OU=Groups,DC=test,DC=local",
            "computers_ou": "OU=Computers,DC=test,DC=local",
            "service_accounts_ou": "OU=Service Accounts,DC=test,DC=local"
        }
    }
    
    config = Config(**config_data)
    
    # Test default values
    assert config.security.enable_tls == True
    assert config.logging.level == "INFO"
    assert config.performance.connection_pool_size == 10
    assert config.active_directory.use_ssl == True
    assert config.active_directory.ssl_port == 636
