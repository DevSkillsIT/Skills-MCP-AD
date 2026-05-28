"""
Client Security Module for Multi-Tenant Active Directory MCP.

This module provides security features for multi-client environments:
- Client identification and validation
- Automation token management
- Write operation confirmation
- Audit logging for client operations

"""

import json
import hashlib
import secrets
import os
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path

from .logging import get_logger

logger = get_logger("ClientSecurity")


class ClientSecurityManager:
    """
    Manages client identification and security for multi-tenant AD MCP.
    
    Features:
    - Client identification via config
    - Automation token validation (for unattended operations)
    - Write operation confirmation requirement
    - Audit logging
    """
    
    def __init__(self, config: Dict[str, Any], config_path: Optional[str] = None):
        """
        Initialize client security manager.
        
        Args:
            config: Configuration dictionary
            config_path: Path to configuration file (for deriving client info)
        """
        self.config = config
        self.config_path = config_path
        
        # Load client identification from config
        client_config = config.get("client", {})
        
        # Client identification
        self.client_name = client_config.get("name", self._derive_client_name())
        self.client_slug = client_config.get("slug", self._derive_client_slug())
        self.client_type = client_config.get("type", "unknown")  # "interno" or "cliente"
        
        # Domain info from AD config
        ad_config = config.get("active_directory", {})
        self.domain = ad_config.get("domain", "unknown")
        self.base_dn = ad_config.get("base_dn", "")
        
        # Automation token (for unattended operations)
        self.automation_token = client_config.get("automation_token", None)
        
        # Security settings
        security_config = client_config.get("security", {})
        self.require_confirmation_for_writes = security_config.get(
            "require_confirmation_for_writes", True
        )
        self.log_all_operations = security_config.get("log_all_operations", True)
        
        logger.info(f"Client security initialized: {self.client_name} ({self.client_slug})")
    
    def _derive_client_name(self) -> str:
        """Derive client name from config path or domain."""
        if self.config_path:
            # Extract from path: /opt/mcp-servers/active-directory/{client}/ad-config/...
            path_parts = Path(self.config_path).parts
            for i, part in enumerate(path_parts):
                if part == "active-directory" and i + 1 < len(path_parts):
                    client_dir = path_parts[i + 1]
                    if client_dir not in [".base-code", "shared"]:
                        return client_dir.replace("-", " ").title()
        
        # Fallback to domain
        domain = self.config.get("active_directory", {}).get("domain", "Unknown")
        return domain.split(".")[0].title()
    
    def _derive_client_slug(self) -> str:
        """Derive client slug from config path."""
        if self.config_path:
            path_parts = Path(self.config_path).parts
            for i, part in enumerate(path_parts):
                if part == "active-directory" and i + 1 < len(path_parts):
                    client_dir = path_parts[i + 1]
                    if client_dir not in [".base-code", "shared"]:
                        return client_dir
        
        # Fallback
        domain = self.config.get("active_directory", {}).get("domain", "unknown")
        return domain.split(".")[0].lower()
    
    def get_client_info(self) -> Dict[str, Any]:
        """
        Get comprehensive client information.
        
        Returns:
            Dictionary with client identification info
        """
        return {
            "client": {
                "name": self.client_name,
                "slug": self.client_slug,
                "type": self.client_type,
            },
            "domain": {
                "name": self.domain,
                "base_dn": self.base_dn,
            },
            "security": {
                "require_confirmation_for_writes": self.require_confirmation_for_writes,
                "has_automation_token": self.automation_token is not None,
            },
            "warning": f"⚠️ ATENÇÃO: Operações afetam o AD do cliente {self.client_name.upper()} ({self.domain})"
        }
    
    def validate_automation_token(self, token: Optional[str]) -> bool:
        """
        Validate automation token for unattended operations.
        
        Args:
            token: Token provided by automation
            
        Returns:
            True if token is valid, False otherwise
        """
        if not self.automation_token:
            logger.warning("Automation token validation attempted but no token configured")
            return False
        
        if not token:
            return False
        
        # Constant-time comparison to prevent timing attacks
        is_valid = secrets.compare_digest(token, self.automation_token)
        
        if is_valid:
            logger.info("Automation token validated successfully")
        else:
            logger.warning("Invalid automation token provided")
        
        return is_valid
    
    def check_write_permission(
        self,
        operation: str,
        target: str,
        automation_token: Optional[str] = None,
        client_confirmation: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check if a write operation is permitted.
        
        Args:
            operation: Operation name (create_user, delete_user, etc.)
            target: Target object (username, group name, etc.)
            automation_token: Optional automation token for unattended ops
            client_confirmation: Optional client name confirmation for manual ops
            
        Returns:
            Dictionary with permission status and message
        """
        # If automation token is valid, allow without confirmation
        if automation_token and self.validate_automation_token(automation_token):
            self._log_operation(operation, target, "AUTOMATION", True)
            return {
                "permitted": True,
                "mode": "automation",
                "message": f"Operação autorizada via automation token"
            }
        
        # If confirmation is not required, allow
        if not self.require_confirmation_for_writes:
            self._log_operation(operation, target, "NO_CONFIRMATION_REQUIRED", True)
            return {
                "permitted": True,
                "mode": "no_confirmation",
                "message": "Confirmação não requerida para este cliente"
            }
        
        # Check client confirmation
        if client_confirmation:
            # Normalize for comparison
            confirmed_slug = client_confirmation.lower().strip().replace(" ", "-")
            expected_slugs = [
                self.client_slug,
                self.client_name.lower().replace(" ", "-"),
                self.domain.split(".")[0].lower()
            ]
            
            if confirmed_slug in expected_slugs:
                self._log_operation(operation, target, "CONFIRMED", True)
                return {
                    "permitted": True,
                    "mode": "confirmed",
                    "message": f"Operação confirmada para cliente {self.client_name}"
                }
            else:
                self._log_operation(operation, target, "WRONG_CONFIRMATION", False)
                return {
                    "permitted": False,
                    "mode": "wrong_confirmation",
                    "message": f"❌ Confirmação incorreta! Você informou {client_confirmation} mas este é o AD do cliente {self.client_name.upper()} ({self.domain})",
                    "expected": self.client_slug
                }
        
        # No confirmation provided - request it
        return {
            "permitted": False,
            "mode": "requires_confirmation",
            "message": f"⚠️ CONFIRMAÇÃO NECESSÁRIA: Esta operação ({operation}) afetará o AD do cliente {self.client_name.upper()} ({self.domain}). Confirme o nome do cliente para prosseguir.",
            "client_info": self.get_client_info(),
            "confirm_with": self.client_slug
        }
    
    def _log_operation(
        self,
        operation: str,
        target: str,
        auth_mode: str,
        success: bool
    ) -> None:
        """Log operation for audit."""
        if not self.log_all_operations:
            return
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "client": self.client_slug,
            "domain": self.domain,
            "operation": operation,
            "target": target,
            "auth_mode": auth_mode,
            "success": success
        }
        
        logger.info(f"AUDIT: {json.dumps(log_entry)}")
    
    @staticmethod
    def generate_automation_token(client_slug: str) -> str:
        """
        Generate a new automation token for a client.
        
        Args:
            client_slug: Client identifier
            
        Returns:
            Generated token string
        """
        random_part = secrets.token_hex(16)
        token = f"sk-ad-{client_slug}-{random_part}"
        return token


# Global instance (initialized when config is loaded)
_security_manager: Optional[ClientSecurityManager] = None


def init_security_manager(config: Dict[str, Any], config_path: Optional[str] = None) -> ClientSecurityManager:
    """Initialize global security manager."""
    global _security_manager
    _security_manager = ClientSecurityManager(config, config_path)
    return _security_manager


def get_security_manager() -> Optional[ClientSecurityManager]:
    """Get global security manager instance."""
    return _security_manager
