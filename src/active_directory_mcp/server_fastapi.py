"""
FastAPI-based MCP server for Active Directory with Streamable HTTP support.

This module provides full HTTP transport with:
- Streamable HTTP Transport (GET/POST/DELETE) for Gemini CLI compatibility
- Bearer Token authentication for security
- Multi-tenant support
- Session management for long-running connections
"""

import os
import sys
import json
import logging
import asyncio
import uuid
import signal
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager, contextmanager

from fastapi import FastAPI, HTTPException, Request, Header, Depends
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
import uvicorn

from .config.loader import load_config, validate_config
from .config.models import LoggingConfig
from .config.multi_loader import load_multi_config, MultiConfigError
from .core.ad_pool import ADServerPool
from .core.logging import setup_logging
from .core.ldap_manager import LDAPManager
from .core.client_security import init_security_manager
from .tools.user import UserTools
from .tools.group import GroupTools
from .tools.computer import ComputerTools
from .tools.organizational_unit import OrganizationalUnitTools
from .tools.security import SecurityTools
from .tools.prompts import PROMPTS_CATALOG, handle_get_prompt


# ============= MODELS =============

class MCPRequest(BaseModel):
    """MCP JSON-RPC request model."""
    jsonrpc: str = "2.0"
    method: str
    params: Optional[Dict[str, Any]] = None
    id: Optional[Any] = None


class MCPResponse(BaseModel):
    """MCP JSON-RPC response model."""
    jsonrpc: str = "2.0"
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[Any] = None


# ============= SESSION MANAGEMENT =============

mcp_sessions: Dict[str, Dict] = {}


def cleanup_expired_sessions():
    """Remove sessions older than 15 minutes."""
    now = datetime.now(timezone.utc)
    expired = [
        sid for sid, data in mcp_sessions.items()
        if (now - data.get("created_at", now)).total_seconds() > 900
    ]
    for sid in expired:
        del mcp_sessions[sid]


# ============= AUTHENTICATION =============

async def verify_bearer_token(authorization: str = Header(None)) -> str:
    """
    Verify Bearer token from Authorization header.
    Token is configured via AD_MCP_API_TOKEN environment variable.
    """
    expected_token = os.getenv("AD_MCP_API_TOKEN")

    if not expected_token:
        # Se nao houver token configurado, permitir acesso (desenvolvimento)
        return "no_auth_configured"

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid authorization format. Use: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = authorization.replace("Bearer ", "")

    if token != expected_token:
        raise HTTPException(
            status_code=403,
            detail="Invalid or expired token"
        )

    return token


# ============= SERVER CLASS =============

class ActiveDirectoryMCPFastAPI:
    """
    FastAPI-based MCP server for Active Directory.

    Supports:
    - Streamable HTTP Transport (Claude + Gemini)
    - Bearer Token authentication
    - Multi-tenant client identification
    - Full AD management operations
    """

    # Tools that do not target one directory and therefore take no ad_server.
    _GLOBAL_TOOLS = (
        "ad_list_ad_servers",
        "ad_check_ad_server_configured",
        "ad_list_configured_clients",
        "ad_check_client_configuration",
        "ad_health_check_mcp_server",
        "ad_get_mcp_schema_tools_info",
    )

    # Attributes swapped per request in multi-AD mode.
    _TENANT_ATTRS = (
        "config", "ldap_manager", "user_tools", "group_tools",
        "computer_tools", "ou_tools", "security_tools", "security_manager",
    )

    def __init__(
        self,
        config_path: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 8820,
        servers_path: Optional[str] = None,
        mode: Optional[str] = None,
    ):
        self.config_path = config_path
        self.host = host
        self.port = port

        # Mode gate. 'single' keeps the original one-AD-per-process path.
        self.mode = (mode or os.getenv("AD_MCP_MODE") or "single").strip().lower()
        if self.mode not in ("single", "multi"):
            raise ValueError(
                f"AD_MCP_MODE invalido: {self.mode!r}. Use 'single' ou 'multi'."
            )
        self.multi = self.mode == "multi"
        self.pool = None
        self.servers_path = None
        self._bound_server = None
        self._bind_lock = asyncio.Lock()

        if self.multi:
            self._init_multi(servers_path)
        else:
            self._init_single()

        # Build tool registry
        self._build_tool_registry()

        # Create FastAPI app
        self.app = self._create_app()

    def _init_single(self):
        """Single-AD mode: one directory per process (unchanged behaviour)."""
        # Load configuration
        self.config = load_config(self.config_path)
        validate_config(self.config)

        # Setup logging
        self.logger = setup_logging(self.config.logging)

        # Initialize security manager
        self._init_client_security()

        # Initialize LDAP manager
        self.ldap_manager = LDAPManager(
            self.config.active_directory,
            self.config.security,
            self.config.performance,
            ou_config=self.config.organizational_units,
        )

        # Test connection
        self._test_connection()

        # Initialize tools
        self.user_tools = UserTools(self.ldap_manager)
        self.group_tools = GroupTools(self.ldap_manager)
        self.computer_tools = ComputerTools(self.ldap_manager)
        self.ou_tools = OrganizationalUnitTools(self.ldap_manager)
        self.security_tools = SecurityTools(self.ldap_manager)

    def _init_multi(self, servers_path: Optional[str] = None):
        """Multi-AD mode: N directories served by one process.

        No LDAP connection is opened here. A directory is only contacted when a
        tool actually targets it, so a misconfigured or unreachable server
        cannot stop the process from starting.
        """
        self.servers_path = servers_path or os.getenv("AD_MCP_SERVERS")
        entries = load_multi_config(self.servers_path)

        logging_config = LoggingConfig(
            level=os.getenv("AD_MCP_LOG_LEVEL", "INFO"),
            file=os.getenv("AD_MCP_LOG_FILE") or None,
        )
        self.logger = setup_logging(logging_config)

        self.pool = ADServerPool(entries)

        # @MX:ANCHOR Unbound tenant state is None on purpose: any handler that
        # runs outside _bound() must crash loudly instead of silently reusing
        # whichever directory happened to be bound last.
        for name in self._TENANT_ATTRS:
            setattr(self, name, None)

        invalid = {k: e.error for k, e in entries.items() if not e.valid}
        self.logger.info(
            "Modo multi-AD: %d servidores configurados (%d validos) a partir de %s",
            len(entries), len(entries) - len(invalid), self.servers_path,
        )
        for key, error in invalid.items():
            self.logger.error("Servidor '%s' NAO utilizavel: %s", key, error)

    @contextmanager
    def _bound(self, bundle):
        """Bind one directory's managers to self for the duration of a call."""
        saved = {name: getattr(self, name, None) for name in self._TENANT_ATTRS}
        previous_server = self._bound_server
        for name in self._TENANT_ATTRS:
            setattr(self, name, getattr(bundle, name))
        self._bound_server = bundle.key
        try:
            yield bundle
        finally:
            for name, value in saved.items():
                setattr(self, name, value)
            self._bound_server = previous_server

    def _init_client_security(self):
        """Initialize client security manager."""
        try:
            if self.config_path and os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config_dict = json.load(f)
            else:
                config_dict = {}

            self.security_manager = init_security_manager(config_dict, self.config_path)
            self.logger.info(f"Client: {self.security_manager.client_name}")
        except Exception as e:
            self.logger.warning(f"Security manager init failed: {e}")
            self.security_manager = None

    def _test_connection(self):
        """Test LDAP connection on startup."""
        try:
            info = self.ldap_manager.test_connection()
            if info.get('connected'):
                self.logger.info(f"LDAP connected: {info.get('server')}")
            else:
                self.logger.error(f"LDAP failed: {info.get('error')}")
        except Exception as e:
            self.logger.error(f"LDAP test error: {e}")

    def _check_write_permission(self, operation: str, target: str,
                                 automation_token: Optional[str] = None,
                                 client_confirmation: Optional[str] = None) -> dict:
        """Check if write operation is permitted."""
        if not self.security_manager:
            return {"permitted": True, "mode": "no_security"}
        return self.security_manager.check_write_permission(
            operation, target, automation_token, client_confirmation
        )

    def _build_tool_registry(self):
        """Build registry of all available tools."""
        self.tools = {}

        # Client identification tools
        self.tools["ad_get_client_tenant_info"] = {
            "description": "Identificação de cliente e tenant no Active Directory — consulta informações do tenant, domínio e configuração desta instância AD. Use quando precisar confirmar qual cliente AD está conectado antes de operações destrutivas no Active Directory. Retorna nome do cliente, slug, domínio, base DN e configuração multi-tenant. Operação somente leitura.",
            "inputSchema": {"type": "object", "properties": {}},
            "handler": self._handle_get_client_info
        }

        self.tools["ad_list_configured_clients"] = {
            "description": "List all configured AD clients. Use this to check which clients have AD configured before trying to access an AD.",
            "inputSchema": {"type": "object", "properties": {}},
            "handler": self._handle_list_ad_clients
        }

        self.tools["ad_check_client_configuration"] = {
            "description": "Check if a specific client has AD configured. Use this before any AD operation to validate the client exists.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "client_name": {"type": "string", "description": "Client name or slug"}
                },
                "required": ["client_name"]
            },
            "handler": self._handle_check_client_exists
        }

        # User tools
        self.tools["ad_list_users_with_filters"] = {
            "description": "Usuários e contas de domínio no Active Directory — lista todos os users, colaboradores, funcionários e membros do AD com filtros opcionais por OU ou atributos. Use quando precisar listar usuários por departamento, status ou atributos customizados no Active Directory. Retorna coleção de usuários com status de conta, grupos, email e atributos LDAP. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ou": {"type": "string", "description": "OU DN to search in", "anyOf": [{"type": "string"}, {"type": "null"}]},
                    "filter_criteria": {"type": "string", "description": "LDAP filter", "anyOf": [{"type": "string"}, {"type": "null"}]},
                    "attributes": {"type": "array", "items": {}, "description": "Attributes to retrieve", "anyOf": [{"type": "array"}, {"type": "null"}]}
                }
            },
            "handler": self._handle_list_users
        }

        self.tools["ad_get_user_details_by_username"] = {
            "description": "Usuário específico, conta ou colaborador no Active Directory — busca detalhes completos de um user por username (sAMAccountName) incluindo perfil, grupos, permissões e status no AD. Use quando precisar informações detalhadas de uma conta específica no Active Directory. Retorna atributos completos: email, telefone, departamento, grupos, última autenticação e configurações de senha. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username (sAMAccountName)"},
                    "attributes": {"anyOf": [{"type": "array", "items": {}}, {"type": "null"}]}
                },
                "required": ["username"]
            },
            "handler": self._handle_get_user
        }

        self.tools["ad_create_user_account"] = {
            "description": "Criação de usuário, conta ou colaborador no Active Directory — cria novo user no AD com atributos obrigatórios e opcionais, senha inicial e OU de destino. Use quando precisar onboarding de funcionários, criação de contas de serviço ou provisionamento de novos colaboradores no Active Directory. Retorna DN do usuário criado, UPN e confirmação. Operação write - confirme cliente primeiro.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "password": {"type": "string"},
                    "first_name": {"type": "string"},
                    "last_name": {"type": "string"},
                    "email": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "ou": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "additional_attributes": {"anyOf": [{"type": "object"}, {"type": "null"}]},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["username", "password", "first_name", "last_name"]
            },
            "handler": self._handle_create_user
        }

        self.tools["ad_modify_user_attributes"] = {
            "description": "Atualização de atributos de usuário ou colaborador no Active Directory — modifica propriedades existentes de uma conta AD incluindo email, telefone, departamento, cargo e campos customizados. Use quando precisar alterar dados de perfil, atualizar informações organizacionais ou modificar atributos LDAP no Active Directory. Retorna confirmação e lista de atributos modificados. Operação write - confirme cliente primeiro.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "attributes": {"type": "object"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["username", "attributes"]
            },
            "handler": self._handle_modify_user
        }

        self.tools["ad_delete_user_account_permanently"] = {
            "description": "Exclusão permanente de usuário ou conta no Active Directory — remove completamente um user do AD incluindo todos os atributos, grupos e referências. Use quando precisar offboarding de funcionários desligados, limpeza de contas obsoletas ou remoção definitiva no Active Directory. Retorna confirmação de exclusão. Operação write irreversível - confirme cliente primeiro antes de executar.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["username"]
            },
            "handler": self._handle_delete_user
        }

        self.tools["ad_enable_user_account_access"] = {
            "description": "Habilitação de conta de usuário ou colaborador no Active Directory — ativa account desabilitada modificando userAccountControl para permitir autenticação e acesso aos recursos do domínio AD. Use quando precisar reativar contas suspensas, liberar acesso após licença ou habilitar usuários bloqueados no Active Directory. Retorna status de habilitação e userAccountControl atualizado. Operação write.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["username"]
            },
            "handler": self._handle_enable_user
        }

        self.tools["ad_disable_user_account_access"] = {
            "description": "Desabilitação de conta de usuário ou colaborador no Active Directory — desativa account modificando userAccountControl para bloquear autenticação preservando dados e histórico do user no AD. Use quando precisar suspender acesso temporário, bloquear contas comprometidas ou desativar usuários em licença no Active Directory. Retorna status de desabilitação e userAccountControl atualizado. Operação write.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["username"]
            },
            "handler": self._handle_disable_user
        }

        self.tools["ad_reset_user_password_forced"] = {
            "description": "Redefinição de senha de usuário ou colaborador no Active Directory — redefine password com geração automática ou valor customizado, força troca no próximo logon e configura políticas de expiração no AD. Use quando precisar resetar senhas esquecidas, resolver bloqueios de conta ou aplicar políticas de segurança no Active Directory. Retorna nova senha gerada e confirmação. Operação write - confirme cliente.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "new_password": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "force_change": {"type": "boolean", "default": True},
                    "password_never_expires": {"type": "boolean", "default": False},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["username"]
            },
            "handler": self._handle_reset_user_password
        }

        self.tools["ad_get_user_group_memberships"] = {
            "description": "Grupos e memberships de usuário no Active Directory — lista todos os security groups, distribution groups e nested groups dos quais um user é membro direto ou indireto no AD. Use quando precisar auditar permissões, verificar acessos ou analisar memberships de colaboradores no Active Directory. Retorna lista de grupos com tipo, escopo, descrição e nível de aninhamento. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"}
                },
                "required": ["username"]
            },
            "handler": self._handle_get_user_groups
        }

        # Group tools
        self.tools["ad_list_groups_with_filters"] = {
            "description": "Grupos de segurança e distribuição no Active Directory — lista todos os security groups, distribution groups e grupos de email do AD com filtros opcionais por OU ou tipo. Use quando precisar listar grupos por escopo, tipo ou atributos customizados no Active Directory. Retorna coleção de grupos com escopo, tipo, membros e descrição. Consulta somente leitura do AD.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ou": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "filter_criteria": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "attributes": {"anyOf": [{"type": "array", "items": {}}, {"type": "null"}]}
                }
            },
            "handler": self._handle_list_groups
        }

        self.tools["ad_get_group_details_by_name"] = {
            "description": "Grupo específico de segurança ou distribuição no Active Directory — busca detalhes completos de um security group ou distribution group por nome (sAMAccountName) incluindo membros, escopo e tipo no AD. Use quando precisar informações detalhadas de um grupo específico no Active Directory. Retorna atributos completos: membros, parent groups, escopo, tipo e configurações. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string"},
                    "attributes": {"anyOf": [{"type": "array", "items": {}}, {"type": "null"}]}
                },
                "required": ["group_name"]
            },
            "handler": self._handle_get_group
        }

        self.tools["ad_create_group_security_or_distribution"] = {
            "description": "Criação de grupo de segurança ou distribuição no Active Directory — cria novo security group ou distribution group no AD com escopo Global, DomainLocal ou Universal e atributos opcionais. Use quando precisar criar grupos de permissões, grupos de email ou grupos organizacionais no Active Directory. Retorna DN do grupo criado, escopo, tipo e confirmação. Operação write - confirme cliente.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string"},
                    "display_name": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "description": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "ou": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "group_scope": {"type": "string", "default": "Global"},
                    "group_type": {"type": "string", "default": "Security"},
                    "additional_attributes": {"anyOf": [{"type": "object"}, {"type": "null"}]},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["group_name"]
            },
            "handler": self._handle_create_group
        }

        self.tools["ad_modify_group_attributes"] = {
            "description": "Atualização de atributos de grupo no Active Directory — modifica propriedades existentes de um security group ou distribution group no AD incluindo descrição, email, managed by e campos customizados. Use quando precisar alterar configurações de grupos, atualizar responsáveis ou modificar atributos LDAP no Active Directory. Retorna confirmação e lista de atributos modificados. Operação write - confirme cliente.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string"},
                    "attributes": {"type": "object"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["group_name", "attributes"]
            },
            "handler": self._handle_modify_group
        }

        self.tools["ad_delete_group_permanently"] = {
            "description": "Exclusão permanente de grupo no Active Directory — remove completamente um security group ou distribution group do AD incluindo todas as associações e referências de membros. Use quando precisar limpeza de grupos obsoletos, remoção de grupos temporários ou exclusão definitiva no Active Directory. Retorna confirmação de exclusão. Operação write irreversível - confirme cliente primeiro antes de executar.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["group_name"]
            },
            "handler": self._handle_delete_group
        }

        self.tools["ad_add_member_to_group"] = {
            "description": "Adição de membro a grupo no Active Directory — adiciona user, computer ou nested group como membro de um security group ou distribution group no AD. Use quando precisar conceder permissões, adicionar usuários a grupos de email ou criar nested groups no Active Directory. Retorna confirmação de adição e DN do membro. Operação write - confirme cliente primeiro.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string"},
                    "member_dn": {"type": "string"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["group_name", "member_dn"]
            },
            "handler": self._handle_add_group_member
        }

        self.tools["ad_remove_member_from_group"] = {
            "description": "Remoção de membro de grupo no Active Directory — remove user, computer ou nested group de um security group ou distribution group no AD. Use quando precisar revogar permissões, remover usuários de grupos de email ou desfazer nested groups no Active Directory. Retorna confirmação de remoção e DN do membro. Operação write - confirme cliente primeiro.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string"},
                    "member_dn": {"type": "string"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["group_name", "member_dn"]
            },
            "handler": self._handle_remove_group_member
        }

        self.tools["ad_get_group_members_recursive"] = {
            "description": "Membros de grupo com recursão no Active Directory — lista todos os members de um security group ou distribution group incluindo nested groups expandidos recursivamente no AD. Use quando precisar auditar memberships completos, verificar permissões indiretas ou analisar hierarquia de grupos no Active Directory. Retorna lista de membros com tipo, nível de aninhamento e DN. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string"},
                    "recursive": {"type": "boolean", "default": False}
                },
                "required": ["group_name"]
            },
            "handler": self._handle_get_group_members
        }

        # Computer tools
        self.tools["ad_list_computers_with_filters"] = {
            "description": "Computadores e workstations no Active Directory — lista todos os computer accounts, estações de trabalho e servidores do AD com filtros opcionais por OU ou sistema operacional. Use quando precisar inventariar máquinas, auditar computer accounts ou buscar por tipo de OS no Active Directory. Retorna coleção de computers com OS, último logon, status e atributos. Consulta somente leitura do AD.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ou": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "filter_criteria": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "attributes": {"anyOf": [{"type": "array", "items": {}}, {"type": "null"}]}
                }
            },
            "handler": self._handle_list_computers
        }

        self.tools["ad_get_computer_details_by_name"] = {
            "description": "Computador específico ou workstation no Active Directory — busca detalhes completos de um computer account por nome (sAMAccountName) incluindo OS, último logon, grupos e status no AD. Use quando precisar informações detalhadas de uma máquina específica no Active Directory. Retorna atributos completos: sistema operacional, DNS, service principal names, grupos e configurações. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string"},
                    "attributes": {"anyOf": [{"type": "array", "items": {}}, {"type": "null"}]}
                },
                "required": ["computer_name"]
            },
            "handler": self._handle_get_computer
        }

        self.tools["ad_create_computer_account"] = {
            "description": "Criação de conta de computador ou workstation no Active Directory — cria novo computer account no AD com DNS hostname, service principal names e OU de destino. Use quando precisar pré-criar contas de máquinas, provisionamento de workstations ou criação de computer objects no Active Directory. Retorna DN do computer criado, DNS hostname e SPNs. Operação write - confirme cliente.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string"},
                    "description": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "ou": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "dns_hostname": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "additional_attributes": {"anyOf": [{"type": "object"}, {"type": "null"}]},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["computer_name"]
            },
            "handler": self._handle_create_computer
        }

        self.tools["ad_modify_computer_attributes"] = {
            "description": "Atualização de atributos de computador no Active Directory — modifica propriedades existentes de um computer account no AD incluindo descrição, localização, managed by e campos customizados. Use quando precisar alterar configurações de máquinas, atualizar informações de inventário ou modificar atributos LDAP no Active Directory. Retorna confirmação e lista de atributos modificados. Operação write - confirme cliente.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string"},
                    "attributes": {"type": "object"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["computer_name", "attributes"]
            },
            "handler": self._handle_modify_computer
        }

        self.tools["ad_delete_computer_account_permanently"] = {
            "description": "Exclusão permanente de conta de computador no Active Directory — remove completamente um computer account do AD incluindo todas as associações, SPNs e referências. Use quando precisar descomissionamento de máquinas, limpeza de computer accounts obsoletos ou remoção definitiva no Active Directory. Retorna confirmação de exclusão. Operação write irreversível - confirme cliente primeiro antes de executar.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["computer_name"]
            },
            "handler": self._handle_delete_computer
        }

        self.tools["ad_enable_computer_account_trust"] = {
            "description": "Habilitação de conta de computador no Active Directory — ativa computer account desabilitado modificando userAccountControl para restabelecer trust relationship e permitir autenticação de máquina no AD. Use quando precisar reativar contas de computadores, restabelecer trust de workstations ou habilitar computer accounts no Active Directory. Retorna status de habilitação e userAccountControl atualizado. Operação write.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["computer_name"]
            },
            "handler": self._handle_enable_computer
        }

        self.tools["ad_disable_computer_account_trust"] = {
            "description": "Desabilitação de conta de computador no Active Directory — desativa computer account modificando userAccountControl para quebrar trust relationship e bloquear autenticação de máquina preservando histórico no AD. Use quando precisar isolar máquinas comprometidas, desativar workstations antigas ou bloquear computer accounts no Active Directory. Retorna status de desabilitação e userAccountControl atualizado. Operação write.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["computer_name"]
            },
            "handler": self._handle_disable_computer
        }

        self.tools["ad_reset_computer_password_trust"] = {
            "description": "Redefinição de senha de conta de computador no Active Directory — redefine password do computer account para reestabelecer trust relationship e resolver erros de autenticação de máquina no AD. Use quando precisar corrigir trust relationship quebrado, resolver erros de logon de workstation ou resetar senhas de computer accounts no Active Directory. Retorna confirmação de reset. Operação write - confirme cliente.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["computer_name"]
            },
            "handler": self._handle_reset_computer_password
        }

        self.tools["ad_get_inactive_computers_by_days"] = {
            "description": "Computadores inativos ou obsoletos no Active Directory — identifica computer accounts que não autenticaram no AD por número de dias especificado, indicando máquinas desconectadas ou obsoletas. Use quando precisar auditar inventário, identificar workstations abandonadas ou realizar limpeza de computer accounts no Active Directory. Retorna lista de computers com dias de inatividade, último logon e status. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "days": {"type": "integer", "default": 90}
                }
            },
            "handler": self._handle_get_stale_computers
        }

        # OU tools
        self.tools["ad_list_organizational_units_hierarchy"] = {
            "description": "Unidades organizacionais e estrutura hierárquica no Active Directory — lista todas as OUs (organizational units), containers e estrutura de organização do AD com opção de busca recursiva. Use quando precisar mapear hierarquia organizacional, listar OUs por nível ou auditar estrutura de containers no Active Directory. Retorna coleção de OUs com nível hierárquico, parent OU e GPOs vinculados. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "parent_ou": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "filter_criteria": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "attributes": {"anyOf": [{"type": "array", "items": {}}, {"type": "null"}]},
                    "recursive": {"type": "boolean", "default": True}
                }
            },
            "handler": self._handle_list_organizational_units
        }

        self.tools["ad_get_organizational_unit_details"] = {
            "description": "Unidade organizacional específica no Active Directory — busca detalhes completos de uma OU (organizational unit) por DN incluindo objetos contidos, GPOs vinculados e managed by no AD. Use quando precisar informações detalhadas de uma OU específica, auditar GPO links ou verificar conteúdo de containers no Active Directory. Retorna atributos completos: objetos, sub-OUs, GPOs e configurações. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ou_dn": {"type": "string"},
                    "attributes": {"anyOf": [{"type": "array", "items": {}}, {"type": "null"}]}
                },
                "required": ["ou_dn"]
            },
            "handler": self._handle_get_organizational_unit
        }

        self.tools["ad_create_organizational_unit"] = {
            "description": "Criação de unidade organizacional no Active Directory — cria nova OU (organizational unit) no AD com parent OU, descrição, managed by e atributos opcionais. Use quando precisar estruturar hierarquia organizacional, criar containers para segregação ou organizar objetos por departamento no Active Directory. Retorna DN da OU criada, parent OU e confirmação. Operação write - confirme cliente primeiro.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "parent_ou": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "description": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "managed_by": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "additional_attributes": {"anyOf": [{"type": "object"}, {"type": "null"}]},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["name"]
            },
            "handler": self._handle_create_organizational_unit
        }

        self.tools["ad_modify_organizational_unit_attributes"] = {
            "description": "Atualização de atributos de unidade organizacional no Active Directory — modifica propriedades existentes de uma OU (organizational unit) no AD incluindo descrição, managed by, location e campos customizados. Use quando precisar alterar configurações de OUs, atualizar responsáveis ou modificar atributos LDAP no Active Directory. Retorna confirmação e lista de atributos modificados. Operação write - confirme cliente.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ou_dn": {"type": "string"},
                    "attributes": {"type": "object"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["ou_dn", "attributes"]
            },
            "handler": self._handle_modify_organizational_unit
        }

        self.tools["ad_delete_organizational_unit_forced"] = {
            "description": "Exclusão de unidade organizacional no Active Directory — remove OU (organizational unit) do AD com opção de exclusão forçada incluindo todos os objetos contidos. Use quando precisar reestruturar hierarquia, remover OUs obsoletas ou executar limpeza de containers no Active Directory. Retorna confirmação de exclusão e contagem de objetos removidos. Operação write irreversível - confirme cliente primeiro.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ou_dn": {"type": "string"},
                    "force": {"type": "boolean", "default": False},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["ou_dn"]
            },
            "handler": self._handle_delete_organizational_unit
        }

        self.tools["ad_move_organizational_unit_parent"] = {
            "description": "Movimentação de unidade organizacional no Active Directory — move OU (organizational unit) para novo parent container no AD preservando todos os objetos contidos e GPO links. Use quando precisar reestruturar hierarquia organizacional, reorganizar containers ou mover OUs entre níveis no Active Directory. Retorna novo DN, novo parent OU e confirmação. Operação write - confirme cliente primeiro antes de executar.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ou_dn": {"type": "string"},
                    "new_parent_dn": {"type": "string"},
                    "automation_token": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                    "client_confirmation": {"anyOf": [{"type": "string"}, {"type": "null"}]}
                },
                "required": ["ou_dn", "new_parent_dn"]
            },
            "handler": self._handle_move_organizational_unit
        }

        self.tools["ad_get_organizational_unit_objects"] = {
            "description": "Conteúdo de unidade organizacional no Active Directory — lista todos os objetos contidos em uma OU (organizational unit) incluindo users, groups, computers e sub-OUs com filtros opcionais por tipo no AD. Use quando precisar auditar conteúdo de OUs, inventariar objetos por container ou verificar estrutura organizacional no Active Directory. Retorna lista de objetos com tipo, DN e atributos básicos. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ou_dn": {"type": "string"},
                    "object_types": {"anyOf": [{"type": "array", "items": {}}, {"type": "null"}]}
                },
                "required": ["ou_dn"]
            },
            "handler": self._handle_get_organizational_unit_contents
        }

        # Security tools
        self.tools["ad_get_domain_security_policy_info"] = {
            "description": "Informações de domínio e políticas de segurança no Active Directory — consulta configurações do domínio AD incluindo password policy, lockout policy, SID do domínio e políticas de segurança. Use quando precisar auditar políticas de senha, verificar configurações de lockout ou obter informações gerais do domínio no Active Directory. Retorna políticas de senha, lockout threshold, max password age e configurações. Consulta somente leitura.",
            "inputSchema": {"type": "object", "properties": {}},
            "handler": self._handle_get_domain_info
        }

        self.tools["ad_get_privileged_security_groups"] = {
            "description": "Grupos privilegiados e administrativos no Active Directory — lista todos os security groups com privilégios elevados no AD incluindo Domain Admins, Enterprise Admins, Schema Admins e grupos de operadores. Use quando precisar auditar permissões administrativas, verificar memberships privilegiados ou realizar análise de segurança no Active Directory. Retorna lista de grupos privilegiados com membros, SID e descrição. Consulta somente leitura.",
            "inputSchema": {"type": "object", "properties": {}},
            "handler": self._handle_get_privileged_groups
        }

        self.tools["ad_get_user_effective_permissions"] = {
            "description": "Permissões efetivas de usuário no Active Directory — analisa memberships de grupos de um user no AD para determinar permissões efetivas, grupos privilegiados e riscos de segurança. Use quando precisar auditar permissões de contas, verificar acessos elevados ou analisar riscos de segurança de usuários no Active Directory. Retorna permissões efetivas, grupos privilegiados e assessment de segurança. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"}
                },
                "required": ["username"]
            },
            "handler": self._handle_get_user_permissions
        }

        self.tools["ad_get_inactive_users_by_days"] = {
            "description": "Usuários inativos ou sem autenticação no Active Directory — identifica user accounts que não autenticaram no AD por número de dias especificado, indicando contas obsoletas ou não utilizadas. Use quando precisar auditar contas inativas, identificar usuários para desativação ou realizar análise de segurança no Active Directory. Retorna lista de usuários com dias de inatividade, último logon, grupos e status. Consulta somente leitura.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "days": {"type": "integer", "default": 90},
                    "include_disabled": {"type": "boolean", "default": False}
                }
            },
            "handler": self._handle_get_inactive_users
        }

        self.tools["ad_get_password_policy_violations"] = {
            "description": "Violações de política de senha no Active Directory — identifica user accounts com passwords que violam políticas de segurança no AD incluindo senhas expiradas, senhas que nunca expiram e non-compliance com políticas. Use quando precisar auditar conformidade de senhas, identificar contas com riscos de segurança ou validar políticas de password no Active Directory. Retorna lista de violações com tipo, usuário e detalhes. Consulta somente leitura.",
            "inputSchema": {"type": "object", "properties": {}},
            "handler": self._handle_get_password_policy_violations
        }

        self.tools["ad_audit_administrative_accounts"] = {
            "description": "Auditoria de contas administrativas no Active Directory — realiza audit abrangente de administrative accounts no AD incluindo memberships privilegiados, compliance de políticas e assessment de riscos de segurança. Use quando precisar auditar segurança de contas admin, verificar conformidade de políticas ou realizar análise de riscos no Active Directory. Retorna relatório completo com violações, riscos e recomendações. Consulta somente leitura.",
            "inputSchema": {"type": "object", "properties": {}},
            "handler": self._handle_audit_admin_accounts
        }

        # System tools
        self.tools["ad_test_ldap_connection_status"] = {
            "description": "Teste de conexão LDAP com Active Directory — verifica conectividade LDAP, bind authentication e capacidade de search no servidor AD para diagnosticar problemas de conexão. Use quando precisar troubleshooting de conectividade, verificar credenciais LDAP ou validar acesso ao servidor no Active Directory. Retorna status de conexão, bind result, server info e resultados de test search. Operação diagnóstica somente leitura.",
            "inputSchema": {"type": "object", "properties": {}},
            "handler": self._handle_test_connection
        }

        self.tools["ad_health_check_mcp_server"] = {
            "description": "Health check do servidor MCP Active Directory — verifica status geral do MCP server AD incluindo conexão LDAP, client info, testes de inicialização e disponibilidade de serviços. Use quando precisar monitoramento de saúde, alertas de disponibilidade ou diagnóstico de problemas no servidor MCP do Active Directory. Retorna status do servidor, conexão LDAP, client info e resultados de health checks. Operação diagnóstica somente leitura.",
            "inputSchema": {"type": "object", "properties": {}},
            "handler": self._handle_health
        }

        self.tools["ad_get_mcp_schema_tools_info"] = {
            "description": "Informações de schema e tools disponíveis no Active Directory MCP — retorna metadados completos de todas as tools disponíveis no servidor MCP AD incluindo parâmetros, permissões e documentação. Use quando precisar documentação de API, descoberta de tools disponíveis ou informações de schema no servidor MCP do Active Directory. Retorna lista completa de tools, parâmetros, operations e client info. Operação diagnóstica somente leitura.",
            "inputSchema": {"type": "object", "properties": {}},
            "handler": self._handle_get_schema_info
        }

        # ---------------------------------------------------------------
        # Multi-AD layer (no-op in single mode)
        # ---------------------------------------------------------------
        for name in self._GLOBAL_TOOLS:
            if name in self.tools:
                self.tools[name]["global"] = True

        if self.multi:
            self._register_multi_ad_tools()
            self._inject_ad_server_parameter()

    # ============= MULTI-AD LAYER =============

    _AD_SERVER_PARAM = {
        "type": "string",
        "description": (
            "Servidor de Active Directory alvo. OBRIGATORIO nesta tool de escrita: "
            "uma alteracao precisa nomear um unico diretorio, e 'todos' nao e aceito. "
            "Use ad_list_ad_servers para os nomes."
        ),
    }

    _AD_SERVER_PARAM_LEITURA = {
        "type": "string",
        "description": (
            "Servidor de Active Directory a consultar. Opcional: se omitido, ou com "
            "'todos'/'all', a busca roda em TODOS os ADs configurados e a resposta diz "
            "em qual cada resultado foi encontrado. Use isso quando nao souber onde a "
            "pessoa ou o objeto esta. Use ad_list_ad_servers para os nomes."
        ),
    }

    def _register_multi_ad_tools(self) -> None:
        """Swap the client-shaped catalogue tools for server-shaped ones.

        In multi-AD mode the axis is the SERVER, not "the client": a name with
        "client" in it invites the model to pass a customer name where a routing
        key is expected. The two legacy tools are also redundant here -- three
        tools answering "which directories exist?" is three chances to pick the
        wrong one -- so multi mode registers exactly two.
        """
        self.tools.pop("ad_list_configured_clients", None)
        self.tools.pop("ad_check_client_configuration", None)

        self.tools["ad_check_ad_server_configured"] = {
            "description": (
                "Verificacao de servidor de Active Directory nesta instancia \u2014 confirma se "
                "um nome, apelido, dominio ou nome de cliente corresponde a um AD configurado "
                "aqui e devolve o valor exato para o parametro ad_server. Use quando o usuario "
                "citar o cliente pelo nome e voce precisar do ad_server correspondente, ou para "
                "responder se determinado cliente tem AD nesta instancia. Retorna se existe, o "
                "ad_server a usar, nome e dominio; quando nao existe, retorna a lista dos que "
                "existem. Consulta somente leitura."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server_name": {
                        "type": "string",
                        "description": "Nome, apelido, dominio ou nome do cliente a verificar",
                    }
                },
                "required": ["server_name"],
            },
            "handler": self._handle_check_client_exists,
            "global": True,
        }

        self.tools["ad_list_ad_servers"] = {
            "description": (
                "Servidores de Active Directory disponiveis nesta instancia \u2014 lista os ADs "
                "configurados com o nome exato a usar no parametro ad_server, dominio, host "
                "LDAP, base DN, unidades organizacionais e estado da conexao. Use quando nao "
                "souber qual valor passar em ad_server, quando o usuario citar um cliente sem "
                "dizer o servidor, ou para confirmar se um cliente tem AD configurado aqui. "
                "Retorna nome, apelidos, dominio, servidor LDAP, base DN, OUs e status por "
                "servidor. Credenciais de bind nao sao expostas. Consulta somente leitura."
            ),
            "inputSchema": {"type": "object", "properties": {}},
            "handler": self._handle_list_ad_servers,
            "global": True,
        }

    # Values that mean "every configured directory".
    _TODOS = {"all", "todos", "todas", "*", "any", "qualquer", "geral", "tudo"}

    def _is_write_tool(self, tool: dict) -> bool:
        """A tool is a write when its own schema asks for a confirmation.

        @MX:ANCHOR Derived from the schema, never from a hand-kept list: a new
        write tool is covered the moment it declares client_confirmation.
        """
        props = (tool.get("inputSchema") or {}).get("properties") or {}
        return "client_confirmation" in props or "automation_token" in props

    def _inject_ad_server_parameter(self) -> None:
        """Add the required ad_server parameter to every directory-bound tool.

        @MX:ANCHOR The schema is the only place the requirement is declared;
        handle_tools_call is the only place it is enforced. Both must agree on
        the same set (everything not marked "global").
        """
        for name, tool in self.tools.items():
            if tool.get("global"):
                continue
            escrita = self._is_write_tool(tool)
            tool["write"] = escrita

            schema = dict(tool.get("inputSchema") or {"type": "object"})
            properties = dict(schema.get("properties") or {})
            param = dict(self._AD_SERVER_PARAM if escrita else self._AD_SERVER_PARAM_LEITURA)
            # ad_server first: the model reads the routing key before the payload.
            merged = {"ad_server": param}
            merged.update(properties)
            schema["properties"] = merged

            required = list(schema.get("required") or [])
            if escrita:
                # A write must name exactly one directory. There is no "all".
                if "ad_server" not in required:
                    required.insert(0, "ad_server")
            else:
                # Reads may omit it: absent means every configured directory.
                required = [r for r in required if r != "ad_server"]
            schema["required"] = required
            tool["inputSchema"] = schema

    def _handle_list_ad_servers(self, params: dict) -> dict:
        if not self.multi or self.pool is None:
            return {
                "modo": "single",
                "total": 1,
                "mensagem": (
                    "Esta instancia atende um unico Active Directory, entao nao existe "
                    "parametro ad_server. Nao informe ad_server nas demais tools."
                ),
                "servidor": {
                    "dominio": self.config.active_directory.domain,
                    "servidor_ldap": self.config.active_directory.server,
                    "base_dn": self.config.active_directory.base_dn,
                },
            }
        return self.pool.list_servers()

    # ============= TOOL HANDLERS =============

    def _format_result(self, result) -> dict:
        """Format tool result for MCP response."""
        if isinstance(result, list) and len(result) > 0:
            # Handle MCP TextContent format
            if hasattr(result[0], 'text'):
                try:
                    return json.loads(result[0].text)
                except:
                    return {"text": result[0].text}
        if isinstance(result, dict):
            return result
        return {"result": str(result)}

    def _handle_get_client_info(self, params: dict) -> dict:
        if self.security_manager:
            info = self.security_manager.get_client_info()
            if self.multi and self._bound_server:
                info["ad_server"] = self._bound_server
            return info
        return {
            "client": {"name": "Unknown", "slug": "unknown"},
            "domain": {"name": self.config.active_directory.domain},
            "warning": "Security manager not initialized"
        }

    def _handle_list_ad_clients(self, params: dict) -> dict:
        if self.multi and self.pool is not None:
            listing = self.pool.list_servers()
            return {
                "total": listing["total"],
                "clients": [
                    {
                        "slug": s["ad_server"],
                        "name": s["nome"],
                        "domain": s["dominio"],
                        "type": s.get("tipo", "cliente"),
                        "status": s["status"],
                    }
                    for s in listing["servidores"]
                ],
                "message": (
                    "Clientes com AD configurado nesta instancia multi-AD. Use o campo "
                    "'slug' no parametro ad_server das demais tools."
                ),
                "detalhes": "Chame ad_list_ad_servers para dominio, host, base DN e OUs.",
            }

        # Single-AD mode: this process serves exactly one client, and saying
        # so is the whole truth available here. (There used to be a central
        # registry file; it pointed at a path that never existed and listed
        # ports that were never used, so it always answered "no clients".)
        if not self.security_manager:
            return {
                "total": 0,
                "clients": [],
                "message": "Identificacao de cliente indisponivel nesta instancia.",
            }
        return {
            "total": 1,
            "clients": [{
                "slug": self.security_manager.client_slug,
                "name": self.security_manager.client_name,
                "domain": self.security_manager.domain,
                "type": self.security_manager.client_type,
            }],
            "current_instance": {
                "name": self.security_manager.client_name,
                "slug": self.security_manager.client_slug,
                "domain": self.security_manager.domain,
            },
            "message": (
                f"Esta instancia atende um unico cliente: "
                f"{self.security_manager.client_name} ({self.security_manager.domain}). "
                "Outros clientes podem existir em outras instancias e nao aparecem aqui."
            ),
        }

    def _handle_check_client_exists(self, params: dict) -> dict:
        # server_name is the multi-AD name; client_name is the single-AD legacy one.
        client_name = params.get("server_name") or params.get("client_name") or ""

        if self.multi and self.pool is not None:
            bundle, error = self.pool.resolve_or_error(client_name)
            if error is not None:
                return {"exists": False, "searched_for": client_name, **error}
            return {
                "exists": True,
                "client": {
                    "slug": bundle.key,
                    "name": bundle.entry.label,
                    "domain": bundle.entry.domain,
                },
                "ad_server": bundle.key,
                "message": (
                    f"Cliente '{bundle.entry.label}' tem AD configurado. Use "
                    f"ad_server='{bundle.key}'."
                ),
            }

        if not self.security_manager:
            return {"exists": False, "searched_for": client_name,
                    "message": "Identificacao de cliente indisponivel nesta instancia."}

        normalized = str(client_name).lower().strip().replace(" ", "-")
        known = {
            self.security_manager.client_slug,
            self.security_manager.client_name.lower().replace(" ", "-"),
            self.security_manager.domain.split(".")[0].lower(),
        }
        if normalized in known:
            return {
                "exists": True,
                "client": {
                    "slug": self.security_manager.client_slug,
                    "name": self.security_manager.client_name,
                    "domain": self.security_manager.domain,
                },
            }
        return {
            "exists": False,
            "searched_for": client_name,
            "available": [f"{self.security_manager.client_name} "
                          f"({self.security_manager.client_slug})"],
            "message": (
                f"Esta instancia atende apenas {self.security_manager.client_name}. "
                f"Nao e possivel afirmar, daqui, se '{client_name}' tem AD em outra "
                "instancia."
            ),
        }

    def _handle_list_users(self, params: dict) -> dict:
        result = self.user_tools.list_users(
            params.get("ou"), params.get("filter_criteria"), params.get("attributes")
        )
        return self._format_result(result)

    def _handle_get_user(self, params: dict) -> dict:
        result = self.user_tools.get_user(params["username"], params.get("attributes"))
        return self._format_result(result)

    def _handle_create_user(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_create_user_account", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.user_tools.create_user(
            params["username"], params["password"], params["first_name"], params["last_name"],
            params.get("email"), params.get("ou"), params.get("additional_attributes")
        )
        return self._format_result(result)

    def _handle_modify_user(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_modify_user_attributes", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.user_tools.modify_user(params["username"], params["attributes"])
        return self._format_result(result)

    def _handle_delete_user(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_delete_user_account_permanently", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.user_tools.delete_user(params["username"])
        return self._format_result(result)

    def _handle_enable_user(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_enable_user_account_access", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.user_tools.enable_user(params["username"])
        return self._format_result(result)

    def _handle_disable_user(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_disable_user_account_access", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.user_tools.disable_user(params["username"])
        return self._format_result(result)

    def _handle_reset_user_password(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_reset_user_password_forced", params["username"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.user_tools.reset_password(
            params["username"], params.get("new_password"),
            params.get("force_change", True), params.get("password_never_expires", False)
        )
        return self._format_result(result)

    def _handle_get_user_groups(self, params: dict) -> dict:
        result = self.user_tools.get_user_groups(params["username"])
        return self._format_result(result)

    def _handle_list_groups(self, params: dict) -> dict:
        result = self.group_tools.list_groups(
            params.get("ou"), params.get("filter_criteria"), params.get("attributes")
        )
        return self._format_result(result)

    def _handle_get_group(self, params: dict) -> dict:
        result = self.group_tools.get_group(params["group_name"], params.get("attributes"))
        return self._format_result(result)

    def _handle_create_group(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_create_group_security_or_distribution", params["group_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.group_tools.create_group(
            params["group_name"], params.get("display_name"), params.get("description"),
            params.get("ou"), params.get("group_scope", "Global"),
            params.get("group_type", "Security"), params.get("additional_attributes")
        )
        return self._format_result(result)

    def _handle_modify_group(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_modify_group_attributes", params["group_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.group_tools.modify_group(params["group_name"], params["attributes"])
        return self._format_result(result)

    def _handle_delete_group(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_delete_group_permanently", params["group_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.group_tools.delete_group(params["group_name"])
        return self._format_result(result)

    def _handle_add_group_member(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_add_member_to_group", params["group_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.group_tools.add_member(params["group_name"], params["member_dn"])
        return self._format_result(result)

    def _handle_remove_group_member(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_remove_member_from_group", params["group_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.group_tools.remove_member(params["group_name"], params["member_dn"])
        return self._format_result(result)

    def _handle_get_group_members(self, params: dict) -> dict:
        result = self.group_tools.get_members(params["group_name"], params.get("recursive", False))
        return self._format_result(result)

    def _handle_list_computers(self, params: dict) -> dict:
        result = self.computer_tools.list_computers(
            params.get("ou"), params.get("filter_criteria"), params.get("attributes")
        )
        return self._format_result(result)

    def _handle_get_computer(self, params: dict) -> dict:
        result = self.computer_tools.get_computer(params["computer_name"], params.get("attributes"))
        return self._format_result(result)

    def _handle_create_computer(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_create_computer_account", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.create_computer(
            params["computer_name"], params.get("description"), params.get("ou"),
            params.get("dns_hostname"), params.get("additional_attributes")
        )
        return self._format_result(result)

    def _handle_modify_computer(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_modify_computer_attributes", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.modify_computer(params["computer_name"], params["attributes"])
        return self._format_result(result)

    def _handle_delete_computer(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_delete_computer_account_permanently", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.delete_computer(params["computer_name"])
        return self._format_result(result)

    def _handle_enable_computer(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_enable_computer_account_trust", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.enable_computer(params["computer_name"])
        return self._format_result(result)

    def _handle_disable_computer(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_disable_computer_account_trust", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.disable_computer(params["computer_name"])
        return self._format_result(result)

    def _handle_reset_computer_password(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_reset_computer_password_trust", params["computer_name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.computer_tools.reset_computer_password(params["computer_name"])
        return self._format_result(result)

    def _handle_get_stale_computers(self, params: dict) -> dict:
        result = self.computer_tools.get_stale_computers(params.get("days", 90))
        return self._format_result(result)

    def _handle_list_organizational_units(self, params: dict) -> dict:
        result = self.ou_tools.list_ous(
            params.get("parent_ou"), params.get("filter_criteria"),
            params.get("attributes"), params.get("recursive", True)
        )
        return self._format_result(result)

    def _handle_get_organizational_unit(self, params: dict) -> dict:
        result = self.ou_tools.get_ou(params["ou_dn"], params.get("attributes"))
        return self._format_result(result)

    def _handle_create_organizational_unit(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_create_organizational_unit", params["name"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.ou_tools.create_ou(
            params["name"], params.get("parent_ou"), params.get("description"),
            params.get("managed_by"), params.get("additional_attributes")
        )
        return self._format_result(result)

    def _handle_modify_organizational_unit(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_modify_organizational_unit_attributes", params["ou_dn"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.ou_tools.modify_ou(params["ou_dn"], params["attributes"])
        return self._format_result(result)

    def _handle_delete_organizational_unit(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_delete_organizational_unit_forced", params["ou_dn"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.ou_tools.delete_ou(params["ou_dn"], params.get("force", False))
        return self._format_result(result)

    def _handle_move_organizational_unit(self, params: dict) -> dict:
        perm = self._check_write_permission("ad_move_organizational_unit_parent", params["ou_dn"],
                                            params.get("automation_token"),
                                            params.get("client_confirmation"))
        if not perm.get("permitted"):
            return perm
        result = self.ou_tools.move_ou(params["ou_dn"], params["new_parent_dn"])
        return self._format_result(result)

    def _handle_get_organizational_unit_contents(self, params: dict) -> dict:
        result = self.ou_tools.get_ou_contents(params["ou_dn"], params.get("object_types"))
        return self._format_result(result)

    def _handle_get_domain_info(self, params: dict) -> dict:
        result = self.security_tools.get_domain_info()
        return self._format_result(result)

    def _handle_get_privileged_groups(self, params: dict) -> dict:
        result = self.security_tools.get_privileged_groups()
        return self._format_result(result)

    def _handle_get_user_permissions(self, params: dict) -> dict:
        result = self.security_tools.get_user_permissions(params["username"])
        return self._format_result(result)

    def _handle_get_inactive_users(self, params: dict) -> dict:
        result = self.security_tools.get_inactive_users(
            params.get("days", 90), params.get("include_disabled", False)
        )
        return self._format_result(result)

    def _handle_get_password_policy_violations(self, params: dict) -> dict:
        result = self.security_tools.get_password_policy_violations()
        return self._format_result(result)

    def _handle_audit_admin_accounts(self, params: dict) -> dict:
        result = self.security_tools.audit_admin_accounts()
        return self._format_result(result)

    def _handle_test_connection(self, params: dict) -> dict:
        try:
            return self.ldap_manager.test_connection()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _handle_health(self, params: dict) -> dict:
        if self.multi and self.pool is not None:
            listing = self.pool.list_servers()
            servers = listing["servidores"]
            broken = [s["ad_server"] for s in servers
                      if s["status"] in ("configuracao_invalida", "erro")]
            health_info = {
                "status": "degraded" if broken else "ok",
                "server": "ActiveDirectoryMCP-FastAPI",
                "version": "1.1.0",
                "mode": "multi",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "transport": "streamable-http",
                "total_servidores": listing["total"],
                "total_habilitados": listing["total_habilitados"],
                "servidores": [
                    {"ad_server": s["ad_server"], "dominio": s["dominio"],
                     "status": s["status"]}
                    for s in servers
                ],
                "nota": (
                    "Servidores com status 'nao_conectado' ainda nao foram usados nesta "
                    "execucao. A conexao LDAP so e aberta na primeira operacao, portanto "
                    "este health check nao afirma nada sobre a saude deles."
                ),
            }
            if broken:
                health_info["servidores_com_problema"] = broken
            return health_info

        health_info = {
            "status": "ok",
            "server": "ActiveDirectoryMCP-FastAPI",
            "version": "1.1.0",
            "mode": "single",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "transport": "streamable-http",
            "ldap_connection": "unknown"
        }

        if self.security_manager:
            health_info["client"] = {
                "name": self.security_manager.client_name,
                "slug": self.security_manager.client_slug,
                "domain": self.security_manager.domain
            }

        try:
            conn_info = self.ldap_manager.test_connection()
            health_info["ldap_connection"] = "connected" if conn_info.get("connected") else "error"
            health_info["ldap_server"] = conn_info.get("server", "unknown")
        except Exception as e:
            health_info["ldap_connection"] = "error"
            health_info["ldap_error"] = str(e)
            health_info["status"] = "degraded"

        return health_info

    def _handle_get_schema_info(self, params: dict) -> dict:
        info = {
            "server": "ActiveDirectoryMCP-FastAPI",
            "version": "1.1.0",
            "transport": "streamable-http",
            "mode": self.mode,
            "multi_tenant": True,
            "total_tools": len(self.tools),
            "tools": list(self.tools.keys())
        }
        if self.multi:
            info["ad_server_obrigatorio_em"] = sorted(
                name for name, tool in self.tools.items() if not tool.get("global")
            )
            info["tools_sem_ad_server"] = sorted(
                name for name, tool in self.tools.items() if tool.get("global")
            )
            info["total_servidores"] = len(self.pool.entries) if self.pool else 0
        return info

    # ============= MCP PROTOCOL HANDLERS =============

    async def handle_initialize(self, params: dict) -> dict:
        """Handle MCP initialize method."""
        return {
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "mcp-active-directory",
                "version": "1.0.0"
            },
            "capabilities": {
                "tools": {},
                "prompts": {}
            }
        }

    async def handle_tools_list(self, params: dict) -> dict:
        """Handle tools/list method."""
        tools_list = []
        for name, tool in self.tools.items():
            tools_list.append({
                "name": name,
                "description": tool["description"],
                "inputSchema": tool["inputSchema"]
            })
        return {"tools": tools_list}

    def _as_content(self, payload) -> dict:
        """Wrap a payload in the MCP content envelope."""
        return {
            "content": [
                {"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}
            ]
        }

    # ============= ENTRADA DE MODELO FRACO =============
    # The server owns its schema, so it can absorb the shapes a model actually
    # sends instead of answering with a Python exception the model cannot act on.

    _CAMPOS_DE_LOGIN = ("username", "computer_name", "group_name")
    _LIMITE_DIAS = 36500  # a hundred years; beyond this datetime itself overflows

    @staticmethod
    def _extrair_login(valor: str) -> str:
        """Reduce a DN, a UPN or DOMAIN\\user to the bare account name."""
        texto = str(valor).strip().strip('"').strip("'")
        if not texto:
            return texto
        if "=" in texto and "," in texto:          # CN=Joao Silva,CN=Users,DC=...
            primeiro = texto.split(",")[0]
            if "=" in primeiro:
                return primeiro.split("=", 1)[1].strip()
        if "\\" in texto:                          # DOMINIO\usuario
            return texto.rsplit("\\", 1)[1].strip()
        if "@" in texto:                            # usuario@dominio
            return texto.split("@", 1)[0].strip()
        return texto

    @staticmethod
    def _coagir(valor, tipos):
        """Best-effort conversion of a value to one of the schema's types."""
        if "array" in tipos and not isinstance(valor, list):
            if isinstance(valor, str):
                texto = valor.strip()
                if texto.startswith("["):
                    try:
                        carregado = json.loads(texto)
                        if isinstance(carregado, list):
                            return [v for v in carregado if v is not None]
                    except (ValueError, TypeError):
                        pass
                return [texto] if texto else []
            if valor is not None:
                return [valor]
        if "array" in tipos and isinstance(valor, list):
            return [v for v in valor if v is not None]
        if "object" in tipos and isinstance(valor, str):
            try:
                carregado = json.loads(valor)
                if isinstance(carregado, dict):
                    return carregado
            except (ValueError, TypeError):
                pass
        if "integer" in tipos and isinstance(valor, str):
            try:
                return int(valor.strip())
            except ValueError:
                pass
        if "boolean" in tipos and isinstance(valor, str):
            if valor.strip().lower() in ("true", "sim", "yes", "1"):
                return True
            if valor.strip().lower() in ("false", "nao", "no", "0"):
                return False
        if "string" in tipos and isinstance(valor, list) and len(valor) == 1:
            return str(valor[0])
        if "string" in tipos and isinstance(valor, (int, float)) and "integer" not in tipos:
            return str(valor)
        return valor

    @staticmethod
    def _tipos_do_schema(spec: dict) -> set:
        tipos = set()
        if isinstance(spec.get("type"), str):
            tipos.add(spec["type"])
        for alternativa in spec.get("anyOf") or []:
            if isinstance(alternativa, dict) and isinstance(alternativa.get("type"), str):
                tipos.add(alternativa["type"])
        return tipos

    def _sanear_argumentos(self, tool_name, tool, args):
        """Coerce arguments to the tool's own schema.

        @MX:ANCHOR Everything here is driven by inputSchema, so a tool added
        later is covered without touching this function. Returns
        (argumentos, recusa) -- recusa is a ready payload when the call cannot
        proceed, and it always says what to send instead.
        """
        schema = tool.get("inputSchema") or {}
        propriedades = schema.get("properties") or {}
        saneados = {}

        bruto_ad_server = args.get("ad_server")
        if bruto_ad_server is not None and not isinstance(bruto_ad_server, (str, list)):
            return None, {
                "sucesso": False,
                "erro": "AD_SERVER_INVALIDO",
                "mensagem": (
                    f"'ad_server' precisa ser um texto com o nome do servidor; veio "
                    f"{type(bruto_ad_server).__name__} ({bruto_ad_server!r}). "
                    "Use ad_list_ad_servers para ver os nomes."
                ),
                "tool": tool_name,
            }

        for chave, valor in args.items():
            spec = propriedades.get(chave)
            if spec is None:
                # Unknown key: keep it, the handler reads by name and ignores it.
                saneados[chave] = valor
                continue
            valor = self._coagir(valor, self._tipos_do_schema(spec))
            if chave in self._CAMPOS_DE_LOGIN and isinstance(valor, str):
                valor = self._extrair_login(valor)
            if isinstance(valor, str) and chave != "filter_criteria":
                valor = valor.strip()
            saneados[chave] = valor

        faltando = [c for c in (schema.get("required") or [])
                    if c not in saneados or saneados[c] in (None, "")]

        if "ad_server" in faltando and tool.get("write"):
            # The specific message says WHY, which the generic one cannot.
            return None, {
                "sucesso": False,
                "erro": "AD_SERVER_OBRIGATORIO_PARA_ESCRITA",
                "mensagem": (
                    f"A tool {tool_name} altera o Active Directory, entao exige um unico "
                    "servidor em 'ad_server'. 'todos' nao e aceito para escrita, e nao "
                    "existe servidor padrao."
                ),
                "servidores_disponiveis": self.pool._short_catalog() if self.pool else [],
                "tool": tool_name,
            }

        if faltando:
            return None, {
                "sucesso": False,
                "erro": "PARAMETRO_OBRIGATORIO_AUSENTE",
                "mensagem": (
                    f"A tool {tool_name} exige {', '.join(faltando)}, que nao veio na "
                    "chamada. Repita informando esse(s) parametro(s)."
                ),
                "parametros_faltando": faltando,
                "parametros_aceitos": sorted(propriedades),
                "tool": tool_name,
            }

        dias = saneados.get("days")
        if dias is not None:
            if not isinstance(dias, int):
                return None, {
                    "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
                    "mensagem": f"'days' precisa ser um numero inteiro; veio {dias!r}.",
                }
            if dias <= 0 or dias > self._LIMITE_DIAS:
                return None, {
                    "sucesso": False, "erro": "PARAMETRO_INVALIDO", "tool": tool_name,
                    "mensagem": (
                        f"'days' precisa estar entre 1 e {self._LIMITE_DIAS}; veio {dias}. "
                        "Um valor negativo ou fora dessa faixa nao descreve um periodo."
                    ),
                }
        return saneados, None

    _CAMPOS_DN = ("ou", "parent_ou", "target_parent_dn", "source_dn", "ou_dn", "target_dn")

    def _validar_dn_no_dominio(self, tool_name, args, bundle):
        """A DN from another domain is a wrong-tenant call, not a search miss.

        Without this the LDAP layer answered "invalid server address", which
        says nothing about the actual mistake.
        """
        base = bundle.config.active_directory.base_dn.lower().replace(" ", "")
        for chave in self._CAMPOS_DN:
            valor = args.get(chave)
            if not isinstance(valor, str) or not valor.strip():
                continue
            alvo = valor.lower().replace(" ", "")
            if "dc=" in alvo and not alvo.endswith(base):
                return {
                    "sucesso": False,
                    "erro": "OU_FORA_DO_DOMINIO",
                    "mensagem": (
                        f"O DN informado em '{chave}' ({valor}) nao pertence ao servidor "
                        f"'{bundle.key}', cujo dominio e {bundle.config.active_directory.base_dn}. "
                        "Ou o ad_server esta errado, ou o DN e de outro cliente."
                    ),
                    "ad_server": bundle.key,
                    "base_dn_do_servidor": bundle.config.active_directory.base_dn,
                    "tool": tool_name,
                }
        return None

    def _resolver_nome_de_tool(self, tool_name):
        """Accept the hub-prefixed name and suggest neighbours for a typo."""
        if tool_name in self.tools:
            return tool_name, None
        nome = str(tool_name or "")
        for prefixo in ("ad-multi-", "ad_multi_", "mcp__ad-multi__", "ad-multi."):
            if nome.startswith(prefixo) and nome[len(prefixo):] in self.tools:
                return nome[len(prefixo):], None
        pedaco = nome.lower().replace("-", "_")
        parecidas = [t for t in self.tools
                     if pedaco in t or any(p in t for p in pedaco.split("_") if len(p) > 4)]
        return None, {
            "sucesso": False,
            "erro": "TOOL_DESCONHECIDA",
            "mensagem": (
                f"Nao existe uma tool chamada '{tool_name}' neste servidor. "
                "Use um dos nomes exatos listados."
            ),
            "tools_parecidas": sorted(parecidas)[:8] or sorted(self.tools)[:8],
        }

    # Above this many characters the aggregated answer is replaced by a
    # per-server summary instead of being silently cut.
    _LIMITE_RESPOSTA = 120_000

    @staticmethod
    def _tem_resultado(payload) -> bool:
        """Whether a per-server payload actually found something."""
        if not isinstance(payload, dict):
            return bool(payload)
        if payload.get("success") is False or "error" in payload:
            return False
        for chave, valor in payload.items():
            if isinstance(valor, list):
                return len(valor) > 0
            if chave.startswith(("total", "count")) and isinstance(valor, int):
                return valor > 0
        return True

    async def _executar_em_todos(self, tool_name, handler, tool_args, pedido) -> dict:
        """Run a read tool against every enabled directory and merge the answers.

        @MX:ANCHOR A server that fails is listed, never dropped: an omitted
        directory reads as "nothing there", which is a different -- and false --
        statement from "could not look".
        """
        achados, vazios, falhas = {}, [], []

        for chave in self.pool.available_names():
            bundle, error = self.pool.resolve_or_error(chave)
            if error is not None:
                falhas.append({"ad_server": chave, "erro": error.get("erro"),
                               "mensagem": error.get("mensagem")})
                continue
            try:
                async with self._bind_lock:
                    with self._bound(bundle):
                        resultado = handler(dict(tool_args))
            except Exception as exc:
                falhas.append({"ad_server": chave, "erro": type(exc).__name__,
                               "mensagem": str(exc)[:200]})
                continue
            if self._tem_resultado(resultado):
                achados[chave] = resultado
            else:
                vazios.append(chave)

        consultados = len(achados) + len(vazios) + len(falhas)
        resposta = {
            "modo_de_busca": "TODOS OS SERVIDORES",
            "tool": tool_name,
            "servidores_consultados": consultados,
            "encontrado_em": sorted(achados),
            "sem_resultado_em": sorted(vazios),
            "resultados_por_servidor": achados,
        }
        if falhas:
            resposta["servidores_com_falha"] = falhas
            resposta["aviso"] = (
                f"{len(falhas)} de {consultados} servidores nao responderam. O que eles "
                "tem NAO foi verificado: 'sem resultado' vale apenas para "
                f"{len(vazios) + len(achados)} servidores."
            )
        if not pedido:
            resposta["nota"] = (
                "'ad_server' nao foi informado, entao a busca rodou em todos os ADs. "
                "Para consultar um so, informe o nome do servidor."
            )
        resposta["resumo"] = (
            f"Encontrado em {len(achados)} de {consultados} servidores"
            + (f": {', '.join(sorted(achados))}." if achados else ".")
        )

        tamanho = len(json.dumps(resposta, ensure_ascii=False, default=str))
        if tamanho > self._LIMITE_RESPOSTA:
            resumo_por_servidor = {}
            for chave, payload in achados.items():
                if isinstance(payload, dict):
                    resumo_por_servidor[chave] = {
                        k: (len(v) if isinstance(v, list) else v)
                        for k, v in payload.items()
                        if isinstance(v, (int, str, bool)) or isinstance(v, list)
                    }
                else:
                    resumo_por_servidor[chave] = "resultado nao estruturado"
            resposta["resultados_por_servidor"] = resumo_por_servidor
            resposta["RESPOSTA_CONDENSADA"] = (
                f"A resposta completa teria {tamanho} caracteres, acima do limite. "
                "Cada servidor aparece apenas com suas contagens. Para ver os registros, "
                "repita a chamada informando um 'ad_server' especifico, ou restrinja a "
                "busca com filtros."
            )
        return resposta

    async def handle_tools_call(self, params: dict) -> dict:
        """Handle tools/call method.

        In multi-AD mode this is the single place where a call is routed to a
        directory. Routing lives here and nowhere else, so a tool cannot reach
        an LDAP connection without having named its server first.
        """
        tool_name = params.get("name")
        bruto = params.get("arguments")
        if isinstance(bruto, str):
            # Some clients send the arguments object as a JSON string.
            try:
                bruto = json.loads(bruto)
            except (ValueError, TypeError):
                bruto = {}
        tool_args = dict(bruto or {})

        resolvido, recusa = self._resolver_nome_de_tool(tool_name)
        if recusa is not None:
            self.logger.warning("tools/call com nome desconhecido: %r", tool_name)
            return self._as_content(recusa)
        tool_name = resolvido

        tool = self.tools[tool_name]
        handler = tool["handler"]

        tool_args, recusa = self._sanear_argumentos(tool_name, tool, tool_args)
        if recusa is not None:
            self.logger.warning("tools/call recusada em %s: %s", tool_name, recusa["erro"])
            return self._as_content(recusa)

        if self.multi and not tool.get("global"):
            requested = tool_args.pop("ad_server", None)
            pedido = str(requested).strip().lower() if requested is not None else ""

            if pedido in self._TODOS or pedido == "":
                if tool.get("write"):
                    # Never fan a write out, and never guess which directory it
                    # meant: both would edit the wrong customer's AD.
                    return self._as_content({
                        "sucesso": False,
                        "erro": "AD_SERVER_OBRIGATORIO_PARA_ESCRITA",
                        "mensagem": (
                            f"A tool {tool_name} altera o Active Directory, entao exige um "
                            "unico servidor em 'ad_server'. 'todos' nao e aceito para "
                            "escrita, e nao existe servidor padrao."
                        ),
                        "servidores_disponiveis": self.pool._short_catalog(),
                        "tool": tool_name,
                    })
                self.logger.info("tools/call %s -> ad_server=TODOS", tool_name)
                return self._as_content(
                    await self._executar_em_todos(tool_name, handler, tool_args, pedido))

            bundle, error = self.pool.resolve_or_error(requested)
            if error is not None:
                error["tool"] = tool_name
                self.logger.warning(
                    "Chamada recusada em %s: %s (ad_server=%r)",
                    tool_name, error["erro"], requested,
                )
                return self._as_content(error)

            # @MX:WARN The tenant is bound onto self for the duration of the
            # handler. The lock keeps exactly one tenant bound at a time; drop it
            # and a future async handler could observe another customer's AD.
            recusa = self._validar_dn_no_dominio(tool_name, tool_args, bundle)
            if recusa is not None:
                return self._as_content(recusa)

            async with self._bind_lock:
                with self._bound(bundle):
                    self.logger.info("tools/call %s -> ad_server=%s", tool_name, bundle.key)
                    result = handler(tool_args)
        else:
            result = handler(tool_args)

        return self._as_content(result)

    async def handle_prompts_list(self, params: dict) -> dict:
        """Handle prompts/list method."""
        return {"prompts": PROMPTS_CATALOG}

    async def handle_prompts_get(self, params: dict) -> dict:
        """Handle prompts/get method."""
        prompt_name = params.get("name")
        prompt_args = params.get("arguments", {})

        if not prompt_name:
            raise ValueError("Prompt name is required")

        # Verificar se prompt existe
        prompt = next((p for p in PROMPTS_CATALOG if p["name"] == prompt_name), None)
        if not prompt:
            raise ValueError(f"Prompt não encontrado: {prompt_name}")

        # Chamar handler de prompts com o ldap_manager
        ldap_manager = self.ldap_manager
        if self.multi and self.pool is not None:
            bundle, error = self.pool.resolve_or_error(prompt_args.get("ad_server"))
            if error is not None:
                raise ValueError(error["mensagem"])
            ldap_manager = bundle.ldap_manager
            prompt_args = {k: v for k, v in prompt_args.items() if k != "ad_server"}

        result = await handle_get_prompt(prompt_name, prompt_args, ldap_manager)
        return result

    async def handle_request(self, request_data: dict) -> dict:
        """Handle MCP JSON-RPC request."""
        method = request_data.get("method", "")
        params = request_data.get("params", {})
        request_id = request_data.get("id")

        try:
            if method == "initialize":
                result = await self.handle_initialize(params)
            elif method == "tools/list":
                result = await self.handle_tools_list(params)
            elif method == "tools/call":
                result = await self.handle_tools_call(params)
            elif method == "prompts/list":
                result = await self.handle_prompts_list(params)
            elif method == "prompts/get":
                result = await self.handle_prompts_get(params)
            elif method == "notifications/initialized":
                return {"jsonrpc": "2.0", "result": {}, "id": request_id}
            else:
                raise ValueError(f"Unknown method: {method}")

            return {"jsonrpc": "2.0", "result": result, "id": request_id}

        except Exception as e:
            self.logger.error(f"Error handling {method}: {e}")
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": str(e)},
                "id": request_id
            }

    # ============= FASTAPI APP CREATION =============

    def _create_app(self) -> FastAPI:
        """Create FastAPI application with Streamable HTTP endpoints."""

        server = self

        @asynccontextmanager
        async def lifespan(app: FastAPI):
            server.logger.info(f"Starting AD MCP on port {server.port}")
            yield
            server.logger.info("Shutting down AD MCP")
            server._shutdown_connections()

        app = FastAPI(
            title="MCP Active Directory Server",
            description="MCP server for Active Directory with Streamable HTTP support",
            version="1.0.0",
            lifespan=lifespan
        )

        # Health check (no auth required)
        @app.get("/health")
        async def health_check():
            return server._handle_health({})

        # ============= STREAMABLE HTTP ENDPOINTS =============

        # GET /mcp - SSE endpoint for Gemini
        @app.get("/mcp")
        async def mcp_sse_endpoint(
            request: Request,
            token: str = Depends(verify_bearer_token)
        ):
            session_id = request.headers.get("mcp-session-id") or str(uuid.uuid4())
            server.logger.info(f"SSE connection opened: {session_id}")

            mcp_sessions[session_id] = {"created_at": datetime.now(timezone.utc), "active": True}

            async def event_generator():
                try:
                    yield f"event: endpoint\ndata: /mcp\n\n"
                    while True:
                        if await request.is_disconnected():
                            break
                        if session_id not in mcp_sessions:
                            break
                        yield ":keepalive\n\n"
                        await asyncio.sleep(30)
                except asyncio.CancelledError:
                    pass
                finally:
                    if session_id in mcp_sessions:
                        del mcp_sessions[session_id]
                    server.logger.info(f"SSE connection closed: {session_id}")

            return StreamingResponse(
                event_generator(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "Mcp-Session-Id": session_id
                }
            )

        # DELETE /mcp - Session termination
        @app.delete("/mcp")
        async def mcp_session_terminate(
            request: Request,
            token: str = Depends(verify_bearer_token)
        ):
            session_id = request.headers.get("mcp-session-id")
            if session_id and session_id in mcp_sessions:
                del mcp_sessions[session_id]
                server.logger.info(f"Session terminated: {session_id}")
            return {"status": "session_terminated", "session_id": session_id}

        # POST /mcp - JSON-RPC handler
        @app.post("/mcp")
        async def mcp_handler_http(
            request: Request,
            mcp_request: MCPRequest,
            token: str = Depends(verify_bearer_token)
        ):
            session_id = request.headers.get("mcp-session-id") or str(uuid.uuid4())

            server.logger.info(f"MCP request: method={mcp_request.method}")

            response = await server.handle_request(mcp_request.model_dump())

            return JSONResponse(
                content=response,
                headers={"Mcp-Session-Id": session_id}
            )

        return app

    def _shutdown_connections(self) -> None:
        """Close every LDAP connection this process opened."""
        if self.multi and self.pool is not None:
            self.pool.disconnect_all()
        elif self.ldap_manager is not None:
            self.ldap_manager.disconnect()

    def run(self):
        """Start the server."""
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info"
        )


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Active Directory MCP FastAPI Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8820, help='Port (default: 8820)')
    parser.add_argument('--config', help='Config file path (single-AD mode)')
    parser.add_argument('--servers', help='Multi-AD servers file (multi-AD mode)')
    parser.add_argument('--mode', choices=['single', 'multi'],
                        help='single (default) or multi. Overrides AD_MCP_MODE.')

    args = parser.parse_args()

    mode = (args.mode or os.getenv("AD_MCP_MODE") or "single").strip().lower()
    config_path = args.config or os.getenv("AD_MCP_CONFIG")
    servers_path = args.servers or os.getenv("AD_MCP_SERVERS")

    if mode == "multi":
        if not servers_path:
            print("Error: modo multi exige AD_MCP_SERVERS (ou --servers)")
            sys.exit(1)
    elif not config_path:
        print("Error: AD_MCP_CONFIG not set")
        sys.exit(1)

    try:
        server = ActiveDirectoryMCPFastAPI(
            config_path=config_path,
            host=args.host,
            port=args.port,
            servers_path=servers_path,
            mode=mode,
        )
    except MultiConfigError as exc:
        print(f"Error: configuracao multi-AD invalida: {exc}")
        sys.exit(1)

    server.run()


if __name__ == "__main__":
    main()
