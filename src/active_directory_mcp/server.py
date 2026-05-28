"""
Main server implementation for Active Directory MCP.

This module implements the core MCP server for Active Directory integration, providing:
- Configuration loading and validation
- Logging setup
- LDAP connection management
- MCP tool registration and routing
- Signal handling for graceful shutdown
- Client identification and security (Multi-tenant support)

The server exposes a comprehensive set of tools for managing Active Directory resources including:
- User management (create, modify, delete, enable/disable, password reset)
- Group management (create, modify, delete, membership management)
- Computer management (create, modify, delete, enable/disable)
- Organizational Unit management (create, modify, delete, move)
- Security operations (audit, permissions analysis, policy compliance)
- Client identification (ad_get_client_tenant_info for multi-tenant environments)

"""

import logging
import json
import os
import sys
import signal
from typing import Optional, List, Annotated

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.tools import Tool
from mcp.types import TextContent as Content
from pydantic import Field

from .config.loader import load_config, validate_config
from .core.logging import setup_logging
from .core.ldap_manager import LDAPManager
from .core.client_security import ClientSecurityManager, init_security_manager, get_security_manager
from .tools.user import UserTools
from .tools.group import GroupTools
from .tools.computer import ComputerTools
from .tools.organizational_unit import OrganizationalUnitTools
from .tools.security import SecurityTools


class ActiveDirectoryMCPServer:
    """Main server class for Active Directory MCP."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the server.

        Args:
            config_path: Path to configuration file
        """
        # Store config path for client security
        self.config_path = config_path

        # Load and validate configuration
        self.config = load_config(config_path)
        validate_config(self.config)

        # Setup logging
        self.logger = setup_logging(self.config.logging)

        # Initialize client security manager (for multi-tenant support)
        self._init_client_security()

        # Initialize LDAP manager
        self.ldap_manager = LDAPManager(
            self.config.active_directory,
            self.config.security,
            self.config.performance
        )

        # Test connection on startup
        self._test_initial_connection()

        # Initialize tools
        self.user_tools = UserTools(self.ldap_manager)
        self.group_tools = GroupTools(self.ldap_manager)
        self.computer_tools = ComputerTools(self.ldap_manager)
        self.ou_tools = OrganizationalUnitTools(self.ldap_manager)
        self.security_tools = SecurityTools(self.ldap_manager)

        # Initialize MCP server
        self.mcp = FastMCP("ActiveDirectoryMCP")
        self._tests_passed: Optional[bool] = None
        self._setup_tools()

    def _init_client_security(self) -> None:
        """Initialize client security manager for multi-tenant support."""
        try:
            # Load raw config as dict for security manager
            if self.config_path and os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config_dict = json.load(f)
            else:
                config_dict = {}

            self.security_manager = init_security_manager(config_dict, self.config_path)
            self.logger.info(f"Client security initialized: {self.security_manager.client_name}")
        except Exception as e:
            self.logger.warning(f"Could not initialize client security: {e}")
            self.security_manager = None

    def _test_initial_connection(self) -> None:
        """Test initial LDAP connection."""
        try:
            self.logger.info("Testing initial LDAP connection...")
            connection_info = self.ldap_manager.test_connection()

            if connection_info.get('connected'):
                self.logger.info(f"Successfully connected to {connection_info.get('server')}:{connection_info.get('port')}")
                if connection_info.get('search_test'):
                    self.logger.info("LDAP search test passed")
                else:
                    self.logger.warning("LDAP search test failed")
            else:
                self.logger.error(f"Initial connection failed: {connection_info.get('error')}")

        except Exception as e:
            self.logger.error(f"Connection test error: {e}")

    def _check_write_permission(
        self,
        operation: str,
        target: str,
        automation_token: Optional[str] = None,
        client_confirmation: Optional[str] = None
    ) -> dict:
        """
        Check if write operation is permitted.

        Returns dict with 'permitted' boolean and 'message'.
        """
        if not self.security_manager:
            return {"permitted": True, "mode": "no_security", "message": "Security manager not initialized"}

        return self.security_manager.check_write_permission(
            operation, target, automation_token, client_confirmation
        )

    def _setup_tools(self) -> None:
        """
        Register MCP tools with the server.

        Initializes and registers all available tools with the MCP server:
        - Client identification tool (ad_get_client_tenant_info)
        - User management tools
        - Group management tools
        - Computer management tools
        - Organizational Unit tools
        - Security and audit tools

        Each tool is registered with appropriate descriptions and parameter
        validation using Pydantic models.
        """

        # =====================================================================
        # CLIENT IDENTIFICATION TOOL (Multi-tenant support)
        # =====================================================================

        @self.mcp.tool(description="Identificação de cliente e tenant no Active Directory — consulta informações do tenant, domínio e configuração desta instância AD. Use quando precisar confirmar qual cliente AD está conectado antes de operações destrutivas no Active Directory. Retorna nome do cliente, slug, domínio, base DN e configuração multi-tenant. Operação somente leitura.")
        def ad_get_client_tenant_info():
            """
            Returns information about the client/tenant this MCP instance is connected to.

            IMPORTANT: Always call this tool before performing write operations to confirm
            you are operating on the correct client's Active Directory.
            """
            if self.security_manager:
                info = self.security_manager.get_client_info()
            else:
                info = {
                    "client": {
                        "name": "Unknown",
                        "slug": "unknown",
                        "type": "unknown"
                    },
                    "domain": {
                        "name": self.config.active_directory.domain,
                        "base_dn": self.config.active_directory.base_dn
                    },
                    "warning": "⚠️ Security manager not initialized - client identification unavailable"
                }
            return [Content(type="text", text=json.dumps(info, indent=2, ensure_ascii=False))]

        # =====================================================================
        # USER MANAGEMENT TOOLS
        # =====================================================================

        @self.mcp.tool(description="Usuários e contas de domínio no Active Directory — lista todos os users, colaboradores, funcionários e membros do AD com filtros opcionais por OU ou atributos. Use quando precisar listar usuários por departamento, status ou atributos customizados no Active Directory. Retorna coleção de usuários com status de conta, grupos, email e atributos LDAP. Consulta somente leitura.")
        def ad_list_users_with_filters(
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to search in", default=None)] = None,
            filter_criteria: Annotated[Optional[str], Field(description="Additional LDAP filter criteria", default=None)] = None,
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.user_tools.list_users(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Usuário específico, conta ou colaborador no Active Directory — busca detalhes completos de um user por username (sAMAccountName) incluindo perfil, grupos, permissões e status no AD. Use quando precisar informações detalhadas de uma conta específica no Active Directory. Retorna atributos completos: email, telefone, departamento, grupos, última autenticação e configurações de senha. Consulta somente leitura.")
        def ad_get_user_details_by_username(
            username: Annotated[str, Field(description="Username (sAMAccountName) to search for")],
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.user_tools.get_user(username, attributes)

        @self.mcp.tool(description="Criação de usuário, conta ou colaborador no Active Directory — cria novo user no AD com atributos obrigatórios e opcionais, senha inicial e OU de destino. Use quando precisar onboarding de funcionários, criação de contas de serviço ou provisionamento de novos colaboradores no Active Directory. Retorna DN do usuário criado, UPN e confirmação. Operação write - confirme cliente primeiro.")
        def ad_create_user_account(
            username: Annotated[str, Field(description="Username (sAMAccountName)")],
            password: Annotated[str, Field(description="User password")],
            first_name: Annotated[str, Field(description="User's first name")],
            last_name: Annotated[str, Field(description="User's last name")],
            email: Annotated[Optional[str], Field(description="User's email address", default=None)] = None,
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to create user in", default=None)] = None,
            additional_attributes: Annotated[Optional[dict], Field(description="Additional attributes to set", default=None)] = None,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations (skips confirmation)", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation for manual operations", default=None)] = None
        ):
            # Check write permission
            perm = self._check_write_permission("ad_create_user_account", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.create_user(username, password, first_name, last_name, email, ou, additional_attributes)

        @self.mcp.tool(description="Atualização de atributos de usuário ou colaborador no Active Directory — modifica propriedades existentes de uma conta AD incluindo email, telefone, departamento, cargo e campos customizados. Use quando precisar alterar dados de perfil, atualizar informações organizacionais ou modificar atributos LDAP no Active Directory. Retorna confirmação e lista de atributos modificados. Operação write - confirme cliente primeiro.")
        def ad_modify_user_attributes(
            username: Annotated[str, Field(description="Username to modify")],
            attributes: Annotated[dict, Field(description="Dictionary of attributes to modify")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_modify_user_attributes", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.modify_user(username, attributes)

        @self.mcp.tool(description="Exclusão permanente de usuário ou conta no Active Directory — remove completamente um user do AD incluindo todos os atributos, grupos e referências. Use quando precisar offboarding de funcionários desligados, limpeza de contas obsoletas ou remoção definitiva no Active Directory. Retorna confirmação de exclusão. Operação write irreversível - confirme cliente primeiro antes de executar.")
        def ad_delete_user_account_permanently(
            username: Annotated[str, Field(description="Username to delete")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_delete_user_account_permanently", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.delete_user(username)

        @self.mcp.tool(description="Habilitação de conta de usuário ou colaborador no Active Directory — ativa account desabilitada modificando userAccountControl para permitir autenticação e acesso aos recursos do domínio AD. Use quando precisar reativar contas suspensas, liberar acesso após licença ou habilitar usuários bloqueados no Active Directory. Retorna status de habilitação. Operação write.")
        def ad_enable_user_account_access(
            username: Annotated[str, Field(description="Username to enable")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_enable_user_account_access", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.enable_user(username)

        @self.mcp.tool(description="Desabilitação de conta de usuário ou colaborador no Active Directory — desativa account modificando userAccountControl para bloquear autenticação preservando dados e histórico do user no AD. Use quando precisar suspender acesso temporário, bloquear contas comprometidas ou desativar usuários em licença no Active Directory. Retorna status de desabilitação. Operação write.")
        def ad_disable_user_account_access(
            username: Annotated[str, Field(description="Username to disable")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_disable_user_account_access", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.disable_user(username)

        @self.mcp.tool(description="Redefinição de senha de usuário ou colaborador no Active Directory — redefine password com geração automática ou valor customizado, força troca no próximo logon e configura políticas de expiração no AD. Use quando precisar resetar senhas esquecidas, resolver bloqueios de conta ou aplicar políticas de segurança no Active Directory. Retorna nova senha e confirmação. Operação write.")
        def ad_reset_user_password_forced(
            username: Annotated[str, Field(description="Username to reset password for")],
            new_password: Annotated[Optional[str], Field(description="New password (auto-generated if not provided)", default=None)] = None,
            force_change: Annotated[bool, Field(description="Force user to change password at next logon", default=True)] = True,
            password_never_expires: Annotated[bool, Field(description="Set password to never expire", default=False)] = False,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_reset_user_password_forced", username, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.user_tools.reset_password(username, new_password, force_change, password_never_expires)

        @self.mcp.tool(description="Grupos e memberships de usuário no Active Directory — lista todos os security groups, distribution groups e nested groups dos quais um user é membro direto ou indireto no AD. Use quando precisar auditar permissões, verificar acessos ou analisar memberships de colaboradores no Active Directory. Retorna lista de grupos com tipo, escopo e descrição. Consulta somente leitura.")
        def ad_get_user_group_memberships(
            username: Annotated[str, Field(description="Username to get groups for")]
        ):
            return self.user_tools.get_user_groups(username)

        # =====================================================================
        # GROUP MANAGEMENT TOOLS
        # =====================================================================

        @self.mcp.tool(description="Grupos de segurança e distribuição no Active Directory — lista todos os security groups, distribution groups e grupos de email do AD com filtros opcionais por OU ou tipo. Use quando precisar listar grupos por escopo, tipo ou atributos customizados no Active Directory. Retorna coleção de grupos com escopo, tipo, membros e descrição. Consulta somente leitura do AD.")
        def ad_list_groups_with_filters(
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to search in", default=None)] = None,
            filter_criteria: Annotated[Optional[str], Field(description="Additional LDAP filter criteria", default=None)] = None,
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.group_tools.list_groups(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Grupo específico de segurança ou distribuição no Active Directory — busca detalhes completos de um group por nome incluindo members, escopo, tipo e descrição no AD. Use quando precisar informações detalhadas sobre um grupo específico no Active Directory. Retorna atributos completos: membros, tipo de grupo, escopo, descrição e propriedades. Consulta somente leitura.")
        def ad_get_group_details_by_name(
            group_name: Annotated[str, Field(description="Group name (sAMAccountName) to search for")],
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.group_tools.get_group(group_name, attributes)

        @self.mcp.tool(description="Criação de grupo de segurança ou distribuição no Active Directory — cria novo security group ou distribution group no AD com escopo Global, DomainLocal ou Universal e atributos opcionais. Use quando precisar criar grupos de permissões, grupos de email ou grupos organizacionais no Active Directory. Retorna DN do grupo criado, escopo, tipo e confirmação. Operação write - confirme cliente.")
        def ad_create_group_security_or_distribution(
            group_name: Annotated[str, Field(description="Group name (sAMAccountName)")],
            display_name: Annotated[Optional[str], Field(description="Display name for the group", default=None)] = None,
            description: Annotated[Optional[str], Field(description="Group description", default=None)] = None,
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to create group in", default=None)] = None,
            group_scope: Annotated[str, Field(description="Group scope (Global, DomainLocal, Universal)", default="Global")] = "Global",
            group_type: Annotated[str, Field(description="Group type (Security, Distribution)", default="Security")] = "Security",
            additional_attributes: Annotated[Optional[dict], Field(description="Additional attributes to set", default=None)] = None,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_create_group_security_or_distribution", group_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.group_tools.create_group(group_name, display_name, description, ou, group_scope, group_type, additional_attributes)

        @self.mcp.tool(description="Atualização de atributos de grupo no Active Directory — modifica propriedades existentes de um security group ou distribution group no AD incluindo descrição, email, managed by e campos customizados. Use quando precisar alterar configurações de grupos, atualizar responsáveis ou modificar atributos LDAP no Active Directory. Retorna confirmação e lista de atributos modificados. Operação write - confirme cliente.")
        def ad_modify_group_attributes(
            group_name: Annotated[str, Field(description="Group name to modify")],
            attributes: Annotated[dict, Field(description="Dictionary of attributes to modify")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_modify_group_attributes", group_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.group_tools.modify_group(group_name, attributes)

        @self.mcp.tool(description="Exclusão permanente de grupo no Active Directory — remove completamente um security group ou distribution group do AD incluindo todas as associações e referências de membros. Use quando precisar limpeza de grupos obsoletos, remoção de grupos temporários ou exclusão definitiva no Active Directory. Retorna confirmação de exclusão. Operação write irreversível - confirme cliente primeiro antes de executar.")
        def ad_delete_group_permanently(
            group_name: Annotated[str, Field(description="Group name to delete")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_delete_group_permanently", group_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.group_tools.delete_group(group_name)

        @self.mcp.tool(description="Adição de membro a grupo no Active Directory — adiciona user, computer ou nested group a um grupo de segurança ou distribuição no AD. Use quando precisar conceder permissões, adicionar usuários a grupos ou criar hierarquia de grupos no Active Directory. Retorna confirmação de adição e lista atualizada de membros. Operação write.")
        def ad_add_member_to_group(
            group_name: Annotated[str, Field(description="Group name to add member to")],
            member_dn: Annotated[str, Field(description="Distinguished name of member to add")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_add_member_to_group", f"{group_name}:{member_dn}", automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.group_tools.add_member(group_name, member_dn)

        @self.mcp.tool(description="Remoção de membro de grupo no Active Directory — remove user, computer ou nested group de um grupo de segurança ou distribuição no AD. Use quando precisar revogar permissões, remover usuários desligados ou reorganizar hierarquia de grupos no Active Directory. Retorna confirmação de remoção e lista atualizada de membros. Operação write.")
        def ad_remove_member_from_group(
            group_name: Annotated[str, Field(description="Group name to remove member from")],
            member_dn: Annotated[str, Field(description="Distinguished name of member to remove")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_remove_member_from_group", f"{group_name}:{member_dn}", automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.group_tools.remove_member(group_name, member_dn)

        @self.mcp.tool(description="Membros de grupo com recursão no Active Directory — lista todos os members de um group incluindo nested groups expandidos recursivamente no AD. Use quando precisar auditar permissões efetivas, verificar hierarquia completa ou analisar memberships indiretos no Active Directory. Retorna lista completa de membros diretos e indiretos com tipo. Consulta somente leitura.")
        def ad_get_group_members_recursive(
            group_name: Annotated[str, Field(description="Group name to get members for")],
            recursive: Annotated[bool, Field(description="Include members of nested groups", default=False)] = False
        ):
            return self.group_tools.get_members(group_name, recursive)

        # =====================================================================
        # COMPUTER MANAGEMENT TOOLS
        # =====================================================================

        @self.mcp.tool(description="Computadores e workstations no Active Directory — lista todos os computer accounts, estações de trabalho e servidores do AD com filtros opcionais por OU ou sistema operacional. Use quando precisar inventariar máquinas, auditar computer accounts ou buscar por tipo de OS no Active Directory. Retorna coleção de computers com OS, último logon, status e atributos. Consulta somente leitura do AD.")
        def ad_list_computers_with_filters(
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to search in", default=None)] = None,
            filter_criteria: Annotated[Optional[str], Field(description="Additional LDAP filter criteria", default=None)] = None,
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.computer_tools.list_computers(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Computador específico ou workstation no Active Directory — busca detalhes completos de um computer por nome incluindo sistema operacional, última autenticação e grupos no AD. Use quando precisar informações detalhadas sobre uma máquina específica no Active Directory. Retorna atributos completos: OS, versão, último logon, grupos e status de trust. Consulta somente leitura.")
        def ad_get_computer_details_by_name(
            computer_name: Annotated[str, Field(description="Computer name (sAMAccountName) to search for")],
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.computer_tools.get_computer(computer_name, attributes)

        @self.mcp.tool(description="Criação de conta de computador ou workstation no Active Directory — cria novo computer account no AD com DNS hostname, service principal names e OU de destino. Use quando precisar pré-criar contas de máquinas, provisionamento de workstations ou criação de computer objects no Active Directory. Retorna DN do computer criado, DNS hostname e SPNs. Operação write - confirme cliente.")
        def ad_create_computer_account(
            computer_name: Annotated[str, Field(description="Computer name (without $ suffix)")],
            description: Annotated[Optional[str], Field(description="Computer description", default=None)] = None,
            ou: Annotated[Optional[str], Field(description="Organizational Unit DN to create computer in", default=None)] = None,
            dns_hostname: Annotated[Optional[str], Field(description="DNS hostname", default=None)] = None,
            additional_attributes: Annotated[Optional[dict], Field(description="Additional attributes to set", default=None)] = None,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_create_computer_account", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.create_computer(computer_name, description, ou, dns_hostname, additional_attributes)

        @self.mcp.tool(description="Atualização de atributos de computador no Active Directory — modifica propriedades existentes de um computer account no AD incluindo descrição, localização, managed by e campos customizados. Use quando precisar alterar configurações de máquinas, atualizar informações de inventário ou modificar atributos LDAP no Active Directory. Retorna confirmação e lista de atributos modificados. Operação write - confirme cliente.")
        def ad_modify_computer_attributes(
            computer_name: Annotated[str, Field(description="Computer name to modify")],
            attributes: Annotated[dict, Field(description="Dictionary of attributes to modify")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_modify_computer_attributes", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.modify_computer(computer_name, attributes)

        @self.mcp.tool(description="Exclusão permanente de conta de computador no Active Directory — remove completamente um computer account do AD incluindo todas as associações, SPNs e referências. Use quando precisar descomissionamento de máquinas, limpeza de computer accounts obsoletos ou remoção definitiva no Active Directory. Retorna confirmação de exclusão. Operação write irreversível - confirme cliente primeiro antes de executar.")
        def ad_delete_computer_account_permanently(
            computer_name: Annotated[str, Field(description="Computer name to delete")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_delete_computer_account_permanently", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.delete_computer(computer_name)

        @self.mcp.tool(description="Habilitação de conta de computador no Active Directory — ativa computer account desabilitada modificando userAccountControl para restaurar trust relationship no AD. Use quando precisar reativar máquinas suspensas, restaurar trust quebrado ou habilitar computadores bloqueados no Active Directory. Retorna status de habilitação. Operação write.")
        def ad_enable_computer_account_trust(
            computer_name: Annotated[str, Field(description="Computer name to enable")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_enable_computer_account_trust", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.enable_computer(computer_name)

        @self.mcp.tool(description="Desabilitação de conta de computador no Active Directory — desativa computer account modificando userAccountControl para remover trust relationship preservando dados no AD. Use quando precisar desativar máquinas obsoletas, quebrar trust ou bloquear computadores comprometidos no Active Directory. Retorna status de desabilitação. Operação write.")
        def ad_disable_computer_account_trust(
            computer_name: Annotated[str, Field(description="Computer name to disable")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_disable_computer_account_trust", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.disable_computer(computer_name)

        @self.mcp.tool(description="Redefinição de senha de conta de computador no Active Directory — redefine password e restaura trust relationship entre computer e domain controller no AD. Use quando precisar resolver problemas de trust quebrado ou resetar credenciais de máquina no Active Directory. Retorna confirmação e nova senha de trust. Operação write.")
        def ad_reset_computer_password_trust(
            computer_name: Annotated[str, Field(description="Computer name to reset password for")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_reset_computer_password_trust", computer_name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.computer_tools.reset_computer_password(computer_name)

        @self.mcp.tool(description="Computadores inativos ou obsoletos no Active Directory — identifica computer accounts que não autenticaram no AD por número de dias especificado, indicando máquinas desconectadas ou obsoletas. Use quando precisar auditar inventário, identificar workstations abandonadas ou realizar limpeza de computer accounts no Active Directory. Retorna lista de computers com dias de inatividade, último logon e status. Consulta somente leitura.")
        def ad_get_inactive_computers_by_days(
            days: Annotated[int, Field(description="Number of days to consider stale", default=90)] = 90
        ):
            return self.computer_tools.get_stale_computers(days)

        # =====================================================================
        # ORGANIZATIONAL UNIT TOOLS
        # =====================================================================

        @self.mcp.tool(description="Unidades organizacionais e estrutura hierárquica no Active Directory — lista todas as OUs (organizational units), containers e estrutura de organização do AD com opção de busca recursiva. Use quando precisar mapear hierarquia organizacional, listar OUs por nível ou auditar estrutura de containers no Active Directory. Retorna coleção de OUs com nível hierárquico, parent OU e GPOs vinculados. Consulta somente leitura.")
        def ad_list_organizational_units_hierarchy(
            parent_ou: Annotated[Optional[str], Field(description="Parent OU DN to search in", default=None)] = None,
            filter_criteria: Annotated[Optional[str], Field(description="Additional LDAP filter criteria", default=None)] = None,
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None,
            recursive: Annotated[bool, Field(description="Search recursively in sub-OUs", default=True)] = True
        ):
            return self.ou_tools.list_ous(parent_ou, filter_criteria, attributes, recursive)

        @self.mcp.tool(description="Unidade organizacional específica no Active Directory — busca detalhes completos de uma OU por distinguished name incluindo políticas, objetos contidos e hierarquia no AD. Use quando precisar informações detalhadas sobre uma OU específica no Active Directory. Retorna atributos completos: GPOs aplicadas, objetos contidos e configurações. Consulta somente leitura.")
        def ad_get_organizational_unit_details(
            ou_dn: Annotated[str, Field(description="Distinguished name of the OU")],
            attributes: Annotated[Optional[List[str]], Field(description="Specific attributes to retrieve", default=None)] = None
        ):
            return self.ou_tools.get_ou(ou_dn, attributes)

        @self.mcp.tool(description="Criação de unidade organizacional no Active Directory — cria nova OU (organizational unit) no AD com parent OU, descrição, managed by e atributos opcionais. Use quando precisar estruturar hierarquia organizacional, criar containers para segregação ou organizar objetos por departamento no Active Directory. Retorna DN da OU criada, parent OU e confirmação. Operação write - confirme cliente primeiro.")
        def ad_create_organizational_unit(
            name: Annotated[str, Field(description="Name of the OU")],
            parent_ou: Annotated[Optional[str], Field(description="Parent OU DN", default=None)] = None,
            description: Annotated[Optional[str], Field(description="OU description", default=None)] = None,
            managed_by: Annotated[Optional[str], Field(description="DN of user/group managing this OU", default=None)] = None,
            additional_attributes: Annotated[Optional[dict], Field(description="Additional attributes to set", default=None)] = None,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_create_organizational_unit", name, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.ou_tools.create_ou(name, parent_ou, description, managed_by, additional_attributes)

        @self.mcp.tool(description="Atualização de atributos de unidade organizacional no Active Directory — modifica propriedades existentes de uma OU (organizational unit) no AD incluindo descrição, managed by, location e campos customizados. Use quando precisar alterar configurações de OUs, atualizar responsáveis ou modificar atributos LDAP no Active Directory. Retorna confirmação e lista de atributos modificados. Operação write - confirme cliente.")
        def ad_modify_organizational_unit_attributes(
            ou_dn: Annotated[str, Field(description="OU distinguished name to modify")],
            attributes: Annotated[dict, Field(description="Dictionary of attributes to modify")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_modify_organizational_unit_attributes", ou_dn, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.ou_tools.modify_ou(ou_dn, attributes)

        @self.mcp.tool(description="Exclusão de unidade organizacional no Active Directory — remove OU (organizational unit) do AD com opção de exclusão forçada incluindo todos os objetos contidos. Use quando precisar reestruturar hierarquia, remover OUs obsoletas ou executar limpeza de containers no Active Directory. Retorna confirmação de exclusão e contagem de objetos removidos. Operação write irreversível - confirme cliente primeiro.")
        def ad_delete_organizational_unit_forced(
            ou_dn: Annotated[str, Field(description="OU distinguished name to delete")],
            force: Annotated[bool, Field(description="Force deletion even if OU contains objects", default=False)] = False,
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_delete_organizational_unit_forced", ou_dn, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.ou_tools.delete_ou(ou_dn, force)

        @self.mcp.tool(description="Movimentação de unidade organizacional no Active Directory — move OU (organizational unit) para novo parent container no AD preservando todos os objetos contidos e GPO links. Use quando precisar reestruturar hierarquia organizacional, reorganizar containers ou mover OUs entre níveis no Active Directory. Retorna novo DN, novo parent OU e confirmação. Operação write - confirme cliente primeiro antes de executar.")
        def ad_move_organizational_unit_parent(
            ou_dn: Annotated[str, Field(description="OU distinguished name to move")],
            new_parent_dn: Annotated[str, Field(description="New parent OU distinguished name")],
            automation_token: Annotated[Optional[str], Field(description="Automation token for unattended operations", default=None)] = None,
            client_confirmation: Annotated[Optional[str], Field(description="Client name confirmation", default=None)] = None
        ):
            perm = self._check_write_permission("ad_move_organizational_unit_parent", ou_dn, automation_token, client_confirmation)
            if not perm.get("permitted"):
                return [Content(type="text", text=json.dumps(perm, indent=2, ensure_ascii=False))]

            return self.ou_tools.move_ou(ou_dn, new_parent_dn)

        @self.mcp.tool(description="Conteúdo de unidade organizacional no Active Directory — lista todos os objetos (users, groups, computers, nested OUs) contidos em uma OU específica no AD. Use quando precisar auditar conteúdo de OU, verificar hierarquia ou listar objetos organizados no Active Directory. Retorna lista completa de objetos com tipo e atributos básicos. Consulta somente leitura.")
        def ad_get_organizational_unit_objects(
            ou_dn: Annotated[str, Field(description="OU distinguished name")],
            object_types: Annotated[Optional[List[str]], Field(description="Types of objects to include", default=None)] = None
        ):
            return self.ou_tools.get_ou_contents(ou_dn, object_types)

        # =====================================================================
        # SECURITY AND AUDIT TOOLS
        # =====================================================================

        @self.mcp.tool(description="Informações de domínio e políticas de segurança no Active Directory — consulta configurações do domínio AD incluindo password policy, lockout policy, SID do domínio e políticas de segurança. Use quando precisar auditar políticas de senha, verificar configurações de lockout ou obter informações gerais do domínio no Active Directory. Retorna políticas de senha, lockout threshold, max password age e configurações. Consulta somente leitura.")
        def ad_get_domain_security_policy_info():
            return self.security_tools.get_domain_info()

        @self.mcp.tool(description="Grupos privilegiados e administrativos no Active Directory — lista todos os security groups com privilégios elevados no AD incluindo Domain Admins, Enterprise Admins, Schema Admins e grupos de operadores. Use quando precisar auditar permissões administrativas, verificar memberships privilegiados ou realizar análise de segurança no Active Directory. Retorna lista de grupos privilegiados com membros, SID e descrição. Consulta somente leitura.")
        def ad_get_privileged_security_groups():
            return self.security_tools.get_privileged_groups()

        @self.mcp.tool(description="Permissões efetivas de usuário no Active Directory — analisa memberships de grupos de um user no AD para determinar permissões efetivas, grupos privilegiados e riscos de segurança. Use quando precisar auditar permissões de contas, verificar acessos elevados ou analisar riscos de segurança de usuários no Active Directory. Retorna permissões efetivas, grupos privilegiados e assessment de segurança. Consulta somente leitura.")
        def ad_get_user_effective_permissions(
            username: Annotated[str, Field(description="Username to analyze permissions for")]
        ):
            return self.security_tools.get_user_permissions(username)

        @self.mcp.tool(description="Usuários inativos ou sem autenticação no Active Directory — identifica user accounts que não autenticaram no AD por número de dias especificado, indicando contas obsoletas ou não utilizadas. Use quando precisar auditar contas inativas, identificar usuários para desativação ou realizar análise de segurança no Active Directory. Retorna lista de usuários com dias de inatividade, último logon, grupos e status. Consulta somente leitura.")
        def ad_get_inactive_users_by_days(
            days: Annotated[int, Field(description="Number of days to consider inactive", default=90)] = 90,
            include_disabled: Annotated[bool, Field(description="Include disabled accounts in results", default=False)] = False
        ):
            return self.security_tools.get_inactive_users(days, include_disabled)

        @self.mcp.tool(description="Violações de política de senha no Active Directory — identifica user accounts com passwords que violam políticas de segurança no AD incluindo senhas expiradas, senhas que nunca expiram e non-compliance com políticas. Use quando precisar auditar conformidade de senhas, identificar contas com riscos de segurança ou validar políticas de password no Active Directory. Retorna lista de violações com tipo, usuário e detalhes. Consulta somente leitura.")
        def ad_get_password_policy_violations():
            return self.security_tools.get_password_policy_violations()

        @self.mcp.tool(description="Auditoria de contas administrativas no Active Directory — realiza audit abrangente de administrative accounts no AD incluindo memberships privilegiados, compliance de políticas e assessment de riscos de segurança. Use quando precisar auditar segurança de contas admin, verificar conformidade de políticas ou realizar análise de riscos no Active Directory. Retorna relatório completo com violações, riscos e recomendações. Consulta somente leitura.")
        def ad_audit_administrative_accounts():
            return self.security_tools.audit_admin_accounts()

        # =====================================================================
        # SYSTEM TOOLS
        # =====================================================================

        @self.mcp.tool(description="Teste de conexão LDAP com Active Directory — verifica conectividade LDAP, bind authentication e capacidade de search no servidor AD para diagnosticar problemas de conexão. Use quando precisar troubleshooting de conectividade, verificar credenciais LDAP ou validar acesso ao servidor no Active Directory. Retorna status de conexão, bind result, server info e resultados de test search. Operação diagnóstica somente leitura.")
        def ad_test_ldap_connection_status():
            try:
                connection_info = self.ldap_manager.test_connection()
                return [Content(type="text", text=json.dumps(connection_info, indent=2))]
            except Exception as e:
                return [Content(type="text", text=json.dumps({
                    "success": False,
                    "error": str(e)
                }, indent=2))]

        @self.mcp.tool(description="Health check do servidor MCP Active Directory — verifica status geral do MCP server AD incluindo conexão LDAP, client info, testes de inicialização e disponibilidade de serviços. Use quando precisar monitoramento de saúde, alertas de disponibilidade ou diagnóstico de problemas no servidor MCP do Active Directory. Retorna status do servidor, conexão LDAP, client info e resultados de health checks. Operação diagnóstica somente leitura.")
        def ad_health_check_mcp_server():
            status = "ok" if self._tests_passed is True else ("degraded" if self._tests_passed is False else "unknown")
            health_info = {
                "status": status,
                "server": "ActiveDirectoryMCP",
                "tests_passed": self._tests_passed,
                "ldap_connection": "unknown"
            }

            # Add client info if available
            if self.security_manager:
                health_info["client"] = {
                    "name": self.security_manager.client_name,
                    "slug": self.security_manager.client_slug,
                    "domain": self.security_manager.domain
                }

            # Test LDAP connection
            try:
                connection_info = self.ldap_manager.test_connection()
                health_info["ldap_connection"] = "connected" if connection_info.get('connected') else "disconnected"
                health_info["ldap_server"] = connection_info.get('server', 'unknown')
            except Exception as e:
                health_info["ldap_connection"] = "error"
                health_info["ldap_error"] = str(e)

            return [Content(type="text", text=json.dumps(health_info, indent=2))]

        @self.mcp.tool(description="Informações de schema e tools disponíveis no Active Directory MCP — retorna metadados completos de todas as tools disponíveis no servidor MCP AD incluindo parâmetros, permissões e documentação. Use quando precisar documentação de API, descoberta de tools disponíveis ou informações de schema no servidor MCP do Active Directory. Retorna lista completa de tools, parâmetros, operations e client info. Operação diagnóstica somente leitura.")
        def ad_get_mcp_schema_tools_info():
            schema_info = {
                "server": "ActiveDirectoryMCP",
                "version": "0.2.0",  # Updated version with multi-tenant support
                "multi_tenant": True,
                "tools": {
                    "user_tools": self.user_tools.get_schema_info(),
                    "group_tools": self.group_tools.get_schema_info(),
                    "computer_tools": self.computer_tools.get_schema_info(),
                    "ou_tools": self.ou_tools.get_schema_info(),
                    "security_tools": self.security_tools.get_schema_info()
                }
            }

            # Add client info
            if self.security_manager:
                schema_info["client"] = self.security_manager.get_client_info()

            return [Content(type="text", text=json.dumps(schema_info, indent=2, ensure_ascii=False))]

    def start(self) -> None:
        """
        Start the MCP server.

        Initializes the server with:
        - Signal handlers for graceful shutdown (SIGINT, SIGTERM)
        - Async runtime for handling concurrent requests
        - Error handling and logging

        The server runs until terminated by a signal or fatal error.
        """
        import anyio

        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown...")
            self.ldap_manager.disconnect()
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Optionally run tests before serving
            run_tests = os.getenv("RUN_TESTS_ON_START", "0").lower() in ("1", "true", "yes", "on")
            if run_tests:
                import subprocess
                self.logger.info("Running startup tests (pytest)...")
                env = os.environ.copy()
                # Ensure src on PYTHONPATH for tests
                env["PYTHONPATH"] = f"{os.getcwd()}/src" + (":" + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
                result = subprocess.run([sys.executable, "-m", "pytest", "-q"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
                self._tests_passed = (result.returncode == 0)
                if not self._tests_passed:
                    self.logger.error("Startup tests failed. Health will be 'degraded'. Output:\n" + result.stdout.decode())
                else:
                    self.logger.info("Startup tests passed.")

            self.logger.info("Starting Active Directory MCP server...")
            self.logger.info(f"Connected to: {self.config.active_directory.server}")
            self.logger.info(f"Domain: {self.config.active_directory.domain}")

            # Log client info if available
            if self.security_manager:
                self.logger.info(f"Client: {self.security_manager.client_name} ({self.security_manager.client_slug})")

            anyio.run(self.mcp.run_stdio_async)

        except Exception as e:
            self.logger.error(f"Server error: {e}")
            self.ldap_manager.disconnect()
            sys.exit(1)


def main():
    """Main entry point for the server."""
    config_path = os.getenv("AD_MCP_CONFIG")
    if not config_path:
        print("AD_MCP_CONFIG environment variable must be set")
        sys.exit(1)

    try:
        server = ActiveDirectoryMCPServer(config_path)
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
