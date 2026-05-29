"""
Client Registry - Registro central de clientes AD configurados.

Este módulo permite:
- Listar todos os clientes com AD configurado
- Validar se um cliente existe antes de operações
- Resolver aliases de nomes de clientes

"""

import json
import os
import logging
from typing import Optional, Dict, List, Any
from pathlib import Path

logger = logging.getLogger("active-directory-mcp.client-registry")

# Caminho padrão do registro de clientes
DEFAULT_REGISTRY_PATH = "/opt/mcp-servers/shared/configs/ad-clients-registry.json"


class ClientRegistry:
    """
    Gerencia o registro central de clientes com AD configurado.
    """
    
    def __init__(self, registry_path: Optional[str] = None):
        """
        Inicializa o registro de clientes.
        
        Args:
            registry_path: Caminho para o arquivo de registro. Se não informado,
                          usa o caminho padrão.
        """
        self.registry_path = registry_path or DEFAULT_REGISTRY_PATH
        self._registry_data: Optional[Dict] = None
        self._load_registry()
    
    def _load_registry(self) -> None:
        """Carrega o registro de clientes do arquivo JSON."""
        try:
            if os.path.exists(self.registry_path):
                with open(self.registry_path, "r", encoding="utf-8") as f:
                    self._registry_data = json.load(f)
                logger.info(f"Client registry loaded: {len(self.get_all_clients())} clients")
            else:
                logger.warning(f"Client registry not found at {self.registry_path}")
                self._registry_data = {"clients": {}, "aliases": {}}
        except Exception as e:
            logger.error(f"Error loading client registry: {e}")
            self._registry_data = {"clients": {}, "aliases": {}}
    
    def reload(self) -> None:
        """Recarrega o registro do disco."""
        self._load_registry()
    
    def get_all_clients(self) -> Dict[str, Dict[str, Any]]:
        """
        Retorna todos os clientes configurados.
        
        Returns:
            Dicionário com slug como chave e dados do cliente como valor.
        """
        return self._registry_data.get("clients", {})
    
    def get_active_clients(self) -> Dict[str, Dict[str, Any]]:
        """
        Retorna apenas clientes ativos.
        
        Returns:
            Dicionário com clientes ativos.
        """
        return {
            slug: data 
            for slug, data in self.get_all_clients().items() 
            if data.get("active", True)
        }
    
    def get_client(self, slug_or_name: str) -> Optional[Dict[str, Any]]:
        """
        Busca um cliente pelo slug ou nome/alias.
        
        Args:
            slug_or_name: Slug do cliente ou nome/alias.
            
        Returns:
            Dados do cliente ou None se não encontrado.
        """
        # Normaliza o input
        normalized = slug_or_name.lower().strip()
        
        # Tenta buscar diretamente pelo slug
        clients = self.get_all_clients()
        if normalized in clients:
            return {**clients[normalized], "slug": normalized}
        
        # Tenta resolver alias
        aliases = self._registry_data.get("aliases", {})
        if normalized in aliases:
            resolved_slug = aliases[normalized]
            if resolved_slug in clients:
                return {**clients[resolved_slug], "slug": resolved_slug}
        
        # Tenta busca parcial no nome
        for slug, data in clients.items():
            client_name = data.get("name", "").lower()
            if normalized in client_name or client_name in normalized:
                return {**data, "slug": slug}
        
        return None
    
    def client_exists(self, slug_or_name: str) -> bool:
        """
        Verifica se um cliente existe no registro.
        
        Args:
            slug_or_name: Slug do cliente ou nome/alias.
            
        Returns:
            True se o cliente existe, False caso contrário.
        """
        return self.get_client(slug_or_name) is not None
    
    def resolve_client_slug(self, slug_or_name: str) -> Optional[str]:
        """
        Resolve um nome/alias para o slug correto.
        
        Args:
            slug_or_name: Slug do cliente ou nome/alias.
            
        Returns:
            Slug do cliente ou None se não encontrado.
        """
        client = self.get_client(slug_or_name)
        return client.get("slug") if client else None
    
    def list_client_names(self) -> List[str]:
        """
        Retorna lista de nomes de clientes (para exibição).
        
        Returns:
            Lista de nomes formatados.
        """
        return [
            f"{data.get('name')} ({slug})"
            for slug, data in self.get_active_clients().items()
        ]
    
    def format_clients_list(self) -> str:
        """
        Formata a lista de clientes para exibição.
        
        Returns:
            String formatada com a lista de clientes.
        """
        clients = self.get_active_clients()
        if not clients:
            return ("Nenhum cliente multi-tenant configurado. "
                    "O servidor pode estar operando em modo de instância única "
                    "(consulte 'current_instance' para a instância ativa).")
        
        lines = ["Clientes com AD configurado:"]
        for slug, data in clients.items():
            name = data.get("name", slug)
            domain = data.get("domain", "N/A")
            port = data.get("port", "N/A")
            lines.append(f"  • {name} (slug: {slug}) - {domain} - Porta: {port}")
        
        return "\n".join(lines)


# Instância global (singleton)
_registry_instance: Optional[ClientRegistry] = None


def get_client_registry() -> ClientRegistry:
    """
    Retorna a instância global do registro de clientes.
    
    Returns:
        Instância do ClientRegistry.
    """
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = ClientRegistry()
    return _registry_instance


def client_exists(slug_or_name: str) -> bool:
    """
    Função de conveniência para verificar se um cliente existe.
    
    Args:
        slug_or_name: Slug do cliente ou nome/alias.
        
    Returns:
        True se o cliente existe, False caso contrário.
    """
    return get_client_registry().client_exists(slug_or_name)


def list_configured_clients() -> Dict[str, Any]:
    """
    Função de conveniência para listar clientes configurados.
    
    Returns:
        Dicionário com informações dos clientes.
    """
    registry = get_client_registry()
    clients = registry.get_active_clients()
    
    return {
        "total": len(clients),
        "clients": [
            {
                "slug": slug,
                "name": data.get("name"),
                "domain": data.get("domain"),
                "type": data.get("type", "cliente"),
                "port": data.get("port")
            }
            for slug, data in clients.items()
        ],
        "message": registry.format_clients_list()
    }
