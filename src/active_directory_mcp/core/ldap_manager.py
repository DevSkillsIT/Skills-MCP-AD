"""LDAP connection manager for Active Directory.

Enhanced with:
- Auto-reconnect decorator for all LDAP operations
- Background keep-alive thread
- Specific SSL error handling
- Real connection health checks

Connection resilience improvements
"""

import logging
import ssl
import time
import threading
from typing import Optional, List, Dict, Any, Union
from functools import wraps
from threading import Lock, Event

import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError, LDAPSocketSendError, LDAPSocketReceiveError

from ..config.models import ActiveDirectoryConfig, SecurityConfig, PerformanceConfig

logger = logging.getLogger(__name__)


# =============================================================================
# SSL/Socket errors that indicate connection is dead and needs reconnection
# =============================================================================
RECONNECTABLE_ERRORS = (
    LDAPSocketSendError,
    LDAPSocketReceiveError,
    LDAPSocketOpenError,
    ConnectionResetError,
    BrokenPipeError,
    OSError,
)

SSL_ERROR_PATTERNS = [
    'SSL: BAD_LENGTH',
    'EOF occurred',
    'socket sending error',
    'socket receiving error',
    'Connection reset',
    'Broken pipe',
]


def is_reconnectable_error(error: Exception) -> bool:
    """
    Check if an error indicates the connection is dead and should be reconnected.
    
    Args:
        error: The exception to check
        
    Returns:
        True if the connection should be invalidated and reconnected
    """
    # Check exception type
    if isinstance(error, RECONNECTABLE_ERRORS):
        return True
    
    # Check error message patterns
    error_str = str(error).lower()
    for pattern in SSL_ERROR_PATTERNS:
        if pattern.lower() in error_str:
            return True
    
    return False


def with_reconnect(method):
    """
    Decorator that adds automatic reconnection to LDAP operations.
    
    If the operation fails with a socket/SSL error, it will:
    1. Invalidate the current connection
    2. Establish a new connection
    3. Retry the operation once
    
    This is generic and works with any LDAP client, not specific to any tool.
    """
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except Exception as e:
            if is_reconnectable_error(e):
                logger.warning(f"Connection error in {method.__name__}: {e}. Attempting reconnect...")
                
                # Invalidate connection
                with self._lock:
                    if self._connection:
                        try:
                            self._connection.unbind()
                        except:
                            pass
                    self._connection = None
                
                # Reconnect and retry once
                try:
                    self.connect()
                    logger.info(f"Reconnected successfully. Retrying {method.__name__}...")
                    return method(self, *args, **kwargs)
                except Exception as retry_error:
                    logger.error(f"Retry failed for {method.__name__}: {retry_error}")
                    raise
            else:
                # Not a reconnectable error, propagate as-is
                raise
    return wrapper


class LDAPManager:
    """
    LDAP connection manager for Active Directory operations.
    
    Provides connection pooling, automatic reconnection, and error handling
    for LDAP operations against Active Directory.
    
    Features:
    - Auto-reconnect on socket/SSL errors
    - Background keep-alive thread
    - Real health checks with LDAP search
    - Thread-safe connection management
    """
    
    def __init__(self, 
                 ad_config: ActiveDirectoryConfig,
                 security_config: SecurityConfig,
                 performance_config: PerformanceConfig,
                 ou_config=None):
        """
        Initialize LDAP manager.
        
        Args:
            ad_config: Active Directory configuration
            security_config: Security configuration
            performance_config: Performance configuration
        """
        self.ad_config = ad_config
        self.security_config = security_config
        self.performance_config = performance_config
        # Organizational units are not part of ActiveDirectoryConfig; the tools
        # reach them through here when deciding where to create an object.
        self.ou_config = ou_config
        
        self._connection: Optional[Connection] = None
        self._server_pool: Optional[List[Server]] = None
        self._lock = Lock()
        
        # Keep-alive configuration
        self._keepalive_interval = getattr(performance_config, 'keepalive_interval', 300)  # 5 minutes default
        self._keepalive_enabled = getattr(performance_config, 'keepalive_enabled', True)
        self._keepalive_thread: Optional[threading.Thread] = None
        self._keepalive_stop = Event()
        
        # Connection health tracking
        self._last_successful_operation = time.time()
        self._connection_errors = 0
        self._max_connection_errors = 5
        
        self._setup_servers()
        
        # Start keep-alive thread if enabled
        if self._keepalive_enabled:
            self._start_keepalive()
    
    def _setup_servers(self) -> None:
        """Setup LDAP servers and server pool."""
        try:
            # Setup TLS configuration
            tls_config = None
            if self.security_config.enable_tls:
                tls_config = ldap3.Tls(
                    validate=ssl.CERT_REQUIRED if self.security_config.validate_certificate else ssl.CERT_NONE,
                    ca_certs_file=self.security_config.ca_cert_file
                )
            
            # Create primary server
            primary_server = Server(
                self.ad_config.server,
                get_info=ALL,
                tls=tls_config,
                connect_timeout=self.ad_config.timeout
            )
            
            servers = [primary_server]
            
            # Add additional servers from pool
            if self.ad_config.server_pool:
                for server_url in self.ad_config.server_pool:
                    server = Server(
                        server_url,
                        get_info=ALL,
                        tls=tls_config,
                        connect_timeout=self.ad_config.timeout
                    )
                    servers.append(server)
            
            # Create server pool for failover
            self._server_pool = servers
            logger.info(f"Configured {len(servers)} LDAP servers")
            
        except Exception as e:
            logger.error(f"Error setting up LDAP servers: {e}")
            raise
    
    def _start_keepalive(self) -> None:
        """Start background keep-alive thread."""
        if self._keepalive_thread and self._keepalive_thread.is_alive():
            return
        
        self._keepalive_stop.clear()
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop,
            name="LDAPKeepAlive",
            daemon=True
        )
        self._keepalive_thread.start()
        logger.info(f"Started LDAP keep-alive thread (interval: {self._keepalive_interval}s)")
    
    def _stop_keepalive(self) -> None:
        """Stop background keep-alive thread."""
        if self._keepalive_thread:
            self._keepalive_stop.set()
            self._keepalive_thread.join(timeout=5)
            self._keepalive_thread = None
            logger.info("Stopped LDAP keep-alive thread")
    
    def _keepalive_loop(self) -> None:
        """
        Background loop that periodically pings the LDAP connection.
        
        This prevents the connection from being closed due to inactivity
        and detects dead connections early.
        """
        while not self._keepalive_stop.wait(timeout=self._keepalive_interval):
            try:
                if self._connection and self._connection.bound:
                    # Perform a lightweight search as keep-alive ping
                    self._connection.search(
                        search_base=self.ad_config.base_dn,
                        search_filter='(objectClass=*)',
                        search_scope=ldap3.BASE,
                        attributes=['objectClass'],
                        size_limit=1
                    )
                    self._last_successful_operation = time.time()
                    self._connection_errors = 0
                    logger.debug("Keep-alive ping successful")
                else:
                    # Connection not established, try to connect
                    logger.debug("Keep-alive: connection not bound, attempting reconnect")
                    self.connect()
            except Exception as e:
                self._connection_errors += 1
                logger.warning(f"Keep-alive ping failed ({self._connection_errors}/{self._max_connection_errors}): {e}")
                
                if is_reconnectable_error(e) or self._connection_errors >= self._max_connection_errors:
                    # Invalidate and reconnect
                    with self._lock:
                        if self._connection:
                            try:
                                self._connection.unbind()
                            except:
                                pass
                        self._connection = None
                    
                    try:
                        self.connect()
                        self._connection_errors = 0
                        logger.info("Keep-alive: reconnected successfully")
                    except Exception as reconnect_error:
                        logger.error(f"Keep-alive: reconnect failed: {reconnect_error}")
    
    def connect(self) -> Connection:
        """
        Establish LDAP connection with retry logic.
        
        Returns:
            Connection: Active LDAP connection
            
        Raises:
            LDAPException: If connection fails after all retries
        """
        with self._lock:
            if self._connection and self._connection.bound:
                return self._connection
            
            last_error = None
            
            for attempt in range(self.performance_config.max_retries):
                try:
                    # Try each server in the pool
                    for server in self._server_pool:
                        try:
                            logger.debug(f"Attempting connection to {server.host}:{server.port}")
                            
                            connection = Connection(
                                server,
                                user=self.ad_config.bind_dn,
                                password=self.ad_config.password,
                                auto_bind=self.ad_config.auto_bind,
                                receive_timeout=self.ad_config.receive_timeout,
                                authentication=ldap3.SIMPLE,
                                check_names=True,
                                raise_exceptions=True
                            )
                            
                            # Test the connection
                            if connection.bind():
                                self._connection = connection
                                self._last_successful_operation = time.time()
                                self._connection_errors = 0
                                logger.info(f"Successfully connected to {server.host}:{server.port}")
                                return connection
                            else:
                                logger.warning(f"Failed to bind to {server.host}:{server.port}")
                                
                        except (LDAPSocketOpenError, LDAPBindError) as e:
                            logger.warning(f"Connection failed to {server.host}:{server.port}: {e}")
                            last_error = e
                            continue
                    
                    # If we get here, all servers failed for this attempt
                    if attempt < self.performance_config.max_retries - 1:
                        logger.info(f"Retry {attempt + 1}/{self.performance_config.max_retries} after {self.performance_config.retry_delay}s")
                        time.sleep(self.performance_config.retry_delay)
                    
                except Exception as e:
                    logger.error(f"Unexpected error during connection attempt {attempt + 1}: {e}")
                    last_error = e
                    
                    if attempt < self.performance_config.max_retries - 1:
                        time.sleep(self.performance_config.retry_delay)
            
            # All attempts failed
            error_msg = f"Failed to connect to any LDAP server after {self.performance_config.max_retries} attempts"
            if last_error:
                error_msg += f". Last error: {last_error}"
            
            logger.error(error_msg)
            raise LDAPException(error_msg)
    
    def disconnect(self) -> None:
        """Disconnect from LDAP server."""
        # Stop keep-alive first
        self._stop_keepalive()
        
        with self._lock:
            if self._connection:
                try:
                    self._connection.unbind()
                    logger.info("Disconnected from LDAP server")
                except Exception as e:
                    logger.warning(f"Error during disconnect: {e}")
                finally:
                    self._connection = None
    
    def _ensure_connection(self) -> Connection:
        """
        Ensure we have a valid connection, reconnecting if necessary.
        
        Returns:
            Connection: Active LDAP connection
        """
        connection = self.connect()
        
        # Check if connection is still alive
        if not connection.bound:
            logger.info("Connection lost, reconnecting...")
            with self._lock:
                self._connection = None
            connection = self.connect()
        
        return connection
    
    @with_reconnect
    def search(self, 
               search_base: str,
               search_filter: str,
               attributes: Union[List[str], str] = ALL_ATTRIBUTES,
               search_scope: str = SUBTREE,
               size_limit: int = 0) -> List[Dict[str, Any]]:
        """
        Perform LDAP search operation.
        
        Args:
            search_base: Base DN for search
            search_filter: LDAP filter string
            attributes: Attributes to retrieve
            search_scope: Search scope (SUBTREE, ONELEVEL, BASE)
            size_limit: Maximum number of results (0 = no limit)
            
        Returns:
            List of LDAP entries as dictionaries
            
        Raises:
            LDAPException: If search fails
        """
        connection = self._ensure_connection()
        
        try:
            logger.debug(f"Searching: base={search_base}, filter={search_filter}")
            
            # Perform paged search for large result sets
            paged_size = min(self.performance_config.page_size, size_limit) if size_limit > 0 else self.performance_config.page_size
            
            entries = []
            cookie = None
            
            while True:
                success = connection.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    search_scope=search_scope,
                    attributes=attributes,
                    paged_size=paged_size,
                    paged_cookie=cookie
                )
                
                if not success:
                    # @MX:ANCHOR ldap3 returns False for a BASE search whose
                    # filter matches nothing, even though the operation
                    # succeeded (result 0). Raising on the boolean alone turned
                    # "nothing matched" into an error and aborted whole audits:
                    # one nested group inside Domain Admins was enough to make
                    # audit_admin_accounts report zero administrative accounts
                    # for a domain that has thirteen.
                    codigo = (connection.result or {}).get('result')
                    if codigo in (0, 32):  # success / noSuchObject
                        logger.debug(
                            "Search returned no entries (result=%s): base=%s filter=%s",
                            codigo, search_base, search_filter)
                        break
                    logger.error(f"Search failed: {connection.result}")
                    raise LDAPException(f"Search failed: {connection.result}")
                
                # Add entries to results
                for entry in connection.entries:
                    entry_dict = {
                        'dn': entry.entry_dn,
                        'attributes': {}
                    }
                    
                    for attr_name in entry.entry_attributes:
                        attr_value = getattr(entry, attr_name)
                        if hasattr(attr_value, 'value'):
                            entry_dict['attributes'][attr_name] = attr_value.value
                        else:
                            entry_dict['attributes'][attr_name] = str(attr_value)
                    
                    entries.append(entry_dict)
                    
                    # Check size limit
                    if size_limit > 0 and len(entries) >= size_limit:
                        logger.debug(f"Size limit reached: {size_limit}")
                        return entries[:size_limit]
                
                # Check for more pages
                cookie = connection.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
                if not cookie:
                    break
            
            self._last_successful_operation = time.time()
            logger.debug(f"Search returned {len(entries)} entries")
            return entries
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            raise
    
    @with_reconnect
    def add(self, dn: str, attributes: Dict[str, Any]) -> bool:
        """
        Add LDAP entry.
        
        Args:
            dn: Distinguished name of new entry
            attributes: Entry attributes
            
        Returns:
            True if successful
            
        Raises:
            LDAPException: If operation fails
        """
        connection = self._ensure_connection()
        
        try:
            logger.debug(f"Adding entry: {dn}")
            
            success = connection.add(dn, attributes=attributes)
            
            if success:
                self._last_successful_operation = time.time()
                logger.info(f"Successfully added entry: {dn}")
                return True
            else:
                logger.error(f"Failed to add entry {dn}: {connection.result}")
                raise LDAPException(f"Add operation failed: {connection.result}")
                
        except Exception as e:
            logger.error(f"Add error for {dn}: {e}")
            raise
    
    @with_reconnect
    def modify(self, dn: str, changes: Dict[str, Any]) -> bool:
        """
        Modify LDAP entry.
        
        Args:
            dn: Distinguished name of entry to modify
            changes: Dictionary of changes to apply
            
        Returns:
            True if successful
            
        Raises:
            LDAPException: If operation fails
        """
        connection = self._ensure_connection()
        
        try:
            logger.debug(f"Modifying entry: {dn}")
            
            success = connection.modify(dn, changes)
            
            if success:
                self._last_successful_operation = time.time()
                logger.info(f"Successfully modified entry: {dn}")
                return True
            else:
                logger.error(f"Failed to modify entry {dn}: {connection.result}")
                raise LDAPException(f"Modify operation failed: {connection.result}")
                
        except Exception as e:
            logger.error(f"Modify error for {dn}: {e}")
            raise
    
    @with_reconnect
    def delete(self, dn: str) -> bool:
        """
        Delete LDAP entry.
        
        Args:
            dn: Distinguished name of entry to delete
            
        Returns:
            True if successful
            
        Raises:
            LDAPException: If operation fails
        """
        connection = self._ensure_connection()
        
        try:
            logger.debug(f"Deleting entry: {dn}")
            
            success = connection.delete(dn)
            
            if success:
                self._last_successful_operation = time.time()
                logger.info(f"Successfully deleted entry: {dn}")
                return True
            else:
                logger.error(f"Failed to delete entry {dn}: {connection.result}")
                raise LDAPException(f"Delete operation failed: {connection.result}")
                
        except Exception as e:
            logger.error(f"Delete error for {dn}: {e}")
            raise
    
    @with_reconnect
    def move(self, dn: str, new_parent: str) -> bool:
        """
        Move LDAP entry to new parent.
        
        Args:
            dn: Distinguished name of entry to move
            new_parent: New parent DN
            
        Returns:
            True if successful
            
        Raises:
            LDAPException: If operation fails
        """
        connection = self._ensure_connection()
        
        try:
            logger.debug(f"Moving entry {dn} to {new_parent}")
            
            success = connection.modify_dn(dn, new_superior=new_parent)
            
            if success:
                self._last_successful_operation = time.time()
                logger.info(f"Successfully moved entry {dn} to {new_parent}")
                return True
            else:
                logger.error(f"Failed to move entry {dn}: {connection.result}")
                raise LDAPException(f"Move operation failed: {connection.result}")
                
        except Exception as e:
            logger.error(f"Move error for {dn}: {e}")
            raise
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test LDAP connection and return server information.
        
        Performs a real LDAP search to validate the connection is working,
        not just checking if the socket is open.
        
        Returns:
            Dictionary with connection test results
        """
        try:
            connection = self.connect()
            
            # Get server info
            server_info = {
                'connected': True,
                'server': connection.server.host,
                'port': connection.server.port,
                'ssl': connection.server.ssl,
                'bound': connection.bound,
                'user': connection.user,
                'last_successful_operation': self._last_successful_operation,
                'connection_errors': self._connection_errors,
                'keepalive_enabled': self._keepalive_enabled,
                'keepalive_interval': self._keepalive_interval,
            }
            
            # Perform a REAL search to test functionality (not just socket state)
            try:
                connection.search(
                    search_base=self.ad_config.base_dn,
                    search_filter='(objectClass=*)',
                    search_scope=ldap3.BASE,
                    attributes=['objectClass'],
                    size_limit=1
                )
                server_info['search_test'] = True
                server_info['search_test_time'] = time.time()
                self._last_successful_operation = time.time()
                self._connection_errors = 0
            except Exception as e:
                server_info['search_test'] = False
                server_info['search_error'] = str(e)
                
                # If search fails, connection is likely dead
                if is_reconnectable_error(e):
                    server_info['connection_status'] = 'stale'
                    server_info['recommendation'] = 'Connection appears stale, will auto-reconnect on next operation'
            
            logger.info("Connection test completed")
            return server_info
            
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return {
                'connected': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'is_reconnectable': is_reconnectable_error(e)
            }
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """
        Get connection statistics and health information.
        
        Returns:
            Dictionary with connection statistics
        """
        return {
            'connected': self._connection is not None and self._connection.bound,
            'last_successful_operation': self._last_successful_operation,
            'seconds_since_last_operation': time.time() - self._last_successful_operation,
            'connection_errors': self._connection_errors,
            'max_connection_errors': self._max_connection_errors,
            'keepalive_enabled': self._keepalive_enabled,
            'keepalive_interval': self._keepalive_interval,
            'keepalive_thread_alive': self._keepalive_thread.is_alive() if self._keepalive_thread else False,
        }
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
