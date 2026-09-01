/**
 * PM2 ecosystem example for Active Directory MCP.
 *
 * Two shapes, pick one. Copy this file to your deployment location and adjust
 * every /path/to/... below.
 *
 *   SINGLE  one directory per process. AD_MCP_CONFIG points at an
 *           ad-config.json (see ad-config/ad-config.example.json). The tools
 *           take no ad_server parameter.
 *
 *   MULTI   one process serving N directories. AD_MCP_SERVERS points at an
 *           ad-servers.json (see ad-config/ad-servers.example.json). Every tool
 *           gains ad_server; reads may omit it to search all of them.
 *
 * Keep the config file and the .env outside the repository, mode 600: they hold
 * the service-account passwords.
 */

module.exports = {
  apps: [
    {
      name: 'mcp-ad-single',
      script: './start_server.sh',
      interpreter: '/bin/bash',
      cwd: '/path/to/your/ad-mcp-deployment',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '300M',
      env: {
        AD_MCP_MODE: 'single',
        AD_MCP_CONFIG: '/path/to/ad-config/ad-config.json',
        AD_MCP_API_TOKEN: 'defina-fora-do-repositorio',
        PYTHONPATH: '/path/to/your/ad-mcp-deployment/src'
      },
      error_file: '/var/log/mcp-ad-single-error.log',
      out_file: '/var/log/mcp-ad-single-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true
    },
    {
      name: 'mcp-ad-multi',
      // A wrapper that sources the .env and runs:
      //   python -m active_directory_mcp.server_fastapi --mode multi --port 8853
      script: './start-multi.sh',
      interpreter: '/bin/bash',
      cwd: '/path/to/your/ad-mcp-deployment',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      env: {
        AD_MCP_MODE: 'multi',
        AD_MCP_SERVERS: '/path/to/ad-config/ad-servers.json',
        AD_MCP_API_TOKEN: 'defina-fora-do-repositorio',
        PYTHONPATH: '/path/to/your/ad-mcp-deployment/src'
      },
      error_file: '/var/log/mcp-ad-multi-error.log',
      out_file: '/var/log/mcp-ad-multi-out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true
    }
  ]
};
