/**
 * PM2 ecosystem example for Active Directory MCP (HTTP transport).
 *
 * Copy this file to your deployment location and adjust:
 *   - name              unique PM2 process name
 *   - script            path to your start-http.sh wrapper
 *   - cwd               directory containing your config
 *   - AD_MCP_CONFIG     full path to your ad-config.json
 *   - error_file/out_file log paths writable by the runtime user
 */

module.exports = {
  apps: [{
    name: 'mcp-ad',
    script: './start-http.sh',
    interpreter: '/bin/bash',
    cwd: '/path/to/your/ad-mcp-deployment',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '256M',
    env: {
      AD_MCP_CONFIG: '/path/to/your/ad-config/ad-config.json',
      PYTHONPATH: '/path/to/your/ad-mcp-deployment/src'
    },
    error_file: '/var/log/mcp-ad-error.log',
    out_file: '/var/log/mcp-ad-out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true
  }]
};
