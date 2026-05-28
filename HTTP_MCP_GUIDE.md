# HTTP MCP Transport Guide

This guide shows how to run the Active Directory MCP server over Streamable HTTP transport so it can be consumed by Claude Code, Gemini CLI, n8n, custom agents or any MCP-aware client.

## Quick start

### Docker Compose

```bash
git clone https://github.com/DevSkillsIT/Skills-MCP-AD.git
cd Skills-MCP-AD

# Create your real config from the template
cp ad-config/ad-config.example.json /etc/ad-mcp/ad-config.json
$EDITOR /etc/ad-mcp/ad-config.json
chmod 600 /etc/ad-mcp/ad-config.json

# Run
AD_MCP_CONFIG=/etc/ad-mcp/ad-config.json docker compose up -d
# HTTP endpoint: http://localhost:8813/activedirectory-mcp
```

### Manual

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

export AD_MCP_CONFIG=/etc/ad-mcp/ad-config.json
python -m active_directory_mcp.server_http \
  --host 0.0.0.0 \
  --port 8813 \
  --path /activedirectory-mcp
```

## Client configuration

### Claude Code

```bash
claude mcp add --transport http ad \
  http://localhost:8813/activedirectory-mcp \
  --headers "Authorization: Bearer YOUR_AUTOMATION_TOKEN"
```

### Gemini CLI

`~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "ad": {
      "httpUrl": "http://localhost:8813/activedirectory-mcp",
      "headers": { "Authorization": "Bearer YOUR_AUTOMATION_TOKEN" },
      "timeout": 30000
    }
  }
}
```

### Generic JSON-RPC client

```bash
curl -X POST http://localhost:8813/activedirectory-mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_AUTOMATION_TOKEN' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 1
  }'
```

## Transports comparison

| Transport | Module | When to use |
|---|---|---|
| stdio | `server.py` | Direct CLI use (Claude Desktop, `mcp-cli`), single instance |
| Streamable HTTP (FastMCP) | `server_http.py` | Multi-tenant deployment behind a reverse proxy; recommended default |
| Streamable HTTP (FastAPI) | `server_fastapi.py` | When you need custom HTTP middleware (auth proxies, custom OpenAPI, etc.) |

All three transports expose the same 47 `ad_*` tools.

## Multi-tenant deployment

Run one process per tenant, each with its own `AD_MCP_CONFIG`:

```
tenant-a:  port 8821, AD_MCP_CONFIG=/opt/tenants/tenant-a/ad-config.json
tenant-b:  port 8822, AD_MCP_CONFIG=/opt/tenants/tenant-b/ad-config.json
tenant-c:  port 8823, AD_MCP_CONFIG=/opt/tenants/tenant-c/ad-config.json
```

Each tenant is fully isolated: separate credentials, separate audit log, separate Bearer token. See [`ecosystem.config.js`](ecosystem.config.js) for a PM2 example.

## Reverse proxy (nginx example)

```nginx
server {
  listen 443 ssl http2;
  server_name ad-mcp.example.com;

  ssl_certificate     /etc/letsencrypt/live/ad-mcp.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/ad-mcp.example.com/privkey.pem;

  location /tenant-a/ {
    proxy_pass http://127.0.0.1:8821/activedirectory-mcp;
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    proxy_buffering off;
    proxy_read_timeout 300s;
  }

  location /tenant-b/ {
    proxy_pass http://127.0.0.1:8822/activedirectory-mcp;
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    proxy_buffering off;
    proxy_read_timeout 300s;
  }
}
```

> Streamable HTTP keeps the response stream open for the duration of the call. Disable `proxy_buffering` and bump `proxy_read_timeout`.

## Authentication

Two layers protect write operations:

1. **Transport layer** &mdash; Bearer token in `Authorization: Bearer …`. Required only when your config opts into HTTP auth (depends on which server module you run; see source for the current default).
2. **Tool layer** &mdash; every `ad_create_*` / `ad_modify_*` / `ad_delete_*` / `ad_enable_*` / `ad_disable_*` / `ad_reset_*` / `ad_add_*` / `ad_remove_*` / `ad_move_*` checks one of:
   - `automation_token` argument equals the tenant's `automation.token`
   - `client_confirmation` argument equals the tenant's `client.slug`
   - `require_confirmation_for_writes: false` in the tenant config

If neither is provided, the call returns `permitted: false` and **no LDAP write happens**.

## Smoke tests

```bash
# 1. Health check
curl -X POST http://localhost:8813/activedirectory-mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ad_health_check_mcp_server","arguments":{}},"id":1}'

# 2. Tenant identity
curl -X POST http://localhost:8813/activedirectory-mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ad_get_client_tenant_info","arguments":{}},"id":1}'

# 3. List users
curl -X POST http://localhost:8813/activedirectory-mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "ad_list_users_with_filters",
      "arguments": { "filter_criteria": "(objectClass=user)" }
    },
    "id": 1
  }'
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Client connects but gets empty tool list | Wrong path | Confirm path matches `--path` (default `/activedirectory-mcp`) |
| 502 from reverse proxy mid-stream | Proxy buffering | Disable buffering, raise read timeout |
| `permitted: false` on all writes | Missing confirmation / token | Pass `client_confirmation=<tenant-slug>` or `automation_token=<value>` |
| `ldap_connection: error` in health | Bad bind / network | Test bind with `ldapsearch -H <server> -D '<bind_dn>' -W` |
| Server starts but logs `Connection test error` | TLS / firewall | Confirm `ldaps://...:636` reachable and CA cert configured |
