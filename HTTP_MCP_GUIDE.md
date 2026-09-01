# HTTP MCP Transport Guide

This guide shows how to run the Active Directory MCP server over Streamable HTTP transport (`server_fastapi.py`) so it can be consumed by Claude Code, Gemini CLI, n8n, custom agents or any MCP-aware client.

## Quick start

### Manual

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Create your real config from the template
cp ad-config/ad-config.example.json /etc/ad-mcp/ad-config.json
$EDITOR /etc/ad-mcp/ad-config.json
chmod 600 /etc/ad-mcp/ad-config.json

export AD_MCP_CONFIG=/etc/ad-mcp/ad-config.json
python -m active_directory_mcp.server_fastapi --host 0.0.0.0 --port 8820
# MCP endpoint: http://localhost:8820/mcp
# Health check (no auth required): http://localhost:8820/health
```

`--port` defaults to `8820` if omitted. There is no `--path` option: the MCP endpoint is always `/mcp`.

> **Bundled Docker image**: `Dockerfile` and both compose files now start `server_fastapi` on port 8820 at the fixed path `/mcp`. They used to invoke the retired `server_http` module on port 8813 &mdash; if you have an image built before 01/09/2026, rebuild it.

### Single vs. multi mode

`server_fastapi.py` supports the same two modes described in [README.md](README.md#multi-tenant-architecture):

| | `single` (default) | `multi` |
|---|---|---|
| Config source | `AD_MCP_CONFIG` &rarr; one `ad-config.json` | `AD_MCP_SERVERS` &rarr; one `ad-servers.json` |
| Directories per process | 1 | N |
| `ad_server` tool parameter | not present | required on writes, optional on reads |
| Catalog tools | `ad_get_client_tenant_info`, `ad_list_configured_clients`, `ad_check_client_configuration` | `ad_list_ad_servers`, `ad_check_ad_server_configured` |
| MSP prompts (`prompts/get`) | no `ad_server` argument | `ad_server` in `arguments` selects the directory |

```bash
export AD_MCP_MODE=multi
export AD_MCP_SERVERS=/etc/ad-mcp/ad-servers.json
python -m active_directory_mcp.server_fastapi --host 0.0.0.0 --port 8820
```

See [`ad-config/ad-servers.example.json`](ad-config/ad-servers.example.json) for the schema. The stdio transport (`server.py`) only supports `single` mode.

## Client configuration

### Claude Code

```bash
claude mcp add --transport http ad \
  http://localhost:8820/mcp \
  --headers "Authorization: Bearer YOUR_AUTOMATION_TOKEN"
```

### Gemini CLI

`~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "ad": {
      "httpUrl": "http://localhost:8820/mcp",
      "headers": { "Authorization": "Bearer YOUR_AUTOMATION_TOKEN" },
      "timeout": 30000
    }
  }
}
```

### Generic JSON-RPC client

```bash
curl -X POST http://localhost:8820/mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_AUTOMATION_TOKEN' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 1
  }'
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | none | Liveness/health check |
| `GET` | `/mcp` | Bearer | Server-Sent Events stream (Gemini-style clients); opens a session and sends periodic keepalives |
| `POST` | `/mcp` | Bearer | JSON-RPC 2.0 endpoint &mdash; `initialize`, `tools/list`, `tools/call`, `prompts/list`, `prompts/get` |
| `DELETE` | `/mcp` | Bearer | Terminates the session named by the `Mcp-Session-Id` header |

## Transports comparison

| Transport | Module | Notes |
|---|---|---|
| stdio | `server.py` | Direct CLI use (Claude Desktop, `mcp-cli`); `single` mode only; does **not** expose the 15 MSP prompts |
| Streamable HTTP (FastAPI) | `server_fastapi.py` | Recommended for every networked client; supports both `single` and `multi` mode and the MSP prompts (`prompts/list` / `prompts/get`) |

The FastMCP-based HTTP transport (`server_http.py`, historically on port 8813 at `/activedirectory-mcp`) has been removed from this codebase.

## Multi-instance deployment

Run one process per tenant (single mode), or one process serving several tenants (multi mode) &mdash; see [`ecosystem.config.js`](ecosystem.config.js) for a PM2 example of both shapes:

```
tenant-a:  port 8821, AD_MCP_MODE=single, AD_MCP_CONFIG=/opt/tenants/tenant-a/ad-config.json
tenant-b:  port 8822, AD_MCP_MODE=single, AD_MCP_CONFIG=/opt/tenants/tenant-b/ad-config.json
```

Each single-mode tenant is fully isolated: separate credentials, separate audit log, separate Bearer token.

## Reverse proxy (nginx example)

```nginx
server {
  listen 443 ssl http2;
  server_name ad-mcp.example.com;

  ssl_certificate     /etc/letsencrypt/live/ad-mcp.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/ad-mcp.example.com/privkey.pem;

  location /tenant-a/ {
    proxy_pass http://127.0.0.1:8821/mcp;
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    proxy_buffering off;
    proxy_read_timeout 300s;
  }

  location /tenant-b/ {
    proxy_pass http://127.0.0.1:8822/mcp;
    proxy_http_version 1.1;
    proxy_set_header Connection '';
    proxy_buffering off;
    proxy_read_timeout 300s;
  }
}
```

> Streamable HTTP keeps the response stream open for the duration of the call. Disable `proxy_buffering` and bump `proxy_read_timeout`.

## Authentication

Two layers protect the server:

1. **Transport layer** &mdash; Bearer token in `Authorization: Bearer …`, checked against `AD_MCP_API_TOKEN`. If `AD_MCP_API_TOKEN` is not set in the environment, the FastAPI server accepts every request unauthenticated (`verify_bearer_token` in `server_fastapi.py` treats a missing configured token as "development mode"). Always set `AD_MCP_API_TOKEN` in any environment reachable over the network.
2. **Tool layer** &mdash; every `ad_create_*` / `ad_modify_*` / `ad_delete_*` / `ad_enable_*` / `ad_disable_*` / `ad_reset_*` / `ad_add_*` / `ad_remove_*` / `ad_move_*` checks one of:
   - `automation_token` argument equals the tenant's `automation.token`
   - `client_confirmation` argument equals the tenant's `client.slug` (in `multi` mode, the same value accepted by `ad_server`: server name, alias, client name, domain or base DN)
   - `require_confirmation_for_writes: false` in the tenant config

If neither is provided, the call returns `permitted: false` and **no LDAP write happens**.

## Smoke tests

```bash
# 1. Health check
curl -X POST http://localhost:8820/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ad_health_check_mcp_server","arguments":{}},"id":1}'

# 2. Tenant identity (single mode)
curl -X POST http://localhost:8820/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ad_get_client_tenant_info","arguments":{}},"id":1}'

# 3. List users
curl -X POST http://localhost:8820/mcp \
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

Add `-H 'Authorization: Bearer YOUR_TOKEN'` to every call once `AD_MCP_API_TOKEN` is set. For a scripted end-to-end smoke test against a live `multi` mode instance, see `tests/test_smoke_ao_vivo.py` (self-skips unless `AD_MCP_API_TOKEN` is exported and the instance answers) &mdash; details in [TESTING_GUIDE.md](TESTING_GUIDE.md).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Client connects but gets empty tool list | Wrong path | The endpoint is always `/mcp` (there is no `--path` option in `server_fastapi.py`) |
| 502 from reverse proxy mid-stream | Proxy buffering | Disable buffering, raise read timeout |
| `permitted: false` on all writes | Missing confirmation / token | Pass `client_confirmation=<tenant-slug>` (or `<ad_server>` in multi mode) or `automation_token=<value>` |
| `ldap_connection: error` in health | Bad bind / network | Test bind with `ldapsearch -H <server> -D '<bind_dn>' -W` |
| Server starts but logs `Connection test error` | TLS / firewall | Confirm `ldaps://...:636` reachable and CA cert configured |
| `Error: modo multi exige AD_MCP_SERVERS` on startup | `AD_MCP_MODE=multi` set without `AD_MCP_SERVERS` / `--servers` | Point `AD_MCP_SERVERS` at an `ad-servers.json` |
