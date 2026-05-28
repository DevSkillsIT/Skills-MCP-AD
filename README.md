<h1 align="center">Active Directory MCP</h1>

<p align="center">
  <strong>Multi-tenant Active Directory MCP Server &mdash; manage AD via AI assistants</strong>
</p>

<p align="center">
  <a href="https://github.com/DevSkillsIT/Skills-MCP-AD/stargazers"><img src="https://img.shields.io/github/stars/DevSkillsIT/Skills-MCP-AD?style=for-the-badge&color=000cd9" alt="Stars"/></a>
  <a href="https://github.com/DevSkillsIT/Skills-MCP-AD/network/members"><img src="https://img.shields.io/github/forks/DevSkillsIT/Skills-MCP-AD?style=for-the-badge&color=0a2463" alt="Forks"/></a>
  <a href="https://github.com/DevSkillsIT/Skills-MCP-AD/issues"><img src="https://img.shields.io/github/issues/DevSkillsIT/Skills-MCP-AD?style=for-the-badge&color=faad14" alt="Issues"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-52c41a?style=for-the-badge" alt="License"/></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/MCP-2024--11--05-blue?style=flat-square" alt="MCP Version"/>
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/Transport-stdio_|_HTTP-orange?style=flat-square" alt="Transport"/>
  <img src="https://img.shields.io/badge/Tools-47-brightgreen?style=flat-square" alt="Tools"/>
</p>

<p align="center">
  <a href="#about">About</a> &bull;
  <a href="#multi-tenant-architecture">Architecture</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#tools">Tools</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="#security">Security</a>
</p>

---

## About

**Active Directory MCP** is an open-source [Model Context Protocol](https://modelcontextprotocol.io) server that lets AI assistants (Claude, Gemini CLI, ChatGPT via API, etc.) safely manage Active Directory environments.

### Key features

- **47 tools** covering users, groups, computers, OUs, security, audit, and 15 MSP prompt playbooks.
- **Three transports**: stdio (`server.py`), Streamable HTTP via FastMCP (`server_http.py`), and Streamable HTTP via FastAPI (`server_fastapi.py`).
- **Multi-tenant by design**: each instance binds to its own AD via `AD_MCP_CONFIG`; the same codebase can serve unlimited tenants from one host.
- **Write-operation guard rails**: every mutating tool requires either a per-tenant client confirmation string or an automation Bearer token before touching AD.
- **Audit log on every operation**: each call records operation name, target, mode (CONFIRMED / AUTOMATION / NO_CONFIRMATION_REQUIRED), and outcome.

### Naming convention

All MCP tool names use the `ad_*` prefix with a descriptive suffix &mdash; e.g. `ad_list_users_with_filters`, `ad_create_user_account`, `ad_disable_computer_account_trust`. This avoids collisions when this MCP runs alongside other servers (GLPI, Hudu, etc.) connected to the same AI client.

---

## Multi-tenant architecture

This MCP is designed to run as one process per tenant, all sharing the same code:

```
.base-code/                    <- this repository (shared source of truth)
  src/active_directory_mcp/
  ad-config/
    ad-config.example.json     <- template only (real configs are .gitignored)

<deployment>/                  <- one directory per tenant, OUTSIDE this repo
  tenant-a/
    ad-config/ad-config.json   <- real credentials (NEVER committed)
    start.sh                   <- exports AD_MCP_CONFIG and launches the server
  tenant-b/
    ad-config/ad-config.json
    start.sh
```

Each `start.sh` exports `AD_MCP_CONFIG` pointing at that tenant's config and runs `python -m active_directory_mcp.server_http` on a dedicated port. Update the shared `.base-code/` once, restart all tenants &mdash; same code, isolated state.

---

## Quick Start

### Prerequisites

- Python 3.11+
- LDAP/LDAPS reachable from the host
- An AD service account with the permissions required by the operations you plan to expose

### 1. Install

```bash
git clone https://github.com/DevSkillsIT/Skills-MCP-AD.git
cd Skills-MCP-AD

python -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows

pip install -e .                   # installs from pyproject.toml
```

### 2. Configure

```bash
mkdir -p /etc/ad-mcp
cp ad-config/ad-config.example.json /etc/ad-mcp/ad-config.json
$EDITOR /etc/ad-mcp/ad-config.json   # set server, bind_dn, password, base_dn, OUs
chmod 600 /etc/ad-mcp/ad-config.json
```

> The example file is the only template kept in git. Any real `ad-config.json` is blocked by `.gitignore` (`ad-config/*.json` + `!ad-config/*.example.json`).

### 3. Run

```bash
export AD_MCP_CONFIG=/etc/ad-mcp/ad-config.json

# stdio transport (for direct Claude Desktop / mcp-cli use):
python -m active_directory_mcp.server

# HTTP transport (for Claude Code, Gemini CLI, n8n, etc.):
python -m active_directory_mcp.server_http --host 0.0.0.0 --port 8813 --path /activedirectory-mcp
```

### 4. Connect from Claude Code

```bash
claude mcp add --transport http ad http://localhost:8813/activedirectory-mcp \
  --headers "Authorization: Bearer YOUR_AUTOMATION_TOKEN"
```

### 5. Connect from Gemini CLI

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

---

## Tools

All tools use the `ad_*` prefix. Tools marked as **Write** require a confirmation string OR an automation Bearer token.

### Tenant identification (3)

| Tool | Operation |
|---|---|
| `ad_get_client_tenant_info` | Return tenant info for this instance (call first) |
| `ad_list_configured_clients` | List all clients registered in the client registry |
| `ad_check_client_configuration` | Check if a given client slug has an AD configured |

### User management (9)

| Tool | Write | Operation |
|---|---|---|
| `ad_list_users_with_filters` | &mdash; | List users (optionally filtered by OU/criteria) |
| `ad_get_user_details_by_username` | &mdash; | Fetch user attributes by sAMAccountName |
| `ad_get_user_group_memberships` | &mdash; | List groups a user is member of |
| `ad_create_user_account` | yes | Create a new user |
| `ad_modify_user_attributes` | yes | Modify user attributes |
| `ad_delete_user_account_permanently` | yes | Delete a user |
| `ad_enable_user_account_access` | yes | Enable user account |
| `ad_disable_user_account_access` | yes | Disable user account |
| `ad_reset_user_password_forced` | yes | Reset password (force change on next login) |

### Group management (8)

| Tool | Write | Operation |
|---|---|---|
| `ad_list_groups_with_filters` | &mdash; | List groups |
| `ad_get_group_details_by_name` | &mdash; | Fetch group attributes |
| `ad_get_group_members_recursive` | &mdash; | List members, optionally recursive |
| `ad_create_group_security_or_distribution` | yes | Create security or distribution group |
| `ad_modify_group_attributes` | yes | Modify group attributes |
| `ad_delete_group_permanently` | yes | Delete a group |
| `ad_add_member_to_group` | yes | Add member |
| `ad_remove_member_from_group` | yes | Remove member |

### Computer management (8)

| Tool | Write | Operation |
|---|---|---|
| `ad_list_computers_with_filters` | &mdash; | List computers |
| `ad_get_computer_details_by_name` | &mdash; | Fetch computer attributes |
| `ad_get_inactive_computers_by_days` | &mdash; | List computers idle for N+ days |
| `ad_create_computer_account` | yes | Create computer object |
| `ad_modify_computer_attributes` | yes | Modify computer attributes |
| `ad_delete_computer_account_permanently` | yes | Delete computer object |
| `ad_enable_computer_account_trust` | yes | Enable computer account |
| `ad_disable_computer_account_trust` | yes | Disable computer account |
| `ad_reset_computer_password_trust` | yes | Reset computer secure-channel password |

### Organizational Unit management (7)

| Tool | Write | Operation |
|---|---|---|
| `ad_list_organizational_units_hierarchy` | &mdash; | List OUs (recursive option) |
| `ad_get_organizational_unit_details` | &mdash; | Fetch OU attributes |
| `ad_get_organizational_unit_objects` | &mdash; | List objects inside an OU |
| `ad_create_organizational_unit` | yes | Create OU |
| `ad_modify_organizational_unit_attributes` | yes | Modify OU |
| `ad_delete_organizational_unit_forced` | yes | Delete OU (force=true to delete non-empty) |
| `ad_move_organizational_unit_parent` | yes | Move OU to a new parent |

### Security & audit (6)

| Tool | Operation |
|---|---|
| `ad_get_domain_security_policy_info` | Domain info + password/lockout policy |
| `ad_get_privileged_security_groups` | List privileged groups (Domain Admins, Enterprise Admins, etc.) |
| `ad_get_user_effective_permissions` | Show effective permissions for a user |
| `ad_get_inactive_users_by_days` | Users with no logon for N+ days |
| `ad_get_password_policy_violations` | Accounts violating the password policy |
| `ad_audit_administrative_accounts` | Audit privileged account hygiene |

### MSP prompts (2 tools + 15 prompts)

| Tool | Operation |
|---|---|
| `ad_list_msp_prompts` | List the 15 professional MSP playbooks (manager & analyst) |
| `ad_execute_msp_prompt` | Execute a named playbook with arguments |

See [PROMPTS.md](PROMPTS.md) for the full prompt catalog (security audit, onboarding, offboarding, password reset playbook, etc.).

### System (4)

| Tool | Operation |
|---|---|
| `ad_test_ldap_connection_status` | LDAP connectivity probe |
| `ad_health_check_mcp_server` | Full health check (server + LDAP search test + stats) |
| `ad_get_mcp_schema_tools_info` | Self-describing schema of all registered tools |

---

## Configuration

The runtime configuration file path is provided via the `AD_MCP_CONFIG` environment variable. Schema in [`ad-config/ad-config.example.json`](ad-config/ad-config.example.json).

### Key fields

| Field | Required | Description |
|---|---|---|
| `active_directory.server` | yes | Primary LDAP URL, e.g. `ldaps://dc.example.com:636` |
| `active_directory.server_pool` | no | Additional LDAP URLs for failover |
| `active_directory.bind_dn` | yes | Full DN of the service account |
| `active_directory.password` | yes | Service account password (keep file at `chmod 600`) |
| `active_directory.base_dn` | yes | Base DN, e.g. `DC=example,DC=com` |
| `organizational_units.*` | yes | Default OUs for users/groups/computers/service accounts |
| `security.enable_tls` | no | Force StartTLS / LDAPS |
| `security.validate_certificate` | no | Verify server certificate against `ca_cert_file` |
| `security.require_secure_connection` | no | Refuse to bind over plaintext |
| `automation.token` | no | Bearer token for unattended write operations |
| `client.slug` | no | Tenant identifier reported by `ad_get_client_tenant_info` |

### Service account permissions

Grant the bind account the minimum delegated rights required by the operations you intend to expose:

- **Read-only deployments**: "Read all properties" + "List contents" on the domain root is enough.
- **User/group write**: delegate "Create/Delete objects" + "Write all properties" on the target OUs.
- **Password reset**: delegate the "Reset password" extended right on the target OUs.
- **Computer join/leave**: delegate "Create/Delete computer objects" on the computers OU.

Always use a dedicated service account, LDAPS in production, and rotate the password regularly.

---

## Security

### Write protection model

Every mutating tool (`ad_create_*`, `ad_modify_*`, `ad_delete_*`, `ad_enable_*`, `ad_disable_*`, `ad_reset_*`, `ad_add_*`, `ad_remove_*`, `ad_move_*`) calls `check_write_permission()` before reaching LDAP. It accepts the write if **one of**:

1. `automation_token` matches `automation.token` in the config &mdash; intended for CI / scheduled jobs.
2. `client_confirmation` matches the tenant slug &mdash; the AI assistant must call `ad_get_client_tenant_info` first, read the slug back to the user, and pass that exact string.
3. The tenant has `require_confirmation_for_writes: false` (explicit opt-out, not recommended).

If none of the above is satisfied, the call short-circuits with a `permitted: false` message and the LDAP write is never attempted.

### Audit logging

All operations write a structured log line including: timestamp, tool name, target, confirmation mode (`AUTOMATION` / `CONFIRMED` / `WRONG_CONFIRMATION` / `NO_CONFIRMATION_REQUIRED`), and success/failure. Logs go wherever `logging.file` points.

### Secrets hygiene

- Real `ad-config.json` files are git-ignored. Only `*.example.json` is tracked.
- Never paste a config containing a real `password` or `automation.token` into a chat that's logged or transcribed by a third party.
- Rotate `automation.token` whenever you regenerate it; treat it as a privileged credential.

---

## Testing

```bash
# Unit + integration tests
pytest tests/ -v

# Coverage
pytest --cov=src --cov-report=term-missing

# Lint
ruff check .
```

A bundled `docker-compose-ad.yml` spins up a Samba AD container at `192.168.1.100` plus an MCP container so the integration tests can run against a real LDAP backend without touching production.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `LDAP bind failed` | bad `bind_dn` / `password` | Verify against `ldapsearch -H <server> -D '<bind_dn>' -W` |
| `Insufficient permissions` | service account lacks delegated rights | Re-delegate on the target OU |
| `Certificate verification failed` | self-signed cert without trust | Set `ca_cert_file` or `validate_certificate: false` (test only) |
| `permitted: false` on every write | Missing confirmation/token | Call `ad_get_client_tenant_info` first, or pass `automation_token` |
| `Health degraded` | socket open but LDAP search failed | Check service-account lockout / replication / network ACLs |

---

## Contributing

1. Fork the repo.
2. Create a feature branch: `git checkout -b feat/your-feature`.
3. Run tests: `pytest`.
4. Open a PR with a clear description and a link to the relevant issue.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/).

---

## License

MIT &mdash; see [LICENSE](LICENSE).

## Acknowledgments

- Based on the upstream [`alpadalar/ActiveDirectoryMCP`](https://github.com/alpadalar/ActiveDirectoryMCP) project by Alperen Adalar.
- Built on top of [`mcp`](https://github.com/modelcontextprotocol/python-sdk), [`fastmcp`](https://github.com/jlowin/fastmcp), [`ldap3`](https://github.com/cannatag/ldap3), and FastAPI.

## Support

- Bug reports: [GitHub Issues](https://github.com/DevSkillsIT/Skills-MCP-AD/issues)
- Discussions: [GitHub Discussions](https://github.com/DevSkillsIT/Skills-MCP-AD/discussions)
