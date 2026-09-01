# Changelog &mdash; MSP Prompts

## [Unreleased] - 2026-09-01

### Changed

- **Prompts moved to the MCP prompts protocol.** The `ad_list_msp_prompts` and `ad_execute_msp_prompt` tools are gone; the 15 MSP prompts are now served through the standard `prompts/list` and `prompts/get` JSON-RPC methods (`server_fastapi.py` only &mdash; the stdio transport, `server.py`, does not register them). `prompts/list` returns a flat `{"prompts": [...]}` array; the manager/analyst split documented in `PROMPTS.md` is a documentation grouping, not a field in the response.
- **New in-process multi-AD mode.** `AD_MCP_MODE=multi` (via `AD_MCP_SERVERS`) lets one `server_fastapi.py` process serve several directories. Every directory-bound tool gains an `ad_server` parameter (required on writes, optional on reads &mdash; omitted or `all`/`todos` fans a read out to every directory); `prompts/get` accepts the same `ad_server` inside `arguments`. `ad_list_configured_clients` and `ad_check_client_configuration` are replaced by `ad_list_ad_servers` and `ad_check_ad_server_configured` in this mode; `ad_get_client_tenant_info` stays, now taking `ad_server` like every other directory-bound tool instead of describing "the" tenant. `AD_MCP_MODE=single` (the previous, unchanged behavior) remains the default.
- **`server_http.py` removed.** The FastMCP-based HTTP transport (port 8813, path `/activedirectory-mcp`) no longer exists; `server_fastapi.py` (default port 8820, fixed path `/mcp`) is the only HTTP transport. `start-http.sh` and `start_http_server.sh` were removed with it.
- **`core/client_registry.py` removed.** It read a separate JSON registry (`shared/configs/ad-clients-registry.json`) that had drifted out of sync with the tenants actually deployed; multi-AD routing now goes through `core/ad_pool.py` and `config/multi_loader.py`, which read the same `ad-servers.json` the process is actually started with.
- **Six audit stub tools removed** (`analyze_permissions`, `detect_privilege_escalation`, `check_service_accounts`, `find_weak_passwords`, `get_ou_permissions`, `delegate_ou_control`): they fabricated audit data rather than querying LDAP.
- **`test_scripts/` replaced by `tests/test_smoke_ao_vivo.py`**, a pytest-native live smoke test that self-skips unless `AD_MCP_API_TOKEN` is exported and the target instance answers.
- Several LDAP-facing correctness bugs fixed in the tools the prompts drive (measured live before the fix): a `ldap3` `search()` result treated as a failure when it was actually "no match" (an admins audit under-reported group membership), a case-sensitive `"HIGH"` vs `"high"` risk-level comparison that misfired every high-risk security recommendation, `datetime`-vs-`int` comparisons on `pwdLastSet`/`accountExpires` that hid expired accounts, a filetime fallback that reported unreadable timestamps as "logged in just now" instead of unknown, OU creation reading a non-existent config key (organizational unit defaults silently never applied), swapped arguments to a response formatter that returned the literal string `"True"`, and `get_ou_statistics` reading the wrong dict keys (always zero).

### Removed

- `scripts/install-client.sh`, `scripts/migrate-to-shared.sh`.

## [0.2.2]

### Changed

- **Tool naming unification.** All MCP tool names across `server.py`, `server_http.py` and `server_fastapi.py` now use the `ad_*` prefix with descriptive suffixes (e.g. `ad_list_users_with_filters`, `ad_get_user_details_by_username`). The two MSP prompt entrypoints renamed: `list_prompts` -> `ad_list_msp_prompts`, `get_prompt` -> `ad_execute_msp_prompt`.
- **Internal prompt instructions updated.** All 22 references inside `tools/prompts.py` that pointed at old tool names (`list_users`, `create_user`, `get_user_groups`, etc.) now reference the canonical `ad_*` names so the AI calls the right tool.
- **Audit log labels aligned.** `_check_write_permission()` operation labels and `_format_response()` operation labels now match the public tool name verbatim.

### Removed

- Vendor-specific branding from source headers, docstrings and shell scripts.
- Hard-coded tenant identifiers in examples; replaced with generic placeholders (`tenant-a`, `tenant-b`, `example-client`).
- `ad-config/ad-config.json` removed from version control. `.gitignore` now blocks `ad-config/*.json` and only allows `*.example.json`.
- Internal audit artifacts dropped from the repo (relatorios, baselines, audit mapping scripts, root-level test duplicates, backup files).

### Added

- Consolidated `ad-config/ad-config.example.json` (single template with TLS + automation token fields).
- `HTTP_MCP_GUIDE.md` rewritten in English for community use (reverse-proxy snippet, transport comparison, smoke tests).
- `TESTING_GUIDE.md` rewritten in English (unit / integration / live smoke test recipes).

---

## [0.2.1] - 2025-12-11

### Added &mdash; Professional MSP prompt system

Implementation of **15 specialized MSP prompts** as multi-step playbooks for AI assistants.

**Architecture:**

- Multi-step aware (identifier resolution -> LDAP lookups -> result formatting)
- Dual format (compact for fast ops, detailed for audit/compliance)
- Tenant-aware (each MCP instance executes the playbook against its own AD)
- MCP protocol 2024-11-05 over Streamable HTTP

**New files:**

- `src/active_directory_mcp/tools/prompts.py` &mdash; the 15 prompts
- `PROMPTS.md` &mdash; usage docs
- `TESTING_PROMPTS.md` &mdash; test plan

**New MCP tools:**

- `ad_list_msp_prompts` &mdash; lists the available playbooks
- `ad_execute_msp_prompt(name, arguments)` &mdash; executes a named playbook

**7 manager prompts:**

1. `ad_security_audit` &mdash; full AD security audit (inactive accounts, password issues, privileged groups)
2. `ad_user_growth_trends` &mdash; user growth analysis for capacity planning
3. `ad_group_policy_compliance` &mdash; GPO compliance verification
4. `ad_privileged_access_review` &mdash; privileged access review (SOC2 / ISO27001)
5. `ad_password_policy_health` &mdash; password policy health check
6. `ad_inactive_account_report` &mdash; inactive account cleanup
7. `ad_licensing_optimization` &mdash; M365 licensing optimization

**8 analyst prompts:**

1. `ad_user_lookup` &mdash; quick user lookup
2. `ad_password_reset_guide` &mdash; safe password reset playbook
3. `ad_user_onboarding` &mdash; new user onboarding checklist
4. `ad_user_offboarding` &mdash; secure offboarding
5. `ad_group_membership_check` &mdash; membership troubleshooting
6. `ad_account_unlock` &mdash; account unlock
7. `ad_permission_troubleshooting` &mdash; access permission troubleshooting
8. `ad_computer_join_guide` &mdash; domain-join guide

### Changed

- `server_http.py` and `server_fastapi.py` register the new prompt tools alongside the existing CRUD tool set.
- `__init__.py` keeps version at `0.2.1`.

### Testing

- Manual end-to-end via curl against the HTTP server (see `TESTING_PROMPTS.md`).
- All 15 prompts validated against a Samba AD test container.

### Compatibility

- 100% backwards compatible with existing read/write tools.
- Multi-tenant aware &mdash; no extra parameter required to switch tenants; the right MCP instance handles routing.

### Performance

- Prompt instructions generated in-memory; no LDAP impact when calling `ad_list_msp_prompts`.
- Each prompt's downstream LDAP calls are bounded by the existing pagination (`page_size: 1000` default).

### Compliance mapping

| Framework | Covered by |
|---|---|
| SOC2 Type II | `ad_security_audit`, `ad_privileged_access_review` |
| ISO 27001 | `ad_security_audit`, `ad_password_policy_health` |
| LGPD / GDPR | `ad_user_offboarding` |
| CIS Benchmarks | `ad_group_policy_compliance` |

---

## [0.2.0] - 2025-12

### Added &mdash; Multi-tenant write protection

- `client_security.py` &mdash; per-tenant write protection: `check_write_permission()` accepts an automation token OR a tenant slug confirmation before allowing any mutating LDAP write.
- `client_registry.py` &mdash; runtime registry of configured tenants.
- `ad_get_client_tenant_info` &mdash; returns current tenant identity (slug, domain, base DN).
- `ad_list_configured_clients` &mdash; lists all tenants known to the registry.
- `ad_check_client_configuration(client_name)` &mdash; verify a tenant slug exists.

### Notes

- Write tools that previously executed without a guard now require either:
  - `automation_token` matching `automation.token` in the tenant config, OR
  - `client_confirmation` matching the tenant `client.slug`.
- The audit log records the chosen mode on every call.

---

## [0.1.0] - initial

Initial fork of [`alpadalar/ActiveDirectoryMCP`](https://github.com/alpadalar/ActiveDirectoryMCP) with the original tool set: user / group / computer / OU CRUD, plus basic audit and security tools.
