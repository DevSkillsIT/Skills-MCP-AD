# Changelog &mdash; MSP Prompts

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
