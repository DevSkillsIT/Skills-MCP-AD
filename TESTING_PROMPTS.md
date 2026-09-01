# Testing the MSP Prompts

End-to-end test plan for the 15 MSP prompts exposed via the MCP `prompts/list` and `prompts/get` methods.

## Prerequisites

- The MCP server is running over the Streamable HTTP transport (`server_fastapi.py`) &mdash; the stdio transport (`server.py`) does not expose these prompts.
- A tenant `ad-config.json` is configured and the server can reach LDAP.
- You have a Bearer token if `AD_MCP_API_TOKEN` is set for the instance.

> Throughout this document we use `https://ad-mcp.example.com:8820/mcp` as the endpoint and `YOUR_TOKEN` as the Bearer. Replace both with your real values. Prompts are invoked with the MCP `prompts/list` and `prompts/get` JSON-RPC methods, not with `tools/call` &mdash; there is no `ad_list_msp_prompts` or `ad_execute_msp_prompt` tool.

---

## 1. Health check

```bash
curl -X POST https://ad-mcp.example.com:8820/mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": { "name": "ad_health_check_mcp_server", "arguments": {} },
    "id": 1
  }'
```

Expected: `status: ok`, `ldap_connection: connected` (single mode) &mdash; the field is `ldap_connection`, not `ldap_verified`.

## 2. List available prompts

```bash
curl -X POST https://ad-mcp.example.com:8820/mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -d '{
    "jsonrpc": "2.0",
    "method": "prompts/list",
    "params": {},
    "id": 1
  }'
```

Expected: `prompts` is a flat array of 15 entries (7 manager + 8 analyst, see below); the response carries no `total` or category field of its own.

---

## 3. Manager prompts

Every call below uses `"method": "prompts/get"`; the ellipsis (`...`) in later sections stands in for the `"name"` / `"arguments"` pair inside `"params"`, following the full example in 3.1.

### 3.1 `ad_security_audit`

```bash
curl -X POST https://ad-mcp.example.com:8820/mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -d '{
    "jsonrpc": "2.0",
    "method": "prompts/get",
    "params": {
      "name": "ad_security_audit",
      "arguments": { "include_disabled": false }
    },
    "id": 1
  }'
```

Expected: instructions reference `ad_get_inactive_users_by_days`, `ad_get_password_policy_violations`, `ad_get_privileged_security_groups`, `ad_audit_administrative_accounts`.

### 3.2 `ad_user_growth_trends`

```bash
... "name": "ad_user_growth_trends", "arguments": { "period_months": 6 } ...
```

Expected: instructions reference `ad_list_users_with_filters` for current and historical counts.

### 3.3 `ad_group_policy_compliance`

```bash
... "name": "ad_group_policy_compliance", "arguments": {} ...
```

Expected: instructions for GPO inventory and per-OU compliance check.

### 3.4 `ad_privileged_access_review`

```bash
... "name": "ad_privileged_access_review", "arguments": {} ...
```

Expected: instructions reference `ad_get_privileged_security_groups` and `ad_get_group_members_recursive`.

### 3.5 `ad_password_policy_health`

```bash
... "name": "ad_password_policy_health", "arguments": { "check_expiration": true } ...
```

Expected: instructions reference `ad_get_domain_security_policy_info` + `ad_get_password_policy_violations`.

### 3.6 `ad_inactive_account_report`

```bash
... "name": "ad_inactive_account_report", "arguments": { "inactive_days": 90 } ...
```

Expected: instructions reference `ad_get_inactive_users_by_days` and `ad_get_inactive_computers_by_days`.

### 3.7 `ad_licensing_optimization`

```bash
... "name": "ad_licensing_optimization", "arguments": {} ...
```

Expected: instructions for user inventory cross-referenced with M365 licensing.

---

## 4. Analyst prompts

### 4.1 `ad_user_lookup`

```bash
... "name": "ad_user_lookup", "arguments": { "search_term": "jdoe" } ...
```

Expected: instructions to call `ad_get_user_details_by_username` and `ad_get_user_group_memberships`.

### 4.2 `ad_password_reset_guide`

```bash
... "name": "ad_password_reset_guide", "arguments": { "username": "jdoe" } ...
```

Expected: pre-reset safety checks, then `ad_reset_user_password_forced` with `force_change=true`.

### 4.3 `ad_user_onboarding`

```bash
... "name": "ad_user_onboarding", "arguments": { "username": "jdoe", "template_user": "template-finance" } ...
```

Expected: checklist with `ad_create_user_account` + `ad_add_member_to_group` referencing the template.

### 4.4 `ad_user_offboarding`

```bash
... "name": "ad_user_offboarding", "arguments": { "username": "jdoe" } ...
```

Expected: instructions for `ad_disable_user_account_access`, group removal via `ad_remove_member_from_group`, OU move.

### 4.5 `ad_group_membership_check`

```bash
... "name": "ad_group_membership_check", "arguments": { "username": "jdoe" } ...
```

Expected: instructions to call `ad_get_user_group_memberships`.

### 4.6 `ad_account_unlock`

```bash
... "name": "ad_account_unlock", "arguments": { "username": "jdoe" } ...
```

Expected: instructions to call `ad_get_user_details_by_username` then `ad_modify_user_attributes` with `lockoutTime=0`.

### 4.7 `ad_permission_troubleshooting`

```bash
... "name": "ad_permission_troubleshooting", "arguments": { "username": "jdoe" } ...
```

Expected: instructions to call `ad_get_user_effective_permissions` + `ad_get_user_group_memberships`.

### 4.8 `ad_computer_join_guide`

```bash
... "name": "ad_computer_join_guide", "arguments": { "computer_name": "WS01" } ...
```

Expected: instructions to call `ad_create_computer_account("WS01")` first, with troubleshooting via `ad_get_computer_details_by_name`.

---

## 5. Negative tests

### 5.1 Unknown prompt name

```bash
... "method": "prompts/get", "params": { "name": "ad_nonexistent" } ...
```

Expected: a JSON-RPC `error` object (protocol-level failure, e.g. code `-32000`) with message `Prompt não encontrado: ad_nonexistent` &mdash; not a normal `result`.

### 5.2 Missing required argument

```bash
... "method": "prompts/get", "params": { "name": "ad_user_lookup", "arguments": {} } ...
```

Expected: a normal `result` (not a JSON-RPC error) whose message text is JSON with `success: false` and an `error` string naming the missing parameter (`search_term`).

### 5.3 Write tool without confirmation

```bash
curl -X POST https://ad-mcp.example.com:8820/mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "ad_create_user_account",
      "arguments": {
        "username": "test.user",
        "password": "Temp@2026",
        "first_name": "Test",
        "last_name": "User"
      }
    },
    "id": 1
  }'
```

Expected: `permitted: false` with a message asking either for `client_confirmation` matching the tenant slug, or `automation_token`.

---

## 6. Multi-tenant smoke test

Run the same `ad_get_client_tenant_info` request against each tenant endpoint and confirm the returned `client.slug` matches the tenant you expect.

```bash
# Tenant A
curl -X POST https://ad-mcp.example.com:8821/mcp \
  -H 'Authorization: Bearer TOKEN_TENANT_A' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ad_get_client_tenant_info","arguments":{}},"id":1}'

# Tenant B
curl -X POST https://ad-mcp.example.com:8822/mcp \
  -H 'Authorization: Bearer TOKEN_TENANT_B' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ad_get_client_tenant_info","arguments":{}},"id":1}'
```

Each instance must return its own slug and domain &mdash; no leakage between tenants. This checks the "one process per tenant" (single mode) deployment; for a single `multi`-mode instance serving several directories, run `tests/test_smoke_ao_vivo.py` instead (see [TESTING_GUIDE.md](TESTING_GUIDE.md)).

---

## 7. Acceptance checklist

- [ ] Health check passes (`ldap_connection: connected`).
- [ ] `prompts/list` returns all 15 prompts.
- [ ] All 7 manager prompts return well-formed instructions referencing `ad_*` tools.
- [ ] All 8 analyst prompts return well-formed instructions referencing `ad_*` tools.
- [ ] Unknown prompt name fails as a JSON-RPC `error`.
- [ ] Required-argument validation rejects empty calls with a `success: false` result naming the missing argument.
- [ ] Write protection rejects mutating calls without confirmation/token.
- [ ] Multi-tenant smoke test returns the correct slug for each port.
