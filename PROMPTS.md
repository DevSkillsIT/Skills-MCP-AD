# Active Directory MCP &mdash; Professional Prompts

## Overview

This MCP ships with **15 professional MSP prompts** &mdash; multi-step playbooks that help AI assistants execute auditing, compliance, troubleshooting, onboarding and offboarding tasks against Active Directory.

**Module:** `tools/prompts.py`
**Listed via:** `ad_list_msp_prompts`
**Executed via:** `ad_execute_msp_prompt`

---

## Architecture

### Multi-step aware

Each prompt returns a structured set of instructions that guide the AI through several steps:

1. **Identifier resolution** (e.g. username -> user DN) when needed.
2. **LDAP queries** using the existing read tools.
3. **Result formatting** in compact (for chat) or detailed (for audit/compliance) form.

### Dual format

Each prompt returns instructions in **two formats**:

- **Compact** &mdash; fast, single-screen answers for daily ops.
- **Detailed** &mdash; full executive report for audit, compliance and complex troubleshooting.

---

## Categories

### Managers (7 prompts)

Focused on auditing, compliance, planning and optimization.

| Name | Description | Arguments |
|---|---|---|
| `ad_security_audit` | Full AD security audit | `include_disabled` (optional) |
| `ad_user_growth_trends` | User growth analysis for capacity planning | `period_months` (default: 6) |
| `ad_group_policy_compliance` | GPO compliance verification | `policy_type` (optional) |
| `ad_privileged_access_review` | Privileged access review (SOC2 / ISO27001) | `group_filter` (optional) |
| `ad_password_policy_health` | Password policy health check | `check_expiration` (default: true) |
| `ad_inactive_account_report` | Inactive account report for cleanup | `inactive_days` (default: 90) |
| `ad_licensing_optimization` | M365 licensing optimization | `license_type` (optional) |

### Analysts (8 prompts)

Focused on support, troubleshooting and daily operations.

| Name | Description | Arguments |
|---|---|---|
| `ad_user_lookup` | Quick user lookup for support | `search_term` (required) |
| `ad_password_reset_guide` | Password reset playbook with safety checks | `username` (required) |
| `ad_user_onboarding` | New user onboarding checklist | `username`, `template_user` (optional) |
| `ad_user_offboarding` | Secure offboarding checklist | `username` (required) |
| `ad_group_membership_check` | Group membership troubleshooting | `username` (required) |
| `ad_account_unlock` | Account unlock with validations | `username` (required) |
| `ad_permission_troubleshooting` | Access permission troubleshooting | `username`, `resource_path` (optional) |
| `ad_computer_join_guide` | Domain-join guide | `computer_name` (required) |

---

## Usage

### List available prompts

```bash
curl -X POST http://localhost:8813/activedirectory-mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": { "name": "ad_list_msp_prompts", "arguments": {} },
    "id": 1
  }'
```

### Execute a specific prompt

#### Example 1: Security audit (manager)

```bash
curl -X POST http://localhost:8813/activedirectory-mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "ad_execute_msp_prompt",
      "arguments": {
        "name": "ad_security_audit",
        "arguments": { "include_disabled": false }
      }
    },
    "id": 1
  }'
```

What happens:

1. The AI receives detailed instructions to run the audit.
2. The AI calls `ad_list_users_with_filters`, password audit tools and `ad_list_groups_with_filters` (privileged groups) automatically.
3. The AI consolidates results into an executive report.

#### Example 2: User lookup (analyst)

```bash
curl -X POST http://localhost:8813/activedirectory-mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "ad_execute_msp_prompt",
      "arguments": {
        "name": "ad_user_lookup",
        "arguments": { "search_term": "jdoe" }
      }
    },
    "id": 1
  }'
```

What happens:

1. The AI gets the user-lookup instructions.
2. The AI calls `ad_get_user_details_by_username("jdoe")` and `ad_get_user_group_memberships("jdoe")`.
3. The AI returns a compact info card.

#### Example 3: Password reset (analyst)

```bash
curl -X POST http://localhost:8813/activedirectory-mcp \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_TOKEN' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "ad_execute_msp_prompt",
      "arguments": {
        "name": "ad_password_reset_guide",
        "arguments": { "username": "jdoe" }
      }
    },
    "id": 1
  }'
```

What happens:

1. The AI receives the pre-reset safety checklist.
2. The AI validates the account with `ad_get_user_details_by_username("jdoe")`.
3. The AI executes `ad_reset_user_password_forced` with `force_change=true`.
4. The AI generates user-facing guidance.

---

## Multi-tenant integration

The prompts are tenant-aware. If you run multiple MCP instances (one per tenant), each instance executes the playbook against its own AD &mdash; no extra parameter is needed.

```json
{
  "mcpServers": {
    "ad-tenant-a": {
      "type": "streamable-http",
      "url": "http://ad-mcp.internal:8821/activedirectory-mcp",
      "headers": { "Authorization": "Bearer TOKEN_TENANT_A" }
    },
    "ad-tenant-b": {
      "type": "streamable-http",
      "url": "http://ad-mcp.internal:8822/activedirectory-mcp",
      "headers": { "Authorization": "Bearer TOKEN_TENANT_B" }
    }
  }
}
```

---

## Use cases

### Monthly security audit (manager)

```
Prompt: ad_security_audit
Frequency: monthly
Output: executive report with critical findings and action plan
Compliance: SOC2, ISO27001, CIS Benchmarks
```

### Capacity planning (manager)

```
Prompt: ad_user_growth_trends + ad_licensing_optimization
Frequency: quarterly
Output: growth analysis, projections, licensing savings estimate
```

### Helpdesk ticket - password (analyst)

```
Prompt: ad_user_lookup -> ad_password_reset_guide
Frequency: daily (multiple times)
Output: safe reset with validations and user-facing instructions
```

### Employee onboarding (analyst)

```
Prompt: ad_user_onboarding
Frequency: weekly
Output: full checklist with account created and groups assigned
```

### Secure offboarding (analyst)

```
Prompt: ad_user_offboarding
Frequency: weekly
Output: account disabled, group memberships removed, OU quarantined
Compliance: LGPD, GDPR (90-day retention)
```

---

## Troubleshooting

### "Prompt not found"

**Cause:** typo in the prompt name.
**Fix:** call `ad_list_msp_prompts` to get the canonical list.

### "Required argument missing"

**Cause:** required argument not provided.
**Fix:** consult the table above for the prompt's required arguments.

### "Prompt returns instructions but does not execute"

**Cause:** this is the expected behavior &mdash; prompts return **instructions** for the AI to execute.
**Fix:** the AI client (Claude / Gemini) will call the referenced tools automatically as it reads the instructions.

---

## Roadmap

### v0.3.0 (planned)

- GPO analysis prompt (Group Policy Objects)
- AD replication health prompt
- Domain trust troubleshooting prompt
- Dangerous-delegation analysis prompt
- Context7 integration for Microsoft docs lookups

### v0.4.0 (future)

- Azure AD / Entra ID sync prompts
- User migration prompts
- Disaster recovery prompts
- Per-tenant response templates

---

**Module version:** 0.2.1
**Protocol:** Streamable HTTP (MCP 2024-11-05)
