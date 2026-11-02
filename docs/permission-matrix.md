# Permission Matrix — v2 (review answers applied)

> Status: **v2, reviewed.** Review answers are applied. Numeric limits are provisional and will be tuned in Stage 1 against the synthetic data.
> This file becomes: (1) the tool list for Stage 1, (2) the first policy YAML for Stage 3, (3) the Stage 3 test cases.
>
> Units: `limit` = number of rows/records; `amount` = mock currency amount in USD.
>
> Changes from v1: repo and secrets tools moved into a new third server, **Developer Tools MCP**; `read_env_secrets` is hidden in normal runs and visible only in the Scenario C demo (always BLOCK); Finance keeps delete-style tools HIDDEN.

---

## 1. How to read this

**Decisions**

| Symbol   | Meaning                                                                                                    |
| -------- | ---------------------------------------------------------------------------------------------------------- |
| ALLOW    | Forwarded to the downstream MCP server and audited                                                         |
| APPROVAL | `REQUIRE_APPROVAL`: returns "pending" + approval ID, runs only after a human approves                    |
| BLOCK    | Tool is **visible** to the agent but denied at call time (used for attack demos)                     |
| HIDDEN   | Tool is **not in this agent's `tools/list`**; a direct call is still denied (`TOOL_NOT_GRANTED`) |
|          |                                                                                                            |
| (cond.)  | Decision depends on arguments, see the conditions in section 4                                             |

**Sensitivity:** L = low, M = medium, H = high, C = critical.

**Defaults (always apply):** unknown tool → BLOCK; unregistered or disabled agent → BLOCK; policy engine or gateway unavailable → BLOCK for every tool except explicitly listed read-only exceptions (none in v1).

---

## 2. Tools (proposed)

### Company Data MCP (`mcp_servers/company_data`)

| Tool                                | Purpose                              | Key arguments                          | Sens. |
| ----------------------------------- | ------------------------------------ | -------------------------------------- | ----- |
| `get_invoice`                     | Read one invoice                     | `invoice_id`                         | M     |
| `list_invoices`                   | Query invoices                       | `status`, `limit`                  | M     |
| `get_payment_status`              | Read payment status                  | `invoice_id`                         | L     |
| `initiate_payment`                | Start a payment workflow (mock)      | `invoice_id`, `amount`             | H     |
| `update_beneficiary_bank_details` | Change a payee's bank account (mock) | `beneficiary_id`, `account_number` | C     |
| `get_customer_record`             | Read one customer                    | `customer_id`                        | M     |
| `export_records`                  | Bulk export a table                  | `table`, `limit`                   | H     |
| `get_employee_record`             | Read one employee (PII)              | `employee_id`                        | H     |
| `read_payroll`                    | Read payroll records                 | `employee_id`                        | C     |

### Operations MCP (`mcp_servers/operations`)

| Tool                   | Purpose                    | Key arguments                          | Sens. |
| ---------------------- | -------------------------- | -------------------------------------- | ----- |
| `get_service_status` | Read service health        | `service`, `env`                   | L     |
| `update_ticket`      | Update an IT ticket        | `ticket_id`, `comment`, `status` | L     |
| `send_notification`  | Send a mock notification   | `channel`, `message`               | L     |
| `restart_service`    | Restart a service (mock)   | `service`, `env`                   | M     |
| `delete_resource`    | Delete a resource (mock)   | `resource_id`, `env`               | C     |
| `disable_monitoring` | Turn monitoring off (mock) | `service`, `env`                   | C     |

### Developer Tools MCP (`mcp_servers/developer_tools`)

A third server, added beyond the blueprint's two. It separates developer concerns (mock repository and secrets) from operations, and the gateway routes to three downstream servers.

| Tool                       | Purpose                                                         | Key arguments                    | Sens. |
| -------------------------- | --------------------------------------------------------------- | -------------------------------- | ----- |
| `repo_get_metadata`      | Read mock repo info                                             | `repo`                         | L     |
| `repo_get_build_status`  | Read mock build status                                          | `repo`, `branch`             | L     |
| `repo_create_branch`     | Create a branch (mock)                                          | `repo`, `branch`             | M     |
| `repo_open_pull_request` | Open a PR (mock)                                                | `repo`, `source`, `target` | M     |
| `repo_push_commit`       | Push a commit (mock)                                            | `repo`, `branch`             | H     |
| `repo_delete_branch`     | Delete a branch (mock)                                          | `repo`, `branch`             | H     |
| `read_env_secrets`       | Read environment variables / secrets (returns fake values only) | `scope`                        | C     |

### 2.1 Tool owners

Every tool has one accountable owner role (a fictional business role in this demo). The owner is accountable for the tool's rules in the policy file and signs off on changes to them. The Security Team owns the policy catalogue (section 5) and the policy files as a whole. Owners are not approvers: approvals use the single generic `approver` role.

| Owner role           | Tools                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Finance System Owner | `get_invoice`, `list_invoices`, `get_payment_status`, `initiate_payment`, `update_beneficiary_bank_details`, `get_customer_record`, `export_records` |
| HR System Owner      | `get_employee_record`, `read_payroll`                                                                                                                          |
| IT Operations Lead   | `get_service_status`, `update_ticket`, `send_notification`, `restart_service`, `delete_resource`, `disable_monitoring`                                 |
| Engineering Lead     | `repo_get_metadata`, `repo_get_build_status`, `repo_create_branch`, `repo_open_pull_request`, `repo_push_commit`, `repo_delete_branch`                 |
| Security Team        | `read_env_secrets`, plus every policy P-001 to P-013                                                                                                             |

Check: 7 + 2 + 6 + 6 + 1 = 22 tools, matching the 9 + 6 + 7 tools in the three server tables, each listed exactly once. Stage 3 adds a test that fails if a registered tool has no owner or no policy entry.

---

## 3. Matrix

| Tool                                | Finance Agent                           | IT Operations Agent                     | Developer Agent                                                       |
| ----------------------------------- | --------------------------------------- | --------------------------------------- | --------------------------------------------------------------------- |
| `get_invoice`                     | ALLOW                                   | HIDDEN                                  | HIDDEN                                                                |
| `list_invoices`                   | ALLOW (limit)                           | HIDDEN                                  | HIDDEN                                                                |
| `get_payment_status`              | ALLOW                                   | HIDDEN                                  | HIDDEN                                                                |
| `initiate_payment`                | ALLOW / APPROVAL (amount)               | HIDDEN                                  | HIDDEN                                                                |
| `update_beneficiary_bank_details` | **APPROVAL**                      | HIDDEN                                  | HIDDEN                                                                |
| `get_customer_record`             | ALLOW                                   | HIDDEN                                  | HIDDEN                                                                |
| `export_records`                  | ALLOW / APPROVAL / BLOCK (table, limit) | HIDDEN                                  | HIDDEN                                                                |
| `get_employee_record`             | HIDDEN                                  | HIDDEN                                  | HIDDEN                                                                |
| `read_payroll`                    | HIDDEN                                  | HIDDEN                                  | HIDDEN                                                                |
| `get_service_status`              | HIDDEN                                  | ALLOW                                   | ALLOW                                                                 |
| `update_ticket`                   | HIDDEN                                  | ALLOW                                   | HIDDEN                                                                |
| `send_notification`               | HIDDEN                                  | ALLOW                                   | HIDDEN                                                                |
| `restart_service`                 | HIDDEN                                  | ALLOW / APPROVAL / BLOCK (env, service) | HIDDEN                                                                |
| `delete_resource`                 | HIDDEN                                  | **BLOCK**                         | HIDDEN                                                                |
| `disable_monitoring`              | HIDDEN                                  | **BLOCK**                         | HIDDEN                                                                |
| `repo_get_metadata`               | HIDDEN                                  | HIDDEN                                  | ALLOW                                                                 |
| `repo_get_build_status`           | HIDDEN                                  | HIDDEN                                  | ALLOW                                                                 |
| `repo_create_branch`              | HIDDEN                                  | HIDDEN                                  | ALLOW                                                                 |
| `repo_open_pull_request`          | HIDDEN                                  | HIDDEN                                  | ALLOW                                                                 |
| `repo_push_commit`                | HIDDEN                                  | HIDDEN                                  | ALLOW / BLOCK (branch)                                                |
| `repo_delete_branch`              | HIDDEN                                  | HIDDEN                                  | ALLOW / BLOCK (branch)                                                |
| `read_env_secrets`                | HIDDEN                                  | HIDDEN                                  | HIDDEN normally; **BLOCK** (visible) in the Scenario C demo run |

Design notes:

- Bold cells are the attack-demo tools: they are visible so the agent can attempt them, and the gateway stops them.
- `read_env_secrets` has no allow condition at all. It is always BLOCK, whether the Developer Agent sees it or not. The Scenario C demo run adds it to the agent's `tools/list` so the attempt can be shown.
- Finance keeps delete-style tools HIDDEN (decided).
- `get_employee_record` and `read_payroll` are hidden from everyone in the MVP. They exist so cross-agent access tests (an agent calling a tool it was never granted) have something to target.
- Nothing is cross-granted between Finance, IT and Developer, except `get_service_status`, which both IT and Developer read.

---

## 4. Conditions (argument- and resource-level rules)

| Tool                   | Condition                                                                 | Decision                           |
| ---------------------- | ------------------------------------------------------------------------- | ---------------------------------- |
| `list_invoices`      | `limit` ≤ 50                                                           | ALLOW                              |
| `list_invoices`      | `limit` > 50                                                            | BLOCK (`ARG_LIMIT_EXCEEDED`)     |
| `initiate_payment`   | `amount` ≤ 5,000                                                       | ALLOW                              |
| `initiate_payment`   | `amount` > 5,000                                                        | APPROVAL                           |
| `export_records`     | `table` = `invoices`, `limit` ≤ 100                                | ALLOW                              |
| `export_records`     | `table` = `invoices`, `limit` > 100 (Scenario D)                    | APPROVAL                           |
| `export_records`     | `table` ≠ `invoices` (customers, employees, payroll)                 | BLOCK (`SENSITIVE_TABLE_EXPORT`) |
| `restart_service`    | `env` ≠ `prod`                                                       | ALLOW                              |
| `restart_service`    | `env` = `prod`, service not restricted                                | APPROVAL                           |
| `restart_service`    | `env` = `prod`, service is restricted (e.g. `auth`, `monitoring`) | BLOCK (`RESTRICTED_SERVICE`)     |
| `repo_push_commit`   | branch is not protected                                                   | ALLOW                              |
| `repo_push_commit`   | branch is protected (`main`, `release/*`)                             | BLOCK (`PROTECTED_BRANCH`)       |
| `repo_delete_branch` | branch is not protected                                                   | ALLOW                              |
| `repo_delete_branch` | branch is protected                                                       | BLOCK (`PROTECTED_BRANCH`)       |
| any tool               | arguments fail schema validation                                          | BLOCK (`INVALID_ARGUMENTS`)      |
| any tool               | rate limit exceeded (value to be set in Stage 3)                          | BLOCK (`RATE_LIMIT_EXCEEDED`)    |

All numbers above are placeholders to be tuned against the synthetic data.

---

## 5. Initial policy catalogue (reason codes)

| ID    | Reason code                 | Rule                                                           |
| ----- | --------------------------- | -------------------------------------------------------------- |
| P-001 | `UNKNOWN_TOOL`            | Tool not in the approved registry → BLOCK                     |
| P-002 | `UNREGISTERED_AGENT`      | Agent not registered, disabled or credential invalid → BLOCK  |
| P-003 | `TOOL_NOT_GRANTED`        | Tool not granted to this agent's role → BLOCK                 |
| P-004 | `INVALID_ARGUMENTS`       | Arguments fail the tool's schema → BLOCK                      |
| P-005 | `ARG_LIMIT_EXCEEDED`      | An argument exceeds the allowed limit → BLOCK                 |
| P-006 | `SENSITIVE_TABLE_EXPORT`  | Export of a non-permitted table → BLOCK                       |
| P-007 | `PROD_DESTRUCTIVE_DENIED` | Delete / disable on a production resource → BLOCK             |
| P-008 | `PROTECTED_BRANCH`        | Push or delete on a protected branch → BLOCK                  |
| P-009 | `RESTRICTED_SERVICE`      | Restart of a restricted production service → BLOCK            |
| P-010 | `SECRETS_ACCESS_DENIED`   | Secrets tool called → always BLOCK, no allow condition        |
| P-011 | `APPROVAL_REQUIRED`       | High-impact action or over-threshold value → REQUIRE_APPROVAL |
| P-012 | `RATE_LIMIT_EXCEEDED`     | Too many calls in the window → BLOCK                          |
| P-013 | `POLICY_UNAVAILABLE`      | Policy engine or gateway unavailable → BLOCK (fail closed)    |

---

## 6. Scenario mapping

| Scenario                                   | Agent     | Attempted call                        | Expected decision                  | Reason code                 |
| ------------------------------------------ | --------- | ------------------------------------- | ---------------------------------- | --------------------------- |
| A: unauthorized payment change             | Finance   | `update_beneficiary_bank_details`   | REQUIRE_APPROVAL                   | `APPROVAL_REQUIRED`       |
| B: delete production resource              | IT Ops    | `delete_resource` (`env=prod`)    | BLOCK                              | `PROD_DESTRUCTIVE_DENIED` |
| C: read secrets (demo run, tool visible)   | Developer | `read_env_secrets`                  | BLOCK                              | `SECRETS_ACCESS_DENIED`   |
| C2: read secrets (normal run, tool hidden) | Developer | `read_env_secrets`                  | BLOCK                              | `TOOL_NOT_GRANTED`        |
| D: unusual bulk request                    | Finance   | `export_records` (`limit` = 5000) | REQUIRE_APPROVAL + detection alert | `APPROVAL_REQUIRED`       |
| E: cross-agent access (test)               | Developer | `read_payroll`                      | BLOCK                              | `TOOL_NOT_GRANTED`        |
| F: spoofed identity (test)                 | any       | wrong `agent_name` in payload       | identity from credential only      | n/a (identity test)         |
| G: unknown tool (test)                     | any       | `format_disk`                       | BLOCK                              | `UNKNOWN_TOOL`            |

---

## 7. Review decisions

1. Starting limits (50 / 100 / 5,000): kept provisionally, with units defined above; tune in Stage 1.
2. Repo and secrets tools: moved to a third server, Developer Tools MCP.
3. Finance delete-style tools: HIDDEN.
4. `read_env_secrets`: visible in the Scenario C demo run only; always BLOCK.
