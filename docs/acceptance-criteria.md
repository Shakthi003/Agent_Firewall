# MVP Acceptance Criteria — v2 (review answers applied)

> Status: **v2, reviewed.** Review answers are in section 9.
> Each criterion is a statement a test can pass or fail. IDs (AC-xx) will be referenced by test names in `tests/`.
> Sources: `docs/permission-matrix.md`, `docs/threat-model.md`, `docs/architecture.md`.
> Rule: results are reported only after the tests are run. No target percentages are published as achieved results.

---

## 1. Identity and gateway (Stage 2)

| ID | Criterion | How it is verified |
| -- | --------- | ------------------ |
| AC-01 | A request with a valid agent key is authenticated and the agent ID and role come from the credential | Integration test |
| AC-02 | A request with a missing, unknown, expired or disabled key is denied with `UNREGISTERED_AGENT` and audited | Integration test |
| AC-03 | An `agent_name` (or similar) field in the payload never changes the identity; a conflicting value is logged as a spoofing attempt | Security test (scenario F) |
| AC-04 | `tools/list` returns only the tools granted to the calling agent | Integration test |
| AC-05 | A call to a tool not in the registry is denied with `UNKNOWN_TOOL` | Security test (scenario G) |
| AC-06 | A call to a registered tool not granted to the agent is denied with `TOOL_NOT_GRANTED` | Security test (scenario E) |
| AC-07 | Arguments that fail the tool schema are denied with `INVALID_ARGUMENTS` and never reach a downstream server | Integration test |
| AC-08 | The gateway preserves MCP `tools/list` and `tools/call` semantics: a standard MCP client works against it unmodified | Integration test with the MCP SDK client |
| AC-09 | Every request gets a correlation ID that appears in the audit event and the downstream call | Integration test |
| AC-10 | Errors returned to agents contain a decision, reason code and correlation ID, and no stack trace or policy internals | Integration test |
| AC-11 | From inside an agent container, every downstream MCP server is unreachable | Docker network test |

---

## 2. Policy and enforcement (Stage 3)

| ID | Criterion | How it is verified |
| -- | --------- | ------------------ |
| AC-12 | Every policy decision is `ALLOW`, `BLOCK` or `REQUIRE_APPROVAL` and carries a reason code and a policy version | Unit test |
| AC-13 | Each row of the permission matrix produces its documented decision | Table-driven test generated from the matrix |
| AC-14 | Each conditional rule in the matrix (limits, thresholds, prod, protected branch, restricted service) produces its documented decision at, below and above the boundary | Unit test |
| AC-15 | Scenario B: `delete_resource` with `env=prod` by IT Ops is blocked and the Operations MCP receives no call | Security test with a downstream call counter |
| AC-16 | Scenario C: `read_env_secrets` is blocked in both the demo run (`SECRETS_ACCESS_DENIED`) and the normal run (`TOOL_NOT_GRANTED`) | Security test |
| AC-17 | Scenario D: an `export_records` call above the limit returns `REQUIRE_APPROVAL` | Security test |
| AC-18 | For every BLOCK and REQUIRE_APPROVAL decision, the downstream server's call counter stays at zero | Security test across the test matrix |
| AC-19 | Allowed calls reach the correct downstream server and return its result | Integration test |
| AC-20 | If the policy engine is unavailable, protected calls are denied with `POLICY_UNAVAILABLE` | Failure-injection test |
| AC-21 | Exceeding the rate limit returns `RATE_LIMIT_EXCEEDED` | Integration test |

---

## 3. Approval (Stage 4)

| ID | Criterion | How it is verified |
| -- | --------- | ------------------ |
| AC-22 | Scenario A: `update_beneficiary_bank_details` returns "pending" with an approval ID and does not execute | Security test |
| AC-23 | After a valid approval, the retry executes exactly the stored request | End-to-end test |
| AC-24 | A retry with changed arguments is rejected (argument hash mismatch) | Security test |
| AC-25 | A second use of the same approval is rejected | Security test |
| AC-26 | An expired approval (15 minutes by default) is rejected | Test with a controllable clock |
| AC-27 | A rejected approval never executes | End-to-end test |
| AC-28 | Only the approver role can approve or reject; the requesting agent cannot approve its own request | Security test |
| AC-29 | Policy is re-checked at execution; if it now forbids the call, the call is denied | Integration test |
| AC-30 | Approver identity, time, decision and execution result are in the audit log | Integration test |

---

## 4. Audit and monitoring (Stage 5)

| ID | Criterion | How it is verified |
| -- | --------- | ------------------ |
| AC-31 | Every protected call, including denied ones, produces an audit event with all required fields | Test over the whole scenario suite |
| AC-32 | Audit events never contain raw keys, secret values, full account numbers or full personal data | Redaction test with seeded canary values |
| AC-33 | Each audit event stores the previous record's hash; the verification check passes on an untouched log | Unit test |
| AC-34 | Editing or deleting any past audit record makes the verification check fail | Tamper test |
| AC-35 | Anomaly score, policy decision and enforcement action are stored as separate fields | Schema test |
| AC-36 | Each rule-based detection (burst, large export, repeated denials, unusual sequence) fires on its simulated attack and stays quiet on normal traffic from the simulator | Detection test |
| AC-37 | Detection results are reproducible: the same seeded simulator run gives the same alerts | Repeat-run test |
| AC-38 | The anomaly model, if used, never overrides a deterministic policy decision | Integration test |

---

## 5. Investigation (Stage 6)

| ID | Criterion | How it is verified |
| -- | --------- | ------------------ |
| AC-39 | The investigation output matches its schema and is validated before display | Unit test with a faked LLM |
| AC-40 | Every finding and recommendation cites at least one real audit event ID | Automatic check against the audit store |
| AC-41 | Facts and hypotheses are labelled separately in the report | Schema and review |
| AC-42 | The workflow has no way to change policy or execute remediation | Code review and a test that its tool set is read-only |
| AC-43 | If the LLM fails, a fallback summary is produced and the failure is logged | Failure-injection test |

---

## 6. Dashboard and API (Stage 7)

| ID | Criterion | How it is verified |
| -- | --------- | ------------------ |
| AC-44 | The dashboard shows decisions, reason codes, policy versions and audit event details | Manual check plus API tests |
| AC-45 | Pending approvals can be approved or rejected from the dashboard | End-to-end test |
| AC-46 | The audit verification result (chain intact or broken) is visible | Manual check |
| AC-47 | A reviewer can run an attack simulation and see decision, evidence and investigation without reading source code | Walkthrough with the demo script |
| AC-48 | API inputs are validated and unhandled errors return a request ID, not a stack trace | API tests |

---

## 7. Evaluation and packaging (Stage 8)

| ID | Criterion | How it is verified |
| -- | --------- | ------------------ |
| AC-49 | The same scenario suite runs against the unprotected baseline and the protected gateway, and both results are reported | Evaluation script |
| AC-50 | Reported metrics (blocking rate, false positives, anomaly precision and recall, authorization latency, audit completeness, approval integrity) come from a recorded run with sample sizes stated | Evaluation report |
| AC-51 | The test suite includes concurrency, timeout, downstream error, retry and duplicate request cases | Test matrix |
| AC-52 | A dependency vulnerability scan and a secret scan run clean, or findings are documented | CI or script output |
| AC-53 | From a clean clone, the README steps bring up the whole stack with Docker Compose | Clean-clone test |
| AC-54 | The README states the limitations, including that bypassing the gateway is outside the enforcement boundary and prompt injection is not prevented | Document review |

---

## 8. Not criteria (stated so we do not overclaim)

- Detecting every prompt injection.
- Protecting agents or tools that bypass the gateway.
- Any numeric performance target before it is measured.

---

## 9. Review decisions

1. Keep all 54 criteria; each one maps to a test.
2. AC-47 is checked by a real person (a friend or colleague) using the demo script before the demo video is recorded.
