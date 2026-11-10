// Typed client for the approver / dashboard API. Credentials live in sessionStorage only (cleared
// when the tab closes) and are sent as HTTP Basic, the same login the Stage 4 approver API uses.

export interface AuditEventView {
  seq: number;
  prev_hash: string;
  record_hash: string;
  timestamp: number;
  correlation_id: string;
  method: string;
  decision: string;
  reason_code: string;
  agent_id: string | null;
  role: string | null;
  key_version: number | null;
  auth_failure: string | null;
  tool: string | null;
  server: string | null;
  policy_version: string | null;
  args_hash: string | null;
  arg_names: string[];
  spoofed_fields: string[];
  spoof_attempt: boolean;
  execution_status: string;
  latency_ms: number;
  tool_count: number | null;
  approval_id: string | null;
  approver_id: string | null;
  sanitized_args: Record<string, unknown>;
  enforcement_action: string | null;
  anomaly_score: number | null;
  extra: Record<string, unknown>;
}

export interface Overview {
  totals: { events: number; calls: number; allowed: number; blocked: number; needs_approval: number };
  decisions: Record<string, number>;
  top_reasons: { reason: string; count: number }[];
  agents: { agent_id: string; total: number; blocked: number; needs_approval: number }[];
  timeline: { t: number; allow: number; block: number; approval: number }[];
  pending_approvals: number;
  alerts: number;
  policy_version: string | null;
  head: { last_seq: number; last_hash: string; count: number };
}

export interface Verify {
  ok: boolean;
  checked: number;
  first_bad_seq: number | null;
  reason: string | null;
  head_seq: number;
  head_hash: string;
}

export interface AlertView {
  id: number;
  timestamp: number;
  rule: string;
  agent_id: string;
  score: number;
  severity: string;
  detail: string;
  evidence: string[];
  audit_seq: number | null;
}

export interface ApprovalView {
  approval_id: string;
  requester_agent_id: string;
  requester_role: string;
  tool: string;
  server: string;
  args: Record<string, unknown>;
  args_hash: string;
  policy_reason: string;
  policy_version: string;
  correlation_id: string;
  status: "pending" | "approved" | "rejected" | "used" | "expired";
  created_at: number;
  expires_at: number;
  decided_by: string | null;
  decided_at: number | null;
  used_at: number | null;
  execution_status: string | null;
}

export interface Finding {
  kind: "fact" | "hypothesis";
  statement: string;
  event_ids: number[];
}

export interface Report {
  advisory_only: true;
  agent_id: string | null;
  severity: "low" | "medium" | "high";
  summary: string;
  summary_event_ids: number[];
  events_examined: number;
  truncated: boolean;
  audit_chain_ok: boolean;
  timeline: { event_id: number; description: string }[];
  root_cause: Finding | null;
  findings: Finding[];
  recommendations: { action: string; rationale: string; event_ids: number[] }[];
  requires_human_review: boolean;
  review_status: "not_required" | "pending_human_review";
  degraded: boolean;
  failures: string[];
}

export interface Scenario {
  id: string;
  name: string;
  agent: string;
  task: string;
  hostile_text: string;
  unsafe_tool: string;
  planned_calls: { call_id: string; tool: string; args: Record<string, unknown> }[];
}

export interface SimCall {
  call_id: string;
  tool: string;
  args: Record<string, unknown>;
  expected_decision: string | null;
  expected_reason: string | null;
  decision: string | null;
  reason_code: string | null;
  enforcement_action: string | null;
  seq: number | null;
}

export interface SimResult {
  scenario: { id: string; name: string; agent: string };
  sandbox: boolean;
  elapsed_ms: number;
  calls: SimCall[];
  events: AuditEventView[];
  chain: { ok: boolean; checked: number; reason: string | null };
  alerts: AlertView[];
  report: Report;
  markdown: string;
}

export interface EventDetail {
  event: AuditEventView;
  same_call: AuditEventView[];
  alerts: AlertView[];
}

export class ApiError extends Error {
  status: number;
  requestId?: string;
  constructor(status: number, message: string, requestId?: string) {
    super(message);
    this.status = status;
    this.requestId = requestId;
  }
}

const STORE = "af.auth";
let token: string | null = sessionStorage.getItem(STORE);
let onUnauthorized: () => void = () => {};

export const hasSession = (): boolean => token !== null;
export const setUnauthorizedHandler = (fn: () => void): void => {
  onUnauthorized = fn;
};
export function logout(): void {
  token = null;
  sessionStorage.removeItem(STORE);
}

const encode = (s: string): string => btoa(String.fromCharCode(...new TextEncoder().encode(s)));

async function request<T>(path: string, init: RequestInit = {}, auth = token): Promise<T> {
  const headers: Record<string, string> = { "X-Requested-With": "dashboard" };
  if (auth) headers.Authorization = `Basic ${auth}`;
  if (init.body) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(path, { ...init, headers });
  } catch {
    throw new ApiError(0, "Cannot reach the API. Is the approver service running?");
  }
  if (!res.ok) {
    let detail = `Request failed (${res.status}).`;
    let requestId = res.headers.get("X-Request-ID") ?? undefined;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      requestId = body.request_id ?? requestId;
    } catch {
      /* keep the generic message */
    }
    if (res.status === 401 && auth === token) onUnauthorized();
    throw new ApiError(res.status, detail, requestId);
  }
  return (await res.json()) as T;
}

export async function login(user: string, password: string): Promise<void> {
  const candidate = encode(`${user}:${password}`);
  await request("/api/session", {}, candidate);
  token = candidate;
  sessionStorage.setItem(STORE, candidate);
}

const qs = (params: Record<string, string | number | undefined | null>): string => {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  const s = q.toString();
  return s ? `?${s}` : "";
};

export const api = {
  session: () => request<{ user: string; role: string }>("/api/session"),
  overview: () => request<Overview>("/api/overview"),
  verify: () => request<Verify>("/api/audit/verify"),
  events: (p: { limit?: number; before_seq?: number | null; decision?: string; search?: string; method?: string }) =>
    request<{ events: AuditEventView[]; next_before_seq: number | null }>(`/api/audit/events${qs(p)}`),
  event: (seq: number) => request<EventDetail>(`/api/audit/events/${seq}`),
  alerts: () => request<AlertView[]>("/api/alerts"),
  approvals: () => request<ApprovalView[]>("/api/approvals"),
  decide: (id: string, approve: boolean) =>
    request<ApprovalView>(`/approvals/${encodeURIComponent(id)}/${approve ? "approve" : "reject"}`, { method: "POST" }),
  scenarios: () => request<Scenario[]>("/api/simulations/scenarios"),
  simulate: (scenario: string, use_llm: boolean) =>
    request<SimResult>("/api/simulations/run", { method: "POST", body: JSON.stringify({ scenario, use_llm }) }),
  investigate: (agent_id: string | null, use_llm: boolean) =>
    request<{ report: Report; markdown: string }>("/api/investigations", {
      method: "POST",
      body: JSON.stringify({ agent_id: agent_id || null, use_llm }),
    }),
};
