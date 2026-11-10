import { api } from "../api";
import { Badge, Empty, ErrorNote, Skeleton, fmtTime, usePoll } from "../ui";

const DECISION_TONE: Record<string, string> = { ALLOW: "ok", BLOCK: "bad", REQUIRE_APPROVAL: "warn" };

const describeWhen = (when: Record<string, Record<string, unknown>>): string =>
  Object.entries(when)
    .map(([field, ops]) =>
      Object.entries(ops)
        .map(([op, val]) => `${field} ${op} ${JSON.stringify(val)}`)
        .join(" and "),
    )
    .join(" and ");

export default function Policies() {
  const policy = usePoll(() => api.policies(), null);
  const agents = usePoll(() => api.agents(), 15000);
  return (
    <div className="stack">
      <div className="note">
        <div>
          Read-only view. Policy rules live in <span className="mono">policies/policy.yaml</span> and tool grants in the tool
          registry. Change them in the files, not here. The first matching rule wins; otherwise the default applies.
        </div>
      </div>

      <h2>Agents</h2>
      {agents.error && <ErrorNote error={agents.error} onRetry={agents.reload} />}
      {agents.loading && !agents.data && <Skeleton h={120} />}
      {agents.data && !agents.data.length && (
        <div className="card">
          <Empty icon="user" title="No agents registered" hint="Run scripts.register_agents to create them." />
        </div>
      )}
      {agents.data && agents.data.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Agent</th><th>Role</th><th>Status</th><th>Key</th><th>Tools it may use</th></tr></thead>
            <tbody>
              {agents.data.map((a) => (
                <tr key={a.agent_id}>
                  <td className="cell-main">{a.agent_id}</td>
                  <td className="soft">{a.role}</td>
                  <td><Badge tone={a.status === "active" ? "ok" : "bad"}>{a.status}</Badge></td>
                  <td className="muted" title={`expires ${fmtTime(a.key_expires_at)}`}>v{a.key_version}</td>
                  <td className="mono" style={{ fontSize: 12 }}>{a.tools.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h2>Policy {policy.data ? <span className="tag mono">{policy.data.policy_version}</span> : null}</h2>
      {policy.error && <ErrorNote error={policy.error} onRetry={policy.reload} />}
      {policy.loading && !policy.data && <Skeleton h={240} />}
      {policy.data && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Tool</th><th>Sensitivity</th><th>Roles</th><th>Rules (in order)</th><th>Default</th></tr></thead>
            <tbody>
              {policy.data.tools.map((t) => (
                <tr key={t.tool}>
                  <td>
                    <div className="cell-main mono">{t.tool}</div>
                    <div className="cell-sub">{t.server ?? "not in registry"}</div>
                  </td>
                  <td className="soft">{t.sensitivity ?? "\u2014"}</td>
                  <td className="soft">{t.roles.length ? t.roles.join(", ") : "none"}</td>
                  <td>
                    {t.rules.length === 0 && <span className="muted">none</span>}
                    {t.rules.map((r, i) => (
                      <div key={i} className="cell-sub">
                        <Badge tone={DECISION_TONE[r.decision] ?? "mute"}>{r.decision}</Badge> if {describeWhen(r.when)}
                        {r.reason ? <span className="mono"> ({r.reason})</span> : null}
                      </div>
                    ))}
                  </td>
                  <td>
                    <Badge tone={DECISION_TONE[t.default.decision] ?? "mute"}>{t.default.decision}</Badge>
                    {t.default.reason ? <div className="cell-sub mono">{t.default.reason}</div> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
