import { api } from "../api";
import { Badge, Empty, ErrorNote, Skeleton, ago, fmtTime, sevTone, usePoll } from "../ui";

const RULES: Record<string, string> = {
  BURST: "A burst of calls in a very short time",
  LARGE_EXPORT: "An unusually large data export",
  REPEATED_DENIALS: "The same agent keeps getting denied",
  UNUSUAL_SEQUENCE: "Tools used in an unusual order",
  OFF_HOURS: "Activity outside business hours (UTC)",
};

export default function Alerts({ onOpenEvent }: { onOpenEvent: (seq: number) => void }) {
  const { data, error, loading, reload } = usePoll(() => api.alerts(), 10000);
  return (
    <div className="stack">
      <div className="note">
        <div>
          Alerts come from the behaviour monitor. They <b>never</b> change a decision: the policy engine decides, the monitor only raises its hand.
        </div>
      </div>
      {error && <ErrorNote error={error} onRetry={reload} />}
      {loading && !data && <Skeleton h={180} />}
      {data && !data.length && (
        <div className="card">
          <Empty icon="bell" title="No alerts" hint="Nothing unusual has been spotted." />
        </div>
      )}
      {data && data.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Severity</th><th>Rule</th><th>Agent</th><th>When</th><th>Score</th><th /></tr></thead>
            <tbody>
              {data.map((a) => (
                <tr key={a.id} className={a.severity === "high" ? "flag" : "flag-warn"}>
                  <td><Badge tone={sevTone(a.severity)}>{a.severity}</Badge></td>
                  <td>
                    <div className="cell-main mono">{a.rule}</div>
                    <div className="cell-sub">{RULES[a.rule] ?? a.detail}</div>
                    <div className="cell-sub">{a.detail}</div>
                  </td>
                  <td className="soft">{a.agent_id}</td>
                  <td className="muted" title={fmtTime(a.timestamp)}>{ago(a.timestamp)}</td>
                  <td className="mono">{a.score.toFixed(2)}</td>
                  <td>
                    {a.audit_seq !== null && (
                      <button className="btn btn-ghost btn-sm" onClick={() => onOpenEvent(a.audit_seq as number)}>
                        View event #{a.audit_seq}
                      </button>
                    )}
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
