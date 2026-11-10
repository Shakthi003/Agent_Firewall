import { useEffect, useState } from "react";
import { api } from "../api";
import type { ApiError, ApprovalView } from "../api";
import { Badge, Empty, ErrorNote, Icon, Skeleton, ago, fmtTime, reasonText, short, usePoll } from "../ui";

const STATUS: Record<string, { tone: string; label: string }> = {
  pending: { tone: "warn", label: "Waiting for you" },
  approved: { tone: "ok", label: "Approved, not used yet" },
  used: { tone: "ok", label: "Approved and used" },
  rejected: { tone: "bad", label: "Rejected" },
  expired: { tone: "mute", label: "Expired" },
};

function Countdown({ to }: { to: number }) {
  const [now, setNow] = useState(Date.now() / 1000);
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(id);
  }, []);
  const left = Math.max(0, Math.round(to - now));
  const tone = left < 120 ? "var(--bad)" : "var(--soft)";
  return (
    <span className="countdown row" style={{ color: tone, gap: 6 }}>
      <Icon name="clock" size={15} /> {left > 0 ? `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")} left` : "expired"}
    </span>
  );
}

function Pending({ a, onDone }: { a: ApprovalView; onDone: () => void }) {
  const [busy, setBusy] = useState<"approve" | "reject" | null>(null);
  const [confirm, setConfirm] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  async function decide(approve: boolean) {
    setBusy(approve ? "approve" : "reject");
    setError(null);
    try {
      await api.decide(a.approval_id, approve);
      onDone();
    } catch (e) {
      setError(e as ApiError);
      setBusy(null);
      setConfirm(null);
    }
  }

  return (
    <div className="card approval">
      <div>
        <div className="row wrap">
          <Badge tone="warn">Waiting for you</Badge>
          <h3 style={{ fontSize: 17 }} className="mono">{a.tool}</h3>
          <span className="muted">on {a.server}</span>
        </div>
        <p className="soft" style={{ marginTop: 8 }}>
          <b>{a.requester_agent_id}</b> <span className="tag">{a.requester_role}</span> asked to run this. {reasonText(a.policy_reason)}
        </p>
        <div className="approval-args" aria-label="The exact request">
          {Object.keys(a.args).length ? Object.entries(a.args).map(([k, v]) => (
            <div key={k}><span>{k}</span><span className="mono">{typeof v === "object" ? JSON.stringify(v) : String(v)}</span></div>
          )) : <span className="muted">No arguments.</span>}
        </div>
        <div className="row wrap muted" style={{ marginTop: 12, fontSize: 12.5, gap: 18 }}>
          <span>Requested {ago(a.created_at)}</span>
          <Countdown to={a.expires_at} />
          <span className="mono">policy {a.policy_version.slice(0, 10)}</span>
          <span className="mono">request {short(a.args_hash, 6)}</span>
        </div>
        {error && <div style={{ marginTop: 12 }}><ErrorNote error={error} /></div>}
      </div>

      <div className="approval-actions">
        {confirm ? (
          <>
            <p className="soft" style={{ fontSize: 13 }}>
              {confirm === "approve" ? "Let the agent run exactly this request once?" : "Reject this request?"}
            </p>
            <button className={`btn ${confirm === "approve" ? "btn-ok" : "btn-bad"}`} disabled={busy !== null} onClick={() => void decide(confirm === "approve")}>
              {busy ? "Saving…" : confirm === "approve" ? "Yes, approve" : "Yes, reject"}
            </button>
            <button className="btn btn-ghost" disabled={busy !== null} onClick={() => setConfirm(null)}>Cancel</button>
          </>
        ) : (
          <>
            <button className="btn btn-ok" onClick={() => setConfirm("approve")}><Icon name="check" size={16} /> Approve</button>
            <button className="btn btn-bad" onClick={() => setConfirm("reject")}><Icon name="x" size={16} /> Reject</button>
          </>
        )}
      </div>
    </div>
  );
}

export default function Approvals({ onChanged }: { onChanged: () => void }) {
  const { data, error, loading, reload } = usePoll(() => api.approvals(), 5000);
  const pending = (data ?? []).filter((a) => a.status === "pending");
  const history = (data ?? []).filter((a) => a.status !== "pending");

  const refresh = () => {
    void reload();
    onChanged();
  };

  return (
    <div className="stack">
      {error && <ErrorNote error={error} onRetry={reload} />}
      {loading && !data && <Skeleton h={180} />}

      {data && (
        <section>
          <div className="section-title">Waiting for a decision ({pending.length})</div>
          {pending.length ? (
            pending.map((a) => <Pending key={a.approval_id} a={a} onDone={refresh} />)
          ) : (
            <div className="card">
              <Empty icon="check" title="Nothing is waiting" hint="When an agent asks to do something risky, it shows up here and the agent waits." />
            </div>
          )}
        </section>
      )}

      {history.length > 0 && (
        <section>
          <div className="section-title">History</div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Status</th><th>Tool</th><th>Agent</th><th>Requested</th><th>Decided by</th></tr></thead>
              <tbody>
                {history.map((a) => (
                  <tr key={a.approval_id}>
                    <td><Badge tone={STATUS[a.status]?.tone ?? "mute"}>{STATUS[a.status]?.label ?? a.status}</Badge></td>
                    <td className="cell-main mono">{a.tool}</td>
                    <td className="soft">{a.requester_agent_id}</td>
                    <td className="muted">{fmtTime(a.created_at)}</td>
                    <td className="soft">{a.decided_by ?? "—"}{a.decided_at ? <span className="muted"> · {ago(a.decided_at)}</span> : null}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
