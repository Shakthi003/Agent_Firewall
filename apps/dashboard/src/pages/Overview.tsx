import { api } from "../api";
import type { ApiError, Overview as OverviewData, Verify } from "../api";
import { Bars, Donut, Empty, ErrorNote, Icon, Skeleton, StackedBars, fmtNum, fmtTime, short, usePoll } from "../ui";

type Poll<T> = { data: T | null; error: ApiError | null; loading: boolean; reload: () => Promise<void> };

function Stat({ label, value, foot, color }: { label: string; value: string; foot?: string; color: string }) {
  return (
    <div className="card stat" style={{ "--c": color } as React.CSSProperties}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {foot && <div className="foot">{foot}</div>}
    </div>
  );
}

function Integrity({ v, onRecheck, busy }: { v: Verify | null; onRecheck: () => void; busy: boolean }) {
  if (!v) return <Skeleton h={84} />;
  return (
    <div className={`integrity ${v.ok ? "ok" : "bad"}`} role="status">
      <div className="seal">
        <Icon name={v.ok ? "shield" : "alert"} size={24} />
      </div>
      <div>
        <h3>{v.ok ? "Audit chain intact" : "Audit chain BROKEN"}</h3>
        <p>
          {v.ok
            ? `All ${fmtNum(v.checked)} records re-checked: no record has been edited, removed or reordered.`
            : `Verification failed at record #${v.first_bad_seq}: ${v.reason}. Treat the evidence after this point as untrusted.`}
        </p>
      </div>
      <div className="right">
        <div className="mono muted" title={v.head_hash}>head #{v.head_seq} · {short(v.head_hash, 8)}</div>
        <button className="btn btn-ghost btn-sm" onClick={onRecheck} disabled={busy} style={{ marginTop: 4 }}>
          <Icon name="refresh" size={15} /> Verify again
        </button>
      </div>
    </div>
  );
}

export default function Overview({
  counts,
  onOpenPage,
  onOpenEvent,
}: {
  counts: Poll<OverviewData>;
  onOpenPage: (p: "audit" | "approvals" | "alerts" | "lab") => void;
  onOpenEvent: (seq: number) => void;
}) {
  const verify = usePoll(() => api.verify(), 60000);
  const recent = usePoll(() => api.events({ limit: 6, method: "tools/call" }), 15000);
  const o = counts.data;

  if (counts.error && !o) return <ErrorNote error={counts.error} onRetry={counts.reload} />;
  if (!o)
    return (
      <div className="stack">
        <Skeleton h={84} />
        <div className="grid g-4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} h={104} />)}</div>
        <Skeleton h={240} />
      </div>
    );

  const t = o.totals;
  const blockRate = t.calls ? Math.round((t.blocked / t.calls) * 100) : 0;
  return (
    <div className="stack">
      <Integrity v={verify.data} onRecheck={() => void verify.reload()} busy={verify.loading} />
      {verify.error && <ErrorNote error={verify.error} onRetry={verify.reload} />}

      <div className="grid g-4">
        <Stat label="Agent calls checked" value={fmtNum(t.calls)} foot={`${fmtNum(t.events)} audit records`} color="var(--accent2)" />
        <Stat label="Allowed" value={fmtNum(t.allowed)} foot="Policy said yes" color="var(--ok)" />
        <Stat label="Blocked" value={fmtNum(t.blocked)} foot={`${blockRate}% of all calls`} color="var(--bad)" />
        <Stat label="Sent to a human" value={fmtNum(t.needs_approval)} foot={o.pending_approvals ? `${o.pending_approvals} waiting now` : "none waiting"} color="var(--warn)" />
      </div>

      <div className="grid g-2-1">
        <div className="card">
          <div className="card-head">
            <h3>Calls in the last 24 hours</h3>
            <div className="right legend">
              <span style={{ "--c": "var(--ok)" } as React.CSSProperties}><i />Allowed</span>
              <span style={{ "--c": "var(--warn)" } as React.CSSProperties}><i />Needs approval</span>
              <span style={{ "--c": "var(--bad)" } as React.CSSProperties}><i />Blocked</span>
            </div>
          </div>
          {t.calls ? <StackedBars data={o.timeline} /> : <Empty icon="list" title="No agent calls yet" hint="Run an agent through the gateway, or try the Attack lab." />}
        </div>

        <div className="card">
          <div className="card-head">
            <h3>Decision split</h3>
          </div>
          <div className="row" style={{ gap: 20 }}>
            <Donut
              parts={[
                { label: "Allowed", value: t.allowed, color: "var(--ok)" },
                { label: "Needs approval", value: t.needs_approval, color: "var(--warn)" },
                { label: "Blocked", value: t.blocked, color: "var(--bad)" },
              ]}
              center={<><b>{blockRate}%</b><span>blocked</span></>}
            />
            <div className="stack" style={{ gap: 8, fontSize: 13 }}>
              <span className="row"><Icon name="check" size={15} /> Approved by humans: <b>{o.decisions.APPROVED}</b></span>
              <span className="row"><Icon name="x" size={15} /> Rejected by humans: <b>{o.decisions.REJECTED}</b></span>
              <button className="btn btn-ghost btn-sm" onClick={() => onOpenPage("approvals")}>Open approvals</button>
            </div>
          </div>
        </div>
      </div>

      <div className="grid g-1-1">
        <div className="card">
          <div className="card-head">
            <h3>Why calls were stopped or paused</h3>
          </div>
          {o.top_reasons.length ? <Bars rows={o.top_reasons.map((r) => ({ label: r.reason, value: r.count }))} /> : <Empty icon="shield" title="Nothing has been stopped" />}
        </div>
        <div className="card">
          <div className="card-head">
            <h3>Agents</h3>
          </div>
          {o.agents.length ? (
            <div className="table-wrap" style={{ border: 0, background: "none" }}>
              <table>
                <thead><tr><th>Agent</th><th>Calls</th><th>Blocked</th><th>Paused</th></tr></thead>
                <tbody>
                  {o.agents.map((a) => (
                    <tr key={a.agent_id}>
                      <td className="cell-main">{a.agent_id}</td>
                      <td>{fmtNum(a.total)}</td>
                      <td style={{ color: a.blocked ? "var(--bad)" : undefined }}>{a.blocked}</td>
                      <td style={{ color: a.needs_approval ? "var(--warn)" : undefined }}>{a.needs_approval}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty icon="user" title="No agents have called yet" />
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>Latest decisions</h3>
          <button className="btn btn-ghost btn-sm right" onClick={() => onOpenPage("audit")}>View all</button>
        </div>
        {recent.data?.events.length ? (
          <div className="table-wrap" style={{ border: 0, background: "none" }}>
            <table>
              <tbody>
                {recent.data.events.map((e) => (
                  <tr key={e.seq} className="click" onClick={() => onOpenEvent(e.seq)}>
                    <td className="mono muted">#{e.seq}</td>
                    <td className="cell-main">{e.tool}</td>
                    <td className="soft">{e.agent_id}</td>
                    <td><span className="tag mono">{e.reason_code}</span></td>
                    <td className="muted">{fmtTime(e.timestamp)}</td>
                    <td><Icon name="chevron" size={16} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty icon="list" title="No decisions recorded yet" />
        )}
      </div>
    </div>
  );
}
