import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import type { ApiError, AuditEventView } from "../api";
import { EventDrawer } from "../EventDetail";
import { DecisionBadge, Empty, ErrorNote, Icon, Skeleton, fmtTime } from "../ui";

const FILTERS = [
  { id: "", label: "All" },
  { id: "ALLOW", label: "Allowed" },
  { id: "BLOCK", label: "Blocked" },
  { id: "REQUIRE_APPROVAL", label: "Needs approval" },
  { id: "APPROVED", label: "Approved" },
  { id: "REJECTED", label: "Rejected" },
];
const PAGE = 40;

export default function Audit({ focusSeq, onFocusDone }: { focusSeq: number | null; onFocusDone: () => void }) {
  const [decision, setDecision] = useState("");
  const [calls, setCalls] = useState(true);
  const [text, setText] = useState("");
  const [search, setSearch] = useState("");
  const [rows, setRows] = useState<AuditEventView[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [open, setOpen] = useState<number | null>(focusSeq);
  const generation = useRef(0);

  useEffect(() => {
    if (focusSeq !== null) {
      setOpen(focusSeq);
      onFocusDone();
    }
  }, [focusSeq, onFocusDone]);

  useEffect(() => {
    const id = setTimeout(() => setSearch(text.trim()), 300); // debounce typing
    return () => clearTimeout(id);
  }, [text]);

  async function load(before: number | null) {
    const mine = ++generation.current;
    setLoading(true);
    try {
      const res = await api.events({ limit: PAGE, before_seq: before, decision, search, method: calls ? "tools/call" : undefined });
      if (mine !== generation.current) return; // a newer request replaced this one
      setRows((prev) => (before ? [...prev, ...res.events] : res.events));
      setNext(res.next_before_seq);
      setError(null);
    } catch (e) {
      if (mine === generation.current) setError(e as ApiError);
    } finally {
      if (mine === generation.current) setLoading(false);
    }
  }

  useEffect(() => {
    void load(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [decision, search, calls]);

  return (
    <div>
      <div className="toolbar">
        <div className="search">
          <Icon name="search" size={16} />
          <input className="input" placeholder="Search tool, agent, reason or call ID" value={text} onChange={(e) => setText(e.target.value)} aria-label="Search the audit log" />
        </div>
        <div className="seg" role="group" aria-label="Filter by decision">
          {FILTERS.map((f) => (
            <button key={f.id} className={decision === f.id ? "on" : ""} onClick={() => setDecision(f.id)}>
              {f.label}
            </button>
          ))}
        </div>
        <label className="row soft" style={{ fontSize: 13, gap: 8 }}>
          <input type="checkbox" checked={calls} onChange={(e) => setCalls(e.target.checked)} /> Tool calls only
        </label>
        <button className="btn btn-ghost btn-sm" style={{ marginLeft: "auto" }} onClick={() => void load(null)}>
          <Icon name="refresh" size={15} className={loading ? "spin" : ""} /> Refresh
        </button>
      </div>

      {error && <ErrorNote error={error} onRetry={() => void load(null)} />}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Time</th>
              <th>Decision</th>
              <th>Tool</th>
              <th>Agent</th>
              <th>Reason</th>
              <th>Policy</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.seq} className={`click${e.decision === "BLOCK" || e.spoof_attempt ? " flag" : e.decision === "REQUIRE_APPROVAL" ? " flag-warn" : ""}`} onClick={() => setOpen(e.seq)} tabIndex={0} onKeyDown={(k) => k.key === "Enter" && setOpen(e.seq)}>
                <td className="mono muted">{e.seq}</td>
                <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtTime(e.timestamp)}</td>
                <td><DecisionBadge decision={e.decision} /></td>
                <td>
                  <div className="cell-main">{e.tool ?? e.method}</div>
                  {e.server && <div className="cell-sub">{e.server}</div>}
                </td>
                <td className="soft">{e.agent_id ?? "—"}</td>
                <td><span className="tag mono">{e.reason_code}</span></td>
                <td className="mono muted">{e.policy_version?.slice(0, 10) ?? "—"}</td>
              </tr>
            ))}
            {loading && !rows.length && [0, 1, 2, 3, 4].map((i) => (
              <tr key={i}><td colSpan={7}><Skeleton h={22} /></td></tr>
            ))}
          </tbody>
        </table>
        {!loading && !rows.length && !error && <Empty icon="search" title="No matching records" hint="Change the filter, or run something through the gateway." />}
      </div>

      {next !== null && (
        <div style={{ textAlign: "center", marginTop: 16 }}>
          <button className="btn" disabled={loading} onClick={() => void load(next)}>
            {loading ? "Loading…" : "Load older records"}
          </button>
        </div>
      )}

      {open !== null && <EventDrawer seq={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
