import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { ApiError } from "./api";

// ---------------------------------------------------------------- data hook

export function usePoll<T>(fn: () => Promise<T>, ms: number | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const ref = useRef(fn);
  ref.current = fn;
  const load = useCallback(async () => {
    try {
      setData(await ref.current());
      setError(null);
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    setLoading(true);
    void load();
    if (!ms) return;
    const id = setInterval(() => {
      if (!document.hidden) void load(); // no background polling in a hidden tab
    }, ms);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load, ms, ...deps]);
  return { data, error, loading, reload: load };
}

// ---------------------------------------------------------------- formatting

export const fmtNum = (n: number): string => n.toLocaleString("en-US");
export const fmtTime = (ts: number): string =>
  new Date(ts * 1000).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });
export const fmtClock = (ts: number): string =>
  new Date(ts * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
export const short = (h: string | null | undefined, n = 10): string => (h ? `${h.slice(0, n)}\u2026${h.slice(-4)}` : "\u2014");

export function ago(ts: number, now = Date.now() / 1000): string {
  const s = Math.max(0, Math.round(now - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// ---------------------------------------------------------------- plain-English meaning

export const REASONS: Record<string, string> = {
  ALLOWED_BY_POLICY: "Policy allows this call.",
  TOOL_NOT_GRANTED: "This agent's role was never granted this tool.",
  APPROVAL_REQUIRED: "Policy requires a human to approve this call first.",
  PROD_DESTRUCTIVE_DENIED: "Destructive actions in production are never allowed.",
  SECRETS_ACCESS_DENIED: "Reading secrets is not allowed for this role.",
  SENSITIVE_TABLE_EXPORT: "Exporting a sensitive table is not allowed.",
  ARG_LIMIT_EXCEEDED: "A request size limit was exceeded.",
  RESTRICTED_SERVICE: "This service is restricted.",
  PROTECTED_BRANCH: "This branch is protected.",
  DESTRUCTIVE_TOOL_DENIED: "This destructive tool is denied.",
  RATE_LIMIT_EXCEEDED: "Too many calls in a short time.",
  INVALID_ARGUMENTS: "The arguments did not match the tool's schema.",
  UNKNOWN_TOOL: "The tool is not in the approved registry.",
  UNREGISTERED_AGENT: "The caller is not a registered agent.",
  POLICY_UNAVAILABLE: "The policy check failed, so the call was denied (fail closed).",
  APPROVAL_GRANTED: "A valid human approval was used for this call.",
  APPROVAL_PENDING: "Still waiting for a human decision.",
  APPROVAL_REJECTED: "A human rejected this request.",
  APPROVAL_EXPIRED: "The approval expired before it was used.",
  APPROVAL_ALREADY_USED: "This approval was already spent (replay refused).",
  APPROVAL_MISMATCH: "The call differs from what was approved.",
  APPROVAL_INVALID: "The approval is unknown or belongs to another agent.",
  APPROVER_DECISION: "A human approver recorded a decision.",
  APPROVER_REFUSED: "The approver's decision was refused.",
  APPROVER_AUTH_FAILED: "Someone failed to log in as the approver.",
  DOWNSTREAM_TIMEOUT: "The tool took too long to answer.",
  DOWNSTREAM_ERROR: "The tool returned an error.",
};
export const reasonText = (code: string): string => REASONS[code] ?? "No description for this code.";

const DECISION: Record<string, { label: string; tone: string }> = {
  ALLOW: { label: "Allowed", tone: "ok" },
  BLOCK: { label: "Blocked", tone: "bad" },
  REQUIRE_APPROVAL: { label: "Needs approval", tone: "warn" },
  APPROVED: { label: "Approved", tone: "ok" },
  REJECTED: { label: "Rejected", tone: "bad" },
};

// ---------------------------------------------------------------- small components

export function Badge({ tone, children, dot = true }: { tone: string; children: ReactNode; dot?: boolean }) {
  return (
    <span className={`badge tone-${tone}`}>
      {dot && <i />}
      {children}
    </span>
  );
}

export function DecisionBadge({ decision }: { decision: string }) {
  const d = DECISION[decision] ?? { label: decision, tone: "mute" };
  return <Badge tone={d.tone}>{d.label}</Badge>;
}

export const sevTone = (s: string): string => (s === "high" ? "bad" : s === "medium" || s === "warning" ? "warn" : "info");

const ICONS: Record<string, string> = {
  shield: "M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3Z",
  check: "m5 12 5 5 9-10",
  alert: "M12 3 2 21h20L12 3Zm0 7v5m0 3v.01",
  grid: "M4 4h7v7H4V4Zm9 0h7v7h-7V4ZM4 13h7v7H4v-7Zm9 0h7v7h-7v-7Z",
  list: "M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01",
  inbox: "M3 13h5l1.5 3h5L16 13h5M5 5h14l2 8v6H3v-6l2-8Z",
  bell: "M6 9a6 6 0 1 1 12 0c0 6 2.5 7.5 2.5 7.5h-17S6 15 6 9Zm4.5 10a2 2 0 0 0 3 0",
  flask: "M9 3h6M10 3v6L4.5 19a1.5 1.5 0 0 0 1.3 2.2h12.4a1.5 1.5 0 0 0 1.3-2.2L14 9V3M7.5 15h9",
  x: "M6 6l12 12M18 6 6 18",
  search: "m21 21-4.3-4.3M10.5 18a7.5 7.5 0 1 1 0-15 7.5 7.5 0 0 1 0 15Z",
  play: "M7 4.5v15l12-7.5L7 4.5Z",
  link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  user: "M12 12a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9Zm-8 9c0-4 3.6-6 8-6s8 2 8 6",
  out: "M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4M10 16l-4-4 4-4M6 12h10",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7",
  chevron: "m9 6 6 6-6 6",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-14v5l3 2",
  lock: "M6 11V8a6 6 0 1 1 12 0v3M5 11h14v10H5V11Z",
};

export function Icon({ name, size = 18, className }: { name: string; size?: number; className?: string }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={ICONS[name] ?? ""} />
    </svg>
  );
}

export function Empty({ icon = "shield", title, hint }: { icon?: string; title: string; hint?: string }) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Icon name={icon} size={26} />
      </div>
      <strong>{title}</strong>
      {hint && <span>{hint}</span>}
    </div>
  );
}

export function ErrorNote({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  return (
    <div className="note note-bad" role="alert">
      <Icon name="alert" />
      <div>
        <strong>{error.message}</strong>
        {error.requestId && <span className="mono muted"> Request ID {error.requestId}</span>}
      </div>
      {onRetry && (
        <button className="btn btn-ghost btn-sm" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Skeleton({ h = 16, w = "100%" }: { h?: number; w?: string | number }) {
  return <div className="skeleton" style={{ height: h, width: w }} />;
}

export function Json({ value }: { value: unknown }) {
  return <pre className="json mono">{JSON.stringify(value, null, 2)}</pre>;
}

export function Drawer({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="drawer-wrap">
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={title}>
        <header>
          <h2>{title}</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <Icon name="x" />
          </button>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </div>
  );
}

// ---------------------------------------------------------------- charts (plain SVG, no library)

export function StackedBars({ data }: { data: { t: number; allow: number; block: number; approval: number }[] }) {
  const W = 720;
  const H = 170;
  const pad = { l: 30, r: 6, t: 8, b: 22 };
  const max = Math.max(1, ...data.map((d) => d.allow + d.block + d.approval));
  const bw = (W - pad.l - pad.r) / data.length;
  const y = (v: number) => (v / max) * (H - pad.t - pad.b);
  const base = H - pad.b;
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="chart" role="img" aria-label="Calls over the last 24 hours, by decision">
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={pad.l} x2={W - pad.r} y1={base - y(max * f)} y2={base - y(max * f)} className="grid-line" />
          <text x={pad.l - 6} y={base - y(max * f) + 3} className="axis" textAnchor="end">
            {Math.round(max * f)}
          </text>
        </g>
      ))}
      {data.map((d, i) => {
        const x = pad.l + i * bw + 2;
        const w = bw - 4;
        const a = y(d.allow);
        const b = y(d.block);
        const p = y(d.approval);
        return (
          <g key={d.t}>
            <title>{`${fmtClock(d.t)}  allowed ${d.allow}, blocked ${d.block}, needs approval ${d.approval}`}</title>
            <rect x={x} y={base - a} width={w} height={a} rx="2" fill="var(--ok)" />
            <rect x={x} y={base - a - p} width={w} height={p} rx="2" fill="var(--warn)" />
            <rect x={x} y={base - a - p - b} width={w} height={b} rx="2" fill="var(--bad)" />
            {i % 4 === 0 && (
              <text x={x + w / 2} y={H - 6} className="axis" textAnchor="middle">
                {fmtClock(d.t)}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

export function Donut({ parts, center }: { parts: { label: string; value: number; color: string }[]; center: ReactNode }) {
  const total = parts.reduce((s, p) => s + p.value, 0);
  const r = 52;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="donut">
      <svg viewBox="0 0 140 140" role="img" aria-label="Decision split">
        <circle cx="70" cy="70" r={r} fill="none" stroke="var(--line)" strokeWidth="14" />
        {total > 0 &&
          parts.map((p) => {
            const len = (p.value / total) * c;
            const el = (
              <circle key={p.label} cx="70" cy="70" r={r} fill="none" stroke={p.color} strokeWidth="14" strokeDasharray={`${Math.max(len - 2, 0)} ${c}`} strokeDashoffset={-offset} transform="rotate(-90 70 70)" />
            );
            offset += len;
            return el;
          })}
      </svg>
      <div className="donut-center">{center}</div>
    </div>
  );
}

export function Bars({ rows }: { rows: { label: string; value: number; hint?: string }[] }) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <ul className="bars">
      {rows.map((r) => (
        <li key={r.label} title={r.hint}>
          <div className="bars-row">
            <span className="mono">{r.label}</span>
            <b>{fmtNum(r.value)}</b>
          </div>
          <div className="track">
            <div style={{ width: `${(r.value / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}
