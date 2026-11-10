import { useState } from "react";
import { api, ApiError } from "./api";
import type { AlertView, AuditEventView } from "./api";
import { Badge, DecisionBadge, Drawer, ErrorNote, Icon, Json, Skeleton, fmtTime, reasonText, sevTone, short, usePoll } from "./ui";

const Row = ({ k, children }: { k: string; children: React.ReactNode }) => (
  <>
    <dt>{k}</dt>
    <dd>{children}</dd>
  </>
);

/** One audit event, explained. Used for live events and for sandbox (simulation) events. */
export function EventDetailView({
  event,
  sameCall = [],
  alerts = [],
  onOpen,
}: {
  event: AuditEventView;
  sameCall?: AuditEventView[];
  alerts?: AlertView[];
  onOpen?: (seq: number) => void;
}) {
  const hasArgs = Object.keys(event.sanitized_args ?? {}).length > 0;
  return (
    <>
      <div className="row wrap">
        <DecisionBadge decision={event.decision} />
        <span className="tag mono">{event.reason_code}</span>
        {event.enforcement_action && <Badge tone="mute" dot={false}>{event.enforcement_action}</Badge>}
        {event.spoof_attempt && <Badge tone="bad">Identity spoof attempt</Badge>}
      </div>

      <div className="explain">
        <b>What this means. </b>
        {reasonText(event.reason_code)}
        {event.tool && (
          <>
            {" "}
            The call was to <b className="mono">{event.tool}</b>
            {event.agent_id && (
              <>
                {" "}
                by <b>{event.agent_id}</b>
              </>
            )}
            .
          </>
        )}
      </div>

      <section>
        <div className="section-title">Details</div>
        <dl className="kv">
          <Row k="Event number">#{event.seq}</Row>
          <Row k="Time">{fmtTime(event.timestamp)}</Row>
          <Row k="Request kind">{event.method}</Row>
          <Row k="Agent">{event.agent_id ?? "—"} {event.role && <span className="tag">{event.role}</span>}</Row>
          <Row k="Tool">{event.tool ? <span className="mono">{event.tool}</span> : "—"} {event.server && <span className="muted">on {event.server}</span>}</Row>
          <Row k="Policy version"><span className="mono">{event.policy_version ?? "—"}</span></Row>
          <Row k="Execution">{event.execution_status} {event.latency_ms > 0 && <span className="muted">({event.latency_ms.toFixed(0)} ms)</span>}</Row>
          <Row k="Anomaly score">{event.anomaly_score === null ? "—" : event.anomaly_score.toFixed(2)}</Row>
          {event.approval_id && <Row k="Approval"><span className="mono">{short(event.approval_id, 8)}</span></Row>}
          {event.approver_id && <Row k="Approver">{event.approver_id}</Row>}
          {event.auth_failure && <Row k="Auth failure">{event.auth_failure}</Row>}
          <Row k="Correlation ID"><span className="mono">{event.correlation_id}</span></Row>
        </dl>
      </section>

      <section>
        <div className="section-title">Arguments (redacted copy)</div>
        {hasArgs ? <Json value={event.sanitized_args} /> : <span className="muted">Names only: {event.arg_names.join(", ") || "none"}</span>}
        {event.args_hash && <p className="mono muted" style={{ marginTop: 8 }}>hash of the full original: {short(event.args_hash, 16)}</p>}
      </section>

      <section>
        <div className="section-title">Tamper-evident chain</div>
        <div className="chain-link">
          <div>
            <small>previous record hash</small>
            <span className="mono">{short(event.prev_hash, 14)}</span>
          </div>
          <div>
            <small>this record’s hash</small>
            <span className="mono">{short(event.record_hash, 14)}</span>
          </div>
        </div>
      </section>

      {alerts.length > 0 && (
        <section>
          <div className="section-title">Monitoring alerts on this call</div>
          {alerts.map((a) => (
            <div className="note note-warn" key={a.id} style={{ marginBottom: 8 }}>
              <Icon name="bell" />
              <div>
                <strong>{a.rule}</strong> <Badge tone={sevTone(a.severity)}>{a.severity}</Badge>
                <div className="cell-sub">{a.detail}</div>
              </div>
            </div>
          ))}
        </section>
      )}

      {sameCall.length > 0 && (
        <section>
          <div className="section-title">Other records for the same call</div>
          {sameCall.map((e) => (
            <button key={e.seq} className="btn btn-ghost btn-sm" onClick={() => onOpen?.(e.seq)} style={{ width: "100%", justifyContent: "space-between" }}>
              <span>
                #{e.seq} · {e.method}
              </span>
              <DecisionBadge decision={e.decision} />
            </button>
          ))}
        </section>
      )}
    </>
  );
}

/** Fetches a live event by number and shows it in a side drawer. */
export function EventDrawer({ seq, onClose }: { seq: number; onClose: () => void }) {
  const [current, setCurrent] = useState(seq);
  const { data, error, reload } = usePoll(() => api.event(current), null, [current]);
  return (
    <Drawer title={`Audit event #${current}`} onClose={onClose}>
      {error && <ErrorNote error={error as ApiError} onRetry={reload} />}
      {!data && !error && (
        <>
          <Skeleton h={28} w="60%" />
          <Skeleton h={80} />
          <Skeleton h={160} />
        </>
      )}
      {data && <EventDetailView event={data.event} sameCall={data.same_call} alerts={data.alerts} onOpen={setCurrent} />}
    </Drawer>
  );
}
