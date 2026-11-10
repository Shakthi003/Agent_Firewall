import { useState } from "react";
import { api } from "../api";
import type { ApiError, AuditEventView, Report, Scenario, SimResult } from "../api";
import { EventDetailView } from "../EventDetail";
import { Badge, DecisionBadge, Drawer, Empty, ErrorNote, Icon, Skeleton, reasonText, sevTone, usePoll } from "../ui";

function Cites({ ids, onOpen }: { ids: number[]; onOpen: (seq: number) => void }) {
  return (
    <>
      {[...new Set(ids)].sort((a, b) => a - b).map((i) => (
        <button key={i} className="cite" onClick={() => onOpen(i)} title={`Open audit event #${i}`}>
          #{i}
        </button>
      ))}
    </>
  );
}

function ReportView({ r, onOpen }: { r: Report; onOpen: (seq: number) => void }) {
  const facts = r.findings.filter((f) => f.kind === "fact");
  const hyps = r.findings.filter((f) => f.kind === "hypothesis");
  const tone = sevTone(r.severity);
  return (
    <div className="stack">
      <div className={`report-sev tone-${tone}`}>
        <Icon name="alert" size={22} />
        <div style={{ flex: 1 }}>
          <b style={{ textTransform: "capitalize" }}>{r.severity} severity</b>
          <div style={{ color: "var(--text)" }}>
            {r.summary} <Cites ids={r.summary_event_ids} onOpen={onOpen} />
          </div>
        </div>
      </div>

      <div className="row wrap">
        <Badge tone="info" dot={false}>Advisory only: nothing was executed</Badge>
        <Badge tone={r.audit_chain_ok ? "ok" : "bad"}>{r.audit_chain_ok ? "Evidence chain verified" : "Evidence chain broken"}</Badge>
        {r.requires_human_review && <Badge tone="warn">Pending human review</Badge>}
        {r.degraded && <Badge tone="mute">Fallback summary (no LLM)</Badge>}
        <span className="muted">{r.events_examined} events examined</span>
      </div>

      {r.root_cause && (
        <section>
          <div className="section-title">Root cause</div>
          <div className="finding">
            <Badge tone={r.root_cause.kind === "fact" ? "ok" : "warn"} dot={false}>{r.root_cause.kind}</Badge>{" "}
            {r.root_cause.statement} <Cites ids={r.root_cause.event_ids} onOpen={onOpen} />
          </div>
        </section>
      )}

      {r.timeline.length > 0 && (
        <section>
          <div className="section-title">Timeline</div>
          <div className="steps">
            {r.timeline.map((t, i) => (
              <div className="step" key={`${t.event_id}-${i}`}>
                <div className="n">{i + 1}</div>
                <div>{t.description}</div>
                <Cites ids={[t.event_id]} onOpen={onOpen} />
              </div>
            ))}
          </div>
        </section>
      )}

      {facts.length > 0 && (
        <section>
          <div className="section-title">Facts (stated by recorded events)</div>
          {facts.map((f, i) => <div className="finding" key={i}>{f.statement} <Cites ids={f.event_ids} onOpen={onOpen} /></div>)}
        </section>
      )}
      {hyps.length > 0 && (
        <section>
          <div className="section-title">Hypotheses (not proven)</div>
          {hyps.map((f, i) => <div className="finding" key={i}>{f.statement} <Cites ids={f.event_ids} onOpen={onOpen} /></div>)}
        </section>
      )}

      {r.recommendations.length > 0 && (
        <section>
          <div className="section-title">Recommendations — for a human to decide</div>
          {r.recommendations.map((x, i) => (
            <div className="finding" key={i}>
              <b>{x.action}</b>
              <div className="soft">{x.rationale} <Cites ids={x.event_ids} onOpen={onOpen} /></div>
            </div>
          ))}
        </section>
      )}
      {r.failures.length > 0 &&
        (r.failures.every((f) => f.includes("offline mode")) ? (
          <div className="note"><div className="soft">
            Built-in summary used. No AI model was called, so the root cause and recommendations above come from fixed rules over the recorded events.
          </div></div>
        ) : (
          <div className="note note-warn"><div>{r.failures.join(" · ")}</div></div>
        ))}
    </div>
  );
}

function Result({ res }: { res: SimResult }) {
  const [openEvent, setOpenEvent] = useState<AuditEventView | null>(null);
  const bySeq = new Map(res.events.map((e) => [e.seq, e]));
  const open = (seq: number) => {
    const e = bySeq.get(seq);
    if (e) setOpenEvent(e);
  };
  const planned = res.calls.filter((c) => c.expected_decision);
  const matched = planned.filter((c) => c.decision === c.expected_decision && c.reason_code === c.expected_reason).length;

  return (
    <div className="stack">
      <div className="card">
        <div className="card-head">
          <h3>1 · What the gateway decided</h3>
          <span className="right muted">
            {matched}/{planned.length} unsafe calls handled exactly as the policy expects · {res.elapsed_ms} ms
          </span>
        </div>
        <div className="steps">
          {res.calls.map((c, i) => (
            <div className="step" key={c.call_id}>
              <div className="n">{i === 0 ? "•" : c.call_id}</div>
              <div>
                <div className="row wrap">
                  <b className="mono">{c.tool}</b>
                  {c.decision && <DecisionBadge decision={c.decision} />}
                  {c.reason_code && <span className="tag mono">{c.reason_code}</span>}
                </div>
                <div className="soft" style={{ marginTop: 4, fontSize: 13 }}>
                  {i === 0 ? "A normal, harmless call to start the trail. " : ""}
                  {c.reason_code ? reasonText(c.reason_code) : "No decision was recorded."}
                  {c.enforcement_action && <> Gateway action: <b>{c.enforcement_action}</b>.</>}
                </div>
                <div className="mono muted" style={{ marginTop: 4 }}>{JSON.stringify(c.args)}</div>
              </div>
              {c.seq !== null && <button className="cite" onClick={() => open(c.seq as number)}>evidence #{c.seq}</button>}
            </div>
          ))}
        </div>
      </div>

      <div className="grid g-1-1">
        <div className="card">
          <div className="card-head"><h3>2 · Evidence trail</h3></div>
          <div className={`note ${res.chain.ok ? "note-ok" : "note-bad"}`}>
            <Icon name={res.chain.ok ? "shield" : "alert"} />
            <div>
              <b>{res.chain.ok ? "Hash chain intact" : "Hash chain broken"}</b>
              <div className="cell-sub">{res.chain.checked} records, each linked to the one before it.</div>
            </div>
          </div>
          <p className="muted" style={{ marginTop: 10 }}>{res.events.length} audit events were written. Click any <span className="cite">#n</span> to read one.</p>
          {res.alerts.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div className="section-title">Monitor alerts raised</div>
              {res.alerts.map((a) => (
                <div className="note note-warn" key={a.id} style={{ marginBottom: 6 }}>
                  <Icon name="bell" />
                  <div><b className="mono">{a.rule}</b> <Badge tone={sevTone(a.severity)}>{a.severity}</Badge><div className="cell-sub">{a.detail}</div></div>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="card">
          <div className="card-head"><h3>What the attacker tried</h3></div>
          <p className="soft">Hidden text inside the data the agent reads asks it to do something unsafe. The agent was never given extra power: the gateway judges every call on its own.</p>
        </div>
      </div>

      <div className="card">
        <div className="card-head"><h3>3 · Investigation</h3></div>
        <ReportView r={res.report} onOpen={open} />
      </div>

      {openEvent && (
        <Drawer title={`Sandbox event #${openEvent.seq}`} onClose={() => setOpenEvent(null)}>
          <EventDetailView event={openEvent} sameCall={res.events.filter((e) => e.correlation_id === openEvent.correlation_id && e.seq !== openEvent.seq)} onOpen={open} />
        </Drawer>
      )}
    </div>
  );
}

export default function Lab() {
  const catalog = usePoll<Scenario[]>(() => api.scenarios(), null);
  const [picked, setPicked] = useState<string>("A");
  const [useLlm, setUseLlm] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<SimResult | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const scenario = catalog.data?.find((s) => s.id === picked);

  async function run() {
    setRunning(true);
    setError(null);
    try {
      setResult(await api.simulate(picked, useLlm));
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="stack">
      <div className="note note-ok">
        <Icon name="shield" />
        <div>
          <b>Safe to run.</b> Each run happens in a throw-away sandbox with its own database. It never touches your live audit log, approvals or agent keys.
        </div>
      </div>
      {catalog.error && <ErrorNote error={catalog.error} onRetry={catalog.reload} />}
      {!catalog.data && !catalog.error && <Skeleton h={200} />}

      {catalog.data && (
        <div className="grid g-1-1">
          <div className="stack" style={{ gap: 10 }}>
            <div className="section-title" style={{ marginBottom: 0 }}>Choose an attack</div>
            {catalog.data.map((s) => (
              <button key={s.id} className={`scn${picked === s.id ? " on" : ""}`} onClick={() => setPicked(s.id)} aria-pressed={picked === s.id}>
                <div className="row">
                  <span className="id">{s.id}</span>
                  <b>{s.name}</b>
                </div>
                <div className="cell-sub" style={{ marginTop: 6, marginLeft: 36 }}>Agent: {s.agent} · targets <span className="mono">{s.unsafe_tool}</span></div>
              </button>
            ))}
          </div>

          <div className="card" style={{ alignSelf: "start" }}>
            <div className="card-head"><h3>Scenario {picked}</h3></div>
            {scenario && (
              <div className="stack" style={{ gap: 14 }}>
                <div>
                  <div className="section-title">The agent is asked</div>
                  <p className="soft">“{scenario.task}”</p>
                </div>
                <div>
                  <div className="section-title">Hidden in the data it reads</div>
                  <div className="hostile">{scenario.hostile_text}</div>
                </div>
                <div>
                  <div className="section-title">Unsafe calls that will be attempted</div>
                  <div className="row wrap">
                    {scenario.planned_calls.map((c) => <span key={c.call_id} className="tag mono">{c.call_id} · {c.tool}</span>)}
                  </div>
                </div>
                <label className="row soft" style={{ fontSize: 13, gap: 8 }}>
                  <input type="checkbox" checked={useLlm} onChange={(e) => setUseLlm(e.target.checked)} />
                  Write the investigation with Gemini (needs <span className="mono">GEMINI_API_KEY</span>; off = built-in summary)
                </label>
                <button className="btn btn-primary" onClick={() => void run()} disabled={running}>
                  <Icon name={running ? "refresh" : "play"} size={16} /> {running ? "Running attack…" : "Run attack"}
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {error && <ErrorNote error={error} onRetry={() => void run()} />}
      {running && !result && <Skeleton h={220} />}
      {!result && !running && !error && catalog.data && (
        <div className="card"><Empty icon="flask" title="No run yet" hint="Pick a scenario and press “Run attack” to see decisions, evidence and the investigation." /></div>
      )}
      {result && <Result res={result} />}
    </div>
  );
}
