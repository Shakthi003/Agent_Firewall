import { Suspense, lazy, useEffect, useState } from "react";
import { api, hasSession, logout, setUnauthorizedHandler } from "./api";
import Login from "./Login";
import Overview from "./pages/Overview";
import Audit from "./pages/Audit";
import Approvals from "./pages/Approvals";
import Alerts from "./pages/Alerts";
import Policies from "./pages/Policies";
import { Icon, Skeleton, usePoll } from "./ui";

const Lab = lazy(() => import("./pages/Lab")); // the biggest page loads only when opened

type Page = "overview" | "audit" | "approvals" | "alerts" | "policies" | "lab";
const PAGES: { id: Page; label: string; icon: string; title: string; sub: string }[] = [
  { id: "overview", label: "Overview", icon: "grid", title: "Overview", sub: "How the gateway is protecting your agents" },
  { id: "audit", label: "Audit log", icon: "list", title: "Audit log", sub: "Every decision, with the reason and the policy that made it" },
  { id: "approvals", label: "Approvals", icon: "inbox", title: "Approvals", sub: "Risky requests waiting for a human decision" },
  { id: "alerts", label: "Alerts", icon: "bell", title: "Alerts", sub: "Unusual behaviour spotted by the monitor" },
  { id: "policies", label: "Policies", icon: "lock", title: "Policies and agents", sub: "Who may use which tool, and the rules applied to each call (read-only)" },
  { id: "lab", label: "Attack lab", icon: "flask", title: "Attack lab", sub: "Replay a prompt-injection attack against the real gateway" },
];

const fromHash = (): Page => (PAGES.find((p) => `#/${p.id}` === window.location.hash)?.id ?? "overview");

function Console({ onLogout }: { onLogout: () => void }) {
  const [page, setPage] = useState<Page>(fromHash);
  const [focusSeq, setFocusSeq] = useState<number | null>(null);
  const counts = usePoll(() => api.overview(), 15000);
  const who = usePoll(() => api.session(), null);

  useEffect(() => {
    const on = () => setPage(fromHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);

  const go = (p: Page) => {
    window.location.hash = `#/${p}`;
    setPage(p);
  };
  const current = PAGES.find((p) => p.id === page)!;
  const pending = counts.data?.pending_approvals ?? 0;
  const alerts = counts.data?.alerts ?? 0;

  return (
    <div className="shell">
      <nav className="side" aria-label="Main">
        <div className="brand">
          <div className="brand-mark">
            <Icon name="shield" size={20} />
          </div>
          <div>
            <b>Agent Firewall</b>
            <span>Security console</span>
          </div>
        </div>
        <div className="nav-label">Monitor</div>
        {PAGES.map((p) => (
          <button key={p.id} className={`nav-item${page === p.id ? " on" : ""}`} onClick={() => go(p.id)} aria-current={page === p.id ? "page" : undefined}>
            <Icon name={p.icon} />
            {p.label}
            {p.id === "approvals" && pending > 0 && <span className="count">{pending}</span>}
            {p.id === "alerts" && alerts > 0 && <span className="count red">{alerts}</span>}
          </button>
        ))}
        <div className="side-foot">
          <div className="who">
            <div className="avatar">
              <Icon name="user" size={16} />
            </div>
            <div>
              <b style={{ fontSize: 13 }}>{who.data?.user ?? "…"}</b>
              <div className="muted" style={{ fontSize: 12 }}>Approver</div>
            </div>
          </div>
          <button className="btn btn-ghost btn-sm" style={{ width: "100%" }} onClick={onLogout}>
            <Icon name="out" size={16} /> Sign out
          </button>
        </div>
      </nav>

      <main className="main">
        <header className="topbar">
          <div>
            <h1>{current.title}</h1>
            <div className="sub">{current.sub}</div>
          </div>
          <div className="right">
            {counts.data?.policy_version && (
              <span className="tag mono" title="Policy version of the most recent decisions">
                policy {counts.data.policy_version.slice(0, 12)}
              </span>
            )}
          </div>
        </header>

        {page === "overview" && <Overview counts={counts} onOpenPage={go} onOpenEvent={(s) => { setFocusSeq(s); go("audit"); }} />}
        {page === "audit" && <Audit focusSeq={focusSeq} onFocusDone={() => setFocusSeq(null)} />}
        {page === "approvals" && <Approvals onChanged={counts.reload} />}
        {page === "alerts" && <Alerts onOpenEvent={(s) => { setFocusSeq(s); go("audit"); }} />}
        {page === "policies" && <Policies />}
        {page === "lab" && (
          <Suspense fallback={<Skeleton h={320} />}>
            <Lab />
          </Suspense>
        )}
      </main>
    </div>
  );
}

export default function App() {
  const [signedIn, setSignedIn] = useState(hasSession());
  useEffect(() => {
    setUnauthorizedHandler(() => {
      logout();
      setSignedIn(false);
    });
  }, []);
  if (!signedIn) return <Login onDone={() => setSignedIn(true)} />;
  return (
    <Console
      onLogout={() => {
        logout();
        setSignedIn(false);
      }}
    />
  );
}
