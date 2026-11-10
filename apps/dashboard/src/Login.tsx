import { useState } from "react";
import { login, ApiError } from "./api";
import { Icon } from "./ui";

export default function Login({ onDone }: { onDone: () => void }) {
  const [user, setUser] = useState("approver");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(user.trim(), password);
      onDone();
    } catch (err) {
      const e = err as ApiError;
      setError(e.status === 401 ? "That username or password is not correct." : e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <section className="login-art">
        <div className="brand">
          <div className="brand-mark">
            <Icon name="shield" size={22} />
          </div>
          <div>
            <b>Agent Firewall</b>
            <span>Security console</span>
          </div>
        </div>
        <h1>
          Every agent action, <em>checked before it happens.</em>
        </h1>
        <p>See what your AI agents tried to do, what was stopped, and prove that the record has not been altered.</p>
        <div className="pillars">
          <div className="pillar">
            <div className="ic"><Icon name="lock" /></div>
            <div><b>Deterministic policy</b><span>Allow, block or ask a human — decided by rules, never by a model.</span></div>
          </div>
          <div className="pillar">
            <div className="ic"><Icon name="link" /></div>
            <div><b>Tamper-evident audit</b><span>A hash chain makes silent edits and deletions visible.</span></div>
          </div>
          <div className="pillar">
            <div className="ic"><Icon name="flask" /></div>
            <div><b>Attack lab</b><span>Replay a prompt-injection attack and watch the gateway respond.</span></div>
          </div>
        </div>
      </section>

      <section className="login-form">
        <form onSubmit={submit}>
          <div>
            <h2>Sign in</h2>
            <p className="muted">Use the approver login configured for this deployment.</p>
          </div>
          {error && (
            <div className="note note-bad" role="alert">
              <Icon name="alert" />
              <div>{error}</div>
            </div>
          )}
          <div className="field">
            <label htmlFor="u">Username</label>
            <input id="u" className="input" value={user} onChange={(e) => setUser(e.target.value)} autoComplete="username" required />
          </div>
          <div className="field">
            <label htmlFor="p">Password</label>
            <input id="p" className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus required />
          </div>
          <button className="btn btn-primary" disabled={busy || !password}>
            {busy ? <Icon name="refresh" /> : <Icon name="lock" />} {busy ? "Signing in…" : "Sign in"}
          </button>
          <p className="muted" style={{ fontSize: 12.5 }}>
            Over plain HTTP this login is only suitable for a local demo. Put TLS in front of it for anything else.
          </p>
        </form>
      </section>
    </div>
  );
}
