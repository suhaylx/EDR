import React, { useEffect, useState } from 'react';

export type PasswordSession = Readonly<{ username: 'admin' | 'analyst' | 'viewer'; role: 'admin' | 'analyst' | 'viewer'; csrf_token: string }>;
const validSession = (value: unknown): value is PasswordSession => {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  return ['admin', 'analyst', 'viewer'].includes(String(v.username)) && v.role === v.username &&
    typeof v.csrf_token === 'string' && /^[0-9a-f]{64}$/.test(v.csrf_token);
};
export async function getPasswordSession(): Promise<{ mode: 'password' | 'legacy' | 'error'; session: PasswordSession | null }> {
  try {
    const response = await fetch('/auth/session', { credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
    if (response.status === 404) return { mode: 'legacy', session: null };
    if (response.status === 401) return { mode: 'password', session: null };
    if (response.status !== 200) return { mode: 'error', session: null };
    const value: unknown = await response.json();
    return validSession(value) ? { mode: 'password', session: value } : { mode: 'error', session: null };
  } catch {
    return { mode: 'error', session: null };
  }
}
export function PasswordLogin({ onAuthenticated }: { onAuthenticated: (session: PasswordSession) => void }) {
  const [user, setUser] = useState<'admin'|'analyst'|'viewer'>('analyst');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const login = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      const response = await fetch('/auth/login', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ username: user, password }),
      });
      setPassword('');
      if (response.status !== 200) { setError(response.status === 429 ? 'Too many attempts. Try later.' : 'Login denied. Check credentials.'); return; }
      const value: unknown = await response.json();
      if (!validSession(value) || value.username !== user) { setError('Unexpected login response.'); return; }
      onAuthenticated(value);
    } catch {
      setPassword('');
      setError('Cannot reach the secured login service.');
    } finally { setBusy(false); }
  };
  return <main className="layout soc-auth-shell">
    <div className="soc-auth-intro"><div className="soc-auth-logo" aria-hidden="true">T</div><p className="eyebrow">TURANSEC / SECURITY OPERATIONS</p>
      <h2>Security visibility. One workspace.</h2><p>Investigate detections, monitor endpoint health, and coordinate trusted response operations.</p>
      <div className="soc-auth-footnote">LOCAL LAB · HTTPS PROTECTED</div>
    </div>
    <div className="panel soc-auth-card">
      <p className="eyebrow">OPERATOR ACCESS</p>
      <h1>Sign in to SOC</h1>
      <p>Choose your role and sign in with your local operator password. No client certificate import is needed.</p>
      <form className="form" onSubmit={e => { void login(e); }}>
        <label htmlFor="soc-user">Account</label>
        <select id="soc-user" value={user} onChange={e => setUser(e.target.value as typeof user)}>
          <option value="admin">Admin</option><option value="analyst">Analyst</option><option value="viewer">Viewer</option>
        </select>
        <label htmlFor="soc-pass">Password</label>
        <input id="soc-pass" type="password" value={password} onChange={e => setPassword(e.target.value)}
          minLength={1} autoComplete="current-password" required />
        <button type="submit" disabled={busy || !password}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <p role="alert" aria-live="polite" className="feedback">{error}</p>
      </form>
      <p className="minor">Passwords were generated at install time and saved in the host-only .docker-local/operator/passwords.txt file. Never paste them into chat.</p>
    </div>
  </main>;
}
type AgentPlatformReadiness = Readonly<{
  windows: boolean;
  linux: boolean;
  setup_kit: boolean;
  missing: Readonly<Record<'windows' | 'linux', readonly string[]>>;
}>;

export function AdminPackageGenerator({ session }: { session: PasswordSession }) {
  const [platform, setPlatform] = useState<'windows'|'linux'>('windows');
  const [agentID, setAgentID] = useState('');
  const [readiness, setReadiness] = useState<AgentPlatformReadiness | null>(null);
  const [checking, setChecking] = useState(false);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const refresh = async () => {
    setChecking(true);
    try {
      const res = await fetch('/auth/agent-platforms', {
        credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      });
      if (!res.ok) throw new Error('Unreachable package service');
      const result: unknown = await res.json();
      if (!result || typeof result !== 'object') throw new Error('Unexpected package status');
      const obj = result as Record<string, unknown>;
      const missing = obj.missing;
      if (typeof obj.windows !== 'boolean' || typeof obj.linux !== 'boolean' ||
        !missing || typeof missing !== 'object' ||
        !Array.isArray((missing as Record<string, unknown>).windows) ||
        !Array.isArray((missing as Record<string, unknown>).linux)) {
        throw new Error('Unexpected package status');
      }
      setReadiness(result as AgentPlatformReadiness);
      setMessage('');
    } catch {
      setReadiness(null);
      setMessage('Could not check approved package files. The setup kit can still be requested.');
    } finally { setChecking(false); }
  };
  useEffect(() => { void refresh(); }, []);
  const generate = async (bundleType: 'setup_kit' | 'complete') => {
    if (busy) return;
    if (!/^[A-Za-z0-9_.-]{1,96}$/.test(agentID) || ['.', '..'].includes(agentID)) {
      setMessage('Enter a valid endpoint ID.'); return;
    }
    if (bundleType === 'complete' && !readiness?.[platform]) {
      setMessage('A complete 3-in-1 package needs the three approved vendor and TuranSec binaries first.'); return;
    }
    setBusy(true);
    setMessage('');
    try {
      const response = await fetch('/auth/agent-generate', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { 'Content-Type': 'application/json', 'X-TuranSec-CSRF': session.csrf_token },
        body: JSON.stringify({ tenant_id: 'lab', agent_id: agentID, platform, bundle_type: bundleType }),
      });
      if (!response.ok || !response.headers.get('content-type')?.startsWith('application/zip')) {
        setMessage(response.status === 503
          ? 'Approved binaries are missing or invalid; refresh package status to see what is required.'
          : response.status === 401 || response.status === 403
            ? 'Sign in again with an administrator account.'
            : 'The package service rejected this request.');
        return;
      }
      const blob = await response.blob();
      const objectURL = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = objectURL;
      link.download = 'TuranSec-' + (bundleType === 'complete' ? '3in1-' : 'setup-kit-') + platform + '-' + agentID + '.zip';
      link.click();
      setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
      setMessage(bundleType === 'complete'
        ? 'Complete offline 3-in-1 ZIP downloaded. Independently verify vendor signatures and enroll the endpoint before installation.'
        : 'Preparation kit downloaded. It is NOT an installable agent: the TuranSec, ClamAV and Sysmon executables must be approved and staged first.');
    } catch { setMessage('Download failed; no package was confirmed.'); }
    finally { setBusy(false); }
  };
  if (session.role !== 'admin') return null;
  const missing = readiness?.missing[platform] ?? [];
  return <section className="panel" aria-labelledby="agent-gen-title">
    <h2 id="agent-gen-title">Endpoint package generator</h2>
    <p>Prepare a Windows or Linux endpoint immediately, or download the complete TuranSec + ClamAV + Sysmon offline bundle once all three approved binaries have been staged.</p>
    <form className="form" onSubmit={event => { event.preventDefault(); void generate('setup_kit'); }}>
      <label htmlFor="agent-gen-os">Target operating system</label>
      <select id="agent-gen-os" value={platform} onChange={e => setPlatform(e.target.value as typeof platform)}>
        <option value="windows">Windows x64 — TuranSec + ClamAV + Sysmon</option>
        <option value="linux">Ubuntu 24.04 — TuranSec + ClamAV + Sysmon for Linux</option>
      </select>
      <label htmlFor="agent-gen-id">Endpoint ID</label>
      <input id="agent-gen-id" value={agentID} onChange={e => setAgentID(e.target.value)} placeholder={platform === 'windows' ? 'win-001' : 'linux-001'} maxLength={96} required />
      <div className="actions">
        <button type="submit" disabled={busy || !agentID.trim()}>
          {busy ? 'Preparing download…' : 'Download preparation kit'}
        </button>
        <button type="button" disabled={busy || !agentID.trim() || !readiness?.[platform]}
          onClick={() => { void generate('complete'); }}>
          Download complete 3-in-1 agent
        </button>
      </div>
      <p role="status" aria-live="polite">{message}</p>
    </form>
    <div className="soc-package-readiness">
      <div className="heading"><h3>Full package readiness: {readiness?.[platform] ? 'Ready' : checking ? 'Checking…' : 'Not ready'}</h3>
        <button className="secondary" type="button" disabled={checking} onClick={() => { void refresh(); }}>Recheck files</button></div>
      {readiness && !readiness[platform] && <>
        <p>Missing or invalid approved files on the SOC host:</p>
        <ul>{missing.map(name => <li key={name}><code>{name}</code></li>)}</ul>
        <p className="minor">Stage approved binaries and <code>approved.json</code> in <code>.docker-local/payloads/{platform}/</code> on the server. Verify vendor origin, signatures and hashes independently. Recheck files to enable the complete ZIP.</p>
      </>}
      {readiness?.[platform] && <p>All three staged binaries passed manifest checks. Publisher verification, endpoint certificate issuance, and on-device acceptance remain mandatory.</p>}
      <p className="minor">The preparation kit includes endpoint metadata, a platform-specific installation script and a component checklist, but NO executable agent or vendor binaries. It cannot be installed until a complete package is generated. Neither kit contains private CA keys, passwords, or enrollment credentials.</p>
    </div>
  </section>;
}
