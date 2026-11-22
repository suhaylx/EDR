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
export function AdminPackageGenerator({ session }: { session: PasswordSession }) {
  const [platform, setPlatform] = useState<'windows'|'linux'>('windows');
  const [agentID, setAgentID] = useState('');
  const [available, setAvailable] = useState<Record<string, boolean>>({});
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let cancelled = false;
    void fetch('/auth/agent-platforms', { credentials: 'same-origin', cache: 'no-store' })
      .then(res => res.ok ? res.json() as Promise<Record<string, boolean>> : Promise.reject())
      .then(data => { if (!cancelled) setAvailable(data); })
      .catch(() => { if (!cancelled) setMessage('Package generation service is unavailable.'); });
    return () => { cancelled = true; };
  }, []);
  if (session.role !== 'admin') return null;
  const generate = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!/^[A-Za-z0-9_.-]{1,96}$/.test(agentID) || ['.', '..'].includes(agentID)) { setMessage('Enter a valid endpoint ID.'); return; }
    setBusy(true);
    setMessage('');
    try {
      const response = await fetch('/auth/agent-generate', {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { 'Content-Type': 'application/json', 'X-TuranSec-CSRF': session.csrf_token },
        body: JSON.stringify({ tenant_id: 'lab', agent_id: agentID, platform }),
      });
      if (response.status !== 200 || !response.headers.get('content-type')?.startsWith('application/zip')) {
        setMessage(response.status === 503 ? 'Missing approved TuranSec, ClamAV or Sysmon payloads on the server.' : 'Generation was denied.');
        return;
      }
      const blob = await response.blob();
      const objectURL = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objectURL;
      a.download = 'TuranSec-' + platform + '-' + agentID + '.zip';
      a.click();
      setTimeout(() => URL.revokeObjectURL(objectURL), 500);
      setMessage('Endpoint bootstrap bundle generated. Issuer enrollment and signing checks remain required.');
    } catch { setMessage('Generation failed; no package was confirmed.'); }
    finally { setBusy(false); }
  };
  return <section className="panel" aria-labelledby="agent-gen-title">
    <h2 id="agent-gen-title">Generate endpoint agent package (admin)</h2>
    <p>Packages include the TuranSec setup and pinned, independently approved ClamAV and Sysmon payloads. The server never embeds CA private keys or agent credentials.</p>
    <form className="form" onSubmit={e => { void generate(e); }}>
      <label htmlFor="agent-gen-os">Platform</label>
      <select id="agent-gen-os" value={platform} onChange={e => setPlatform(e.target.value as typeof platform)}>
        <option value="windows">Windows x64 — agent + ClamAV + Sysmon</option>
        <option value="linux">Ubuntu 24.04 — agent + ClamAV + Sysmon for Linux</option>
      </select>
      <label htmlFor="agent-gen-id">Endpoint ID</label>
      <input id="agent-gen-id" value={agentID} onChange={e => setAgentID(e.target.value)} placeholder="win-001" maxLength={96} required />
      <button type="submit" disabled={busy || !available[platform] || !agentID}>{busy ? 'Generating…' : available[platform] ? 'Generate 3-in-1 bundle' : 'Approved payloads not yet staged'}</button>
      <p role="status">{message}</p>
      <p className="minor">This is a staged deployment bundle, not an automatically enrolled or independently signed installer. A security administrator must approve all three payloads before generation is enabled.</p>
    </form>
  </section>;
}
