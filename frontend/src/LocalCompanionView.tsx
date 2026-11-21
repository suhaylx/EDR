import type { LocalCompanionSnapshot } from './local-companion.js';
import { localCompanionPresentation, localCompanionRows } from './local-companion.js';

/**
 * Unprivileged status-window presentation. No IPC or endpoint actions.
 * A trusted native host may provide a verified snapshot only after Agent 2
 * implements transport identity, authorization, replay defense and timeouts.
 */
export function LocalCompanionView({
  snapshot, nowMs,
}: {
  snapshot: LocalCompanionSnapshot | null;
  nowMs: number;
}) {
  const presentation = localCompanionPresentation(snapshot, nowMs);
  const rows = localCompanionRows(snapshot, nowMs);
  return <main className="companion-shell">
    <header className="companion-heading">
      <p className="eyebrow">TURANSEC / ENDPOINT COMPANION</p>
      <h1>Device security status</h1>
      <p className="companion-description">A read-only, unprivileged status-window prototype for the
        single TuranSec endpoint product. The Rust core owns scanning, telemetry and policies.</p>
      <p className="companion-lab-mark">UI PROTOTYPE — NOT CONNECTED TO THE AGENT</p>
    </header>
    <section aria-labelledby="companion-connection-title" className="panel companion-connection">
      <h2 id="companion-connection-title">Local connection</h2>
      <div className={'companion-state companion-state--' + presentation.status}
        role="status" aria-live="polite" aria-atomic="true">
        <strong>{presentation.heading}</strong>
        <p>{presentation.explanation}</p>
      </div>
      <p className="minor">A reported status is not cryptographic authentication or
        a confirmation that endpoint protection is working.</p>
    </section>
    <section aria-labelledby="companion-components-title" className="panel">
      <h2 id="companion-components-title">Component evidence</h2>
      <p>All statuses remain unknown unless a current, authenticated local status
        channel is available. This prototype does not open such a channel.</p>
      <dl className="companion-details">
        {rows.map(row => <div className="companion-detail" key={row.key}>
          <dt>{row.label}</dt>
          <dd><strong>{row.value}</strong><span className="minor">{row.detail}</span></dd>
        </div>)}
      </dl>
    </section>
    <section aria-labelledby="companion-boundary-title" className="panel companion-boundary">
      <h2 id="companion-boundary-title">Security boundary</h2>
      <p>Scan requests, quarantine, policy changes, network isolation and disabling
        protection are not available in this UI. Closing a future companion window
        must not stop the Rust service. ClamAV and telemetry services can remain
        separate managed processes without creating another endpoint product.</p>
      <p className="minor">Windows: planned native tray/window. Linux: optional
        desktop window, tray only where supported. No tray integration, authenticated
        IPC, Windows or Linux installer, real-time updates or live agent health are implemented.</p>
    </section>
  </main>;
}
