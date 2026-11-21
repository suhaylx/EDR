# Lab dashboard session after browser refresh

**Scope:** TuranSec EDR laboratory Go/SOC dashboard only. The shared `EDR_DEV_TOKEN` is not production authentication and must never be entered over public plaintext HTTP.

The previous frontend kept the development bearer token in a JavaScript variable. Browser refresh reset it and showed “Enter the API token above” even though the Go backend was healthy. Telemetry in the server's in-memory store was unchanged by a browser refresh.

## New behavior

- A visible **Remember this tab** checkbox is checked by default only when the dashboard is accessed through HTTPS or via loopback (`http://127.0.0.1:18080` / `http://localhost:18080` using an SSH tunnel). If checked, the token is stored in **browser sessionStorage**; it survives a page refresh in the same tab session. The browser may preserve this storage during session restoration; never rely on tab closure as secure revocation.
- On an insecure public HTTP origin such as `http://<server-ip>:8080`, token entry/Connect are disabled with a visible warning. Do not use the raw public development API. The Go listener may bind `0.0.0.0` for a restricted lab, but firewall rules must deny public inbound TCP 8080; HTTPS or SSH/VPN access is required.
- **Disconnect** removes the remembered token, clears in-memory dashboard state and returns to Connect. A rejected/rotated token (HTTP 401) also clears it.
- If sessionStorage is blocked by the browser, the token remains memory-only for that load; connection and refresh still work but the next page reload requires re-entry.
- The token is never placed in a URL, localStorage, a cookie, logs or repository files. sessionStorage remains readable to JavaScript and is not a defense against XSS, browser compromise or malicious extensions. This is not production session management.

## Deployment to the running Ubuntu dashboard (without replacing the Go binary)

After reviewing the PR, on the Ubuntu host that already serves `backend/web` from `/opt/turansec-edr/web`, update the **frontend asset files only**:

```bash
# Use the authorized review branch and private GitHub deploy key.
cd ~/turansec-edr
git fetch origin feat/ui-lab-session-refresh-20261121
git switch --detach FETCH_HEAD
node --test backend/web/auth-session.test.cjs # optional if Node is installed
sudo install -m 0644 backend/web/app.js backend/web/index.html \
  backend/web/styles.css backend/web/auth-session.js /opt/turansec-edr/web/
```

The Go `http.FileServer` reads these files on request, so no backend restart is normally needed. If you installed to a different `EDR_WEB_DIR`, use that verified directory instead. Hard-refresh via localhost or HTTPS to load the new JS. Keep the existing Go version and in-memory data intact.

## QA acceptance

1. Through the local SSH tunnel, visit `http://127.0.0.1:18080`; provide the development token and Connect.
2. With Remember this tab selected, reload/F5. Dashboard should auto-reconnect and display the same available lab metrics.
3. Disconnect, reload/F5: the token must not return.
4. Enter an incorrect token: HTTP 401 clears the remembered session and prompts re-entry.
5. Visit the server's public `http://<server-ip>:8080`: Connect must be disabled with an unsafe HTTP warning. Public inbound port 8080 should already be blocked externally.
6. Check no token appears in the URL, console output, Git history, or HTTP server logs. Avoid pasting secrets into a bug report.

Automated tests: `node --test backend/web/auth-session.test.cjs`. No external JS packages are required.
