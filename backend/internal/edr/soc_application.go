package edr

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

// SOCApplicationHandler serves the built React application and operator API
// from one mTLS origin. Every request, including static assets and session
// discovery, rechecks the certificate fingerprint in the read-only registry.
// The tenant and role are never accepted from browser storage or headers.
func SOCApplicationHandler(registryDB, runtimeDB *sql.DB, ui fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if registryDB == nil || runtimeDB == nil || ui == nil {
			http.Error(w, "service unavailable", 503)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		p, err := verifySOCOperator(ctx, r.TLS, registryDB, time.Now().UTC())
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, errSOCRegistryUnavailable) {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		// Browser certificates are ambient credentials. Reject cross-origin browser
		// requests before either read or mutation; native mTLS clients omit Origin.
		origin := r.Header.Get("Origin")
		if (origin != "" && origin != "https://"+r.Host) ||
			r.Header.Get("Sec-Fetch-Site") == "cross-site" || r.Header.Get("Sec-Fetch-Site") == "same-site" {
			http.Error(w, "forbidden", 403)
			return
		}
		if r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path {
			http.NotFound(w, r)
			return
		}
		guarded := r.WithContext(context.WithValue(ctx, socOperatorContextKey{}, p))
		guarded.Header = r.Header.Clone()
		for name := range guarded.Header {
			low := strings.ToLower(name)
			if untrustedAgentIdentityHeader(low) || low == "x-operator-role" || low == "x-operator-id" {
				delete(guarded.Header, name)
			}
		}
		if r.URL.Path == "/soc/v1/session" {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				http.Error(w, "method not allowed", 405)
				return
			}
			if r.URL.RawQuery != "" {
				http.Error(w, "invalid query", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				TenantID   string `json:"tenant_id"`
				OperatorID string `json:"operator_id"`
				Role       string `json:"role"`
				ServerTime string `json:"server_time"`
			}{p.TenantID, p.OperatorID, p.Role, time.Now().UTC().Format(time.RFC3339)})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/soc/v1/") {
			tenant, ok := socTenantRoute(r.URL)
			if !ok {
				http.NotFound(w, r)
				return
			}
			if tenant != p.TenantID {
				http.Error(w, "forbidden", 403)
				return
			}
			serveSOCTransaction(w, guarded, runtimeDB)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", 405)
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "invalid query", 400)
			return
		}
		name := ""
		switch {
		case r.URL.Path == "/" || r.URL.Path == "/soc/":
			name = "index.html"
		case strings.HasPrefix(r.URL.Path, "/assets/"):
			name = strings.TrimPrefix(r.URL.Path, "/")
			if !fs.ValidPath(name) || strings.Contains(name, "\\") {
				http.NotFound(w, r)
				return
			}
		default:
			http.NotFound(w, r)
			return
		}
		// Serve only regular build artifacts, with no directory listing or SPA
		// fallback for arbitrary API/lab paths. Configuration is outside this FS.
		stat, e := fs.Stat(ui, name)
		if e != nil || !stat.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		http.ServeFileFS(w, guarded, ui, name)
	})
}
