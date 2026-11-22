package edr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// AgentAuthenticatedScanHandler binds a verified leaf to the complete write
// transaction. Certificate rotation/revocation serializes with every mutation.
func AgentAuthenticatedScanHandler(registryDB, runtimeDB *sql.DB) http.Handler {
	return AgentHTTPGuard(PostgresAgentIdentityRegistry{DB: registryDB}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/scan-jobs/complete") {
			http.Error(w, "boolean completion is retired; explicit scan result required", http.StatusGone)
			return
		}
		if r.Method == http.MethodGet {
			AgentScanQueueHandler(PostgresScanJobQueue{DB: runtimeDB}).ServeHTTP(w, r)
			return
		}
		principal, ok := AgentIdentityFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", 401)
			return
		}
		certificateTransaction(w, r, runtimeDB,
			`SELECT public.edr_authorize_agent_certificate($1,$2,$3)`,
			[]any{principal.TenantID, principal.AgentID},
			func(tx *sql.Tx) http.Handler { return AgentScanQueueHandler(PostgresScanJobQueue{DB: tx}) })
	}))
}

func serveSOCTransaction(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		SOCScanHandler(PostgresScanJobQueue{DB: db}).ServeHTTP(w, r)
		return
	}
	p, ok := socPrincipal(r.Context())
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	certificateTransaction(w, r, db,
		`SELECT public.edr_authorize_operator_certificate($1,$2,$3,$4)`,
		[]any{p.TenantID, p.OperatorID, p.Role},
		func(tx *sql.Tx) http.Handler { return SOCScanHandler(PostgresScanJobQueue{DB: tx}) })
}

type heldResponse struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	overflow bool
}

func (h *heldResponse) Header() http.Header { return h.header }
func (h *heldResponse) WriteHeader(status int) {
	if h.status == 0 {
		h.status = status
	}
}
func (h *heldResponse) Write(b []byte) (int, error) {
	if h.status == 0 {
		h.status = http.StatusOK
	}
	if h.body.Len()+len(b) > 64<<10 {
		h.overflow = true
		return 0, io.ErrShortBuffer
	}
	return h.body.Write(b)
}
func (h *heldResponse) flush(w http.ResponseWriter) {
	for name, values := range h.header {
		w.Header()[name] = append([]string(nil), values...)
	}
	status := h.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(h.body.Bytes())
}

func certificateTransaction(w http.ResponseWriter, r *http.Request, db *sql.DB, query string, identity []any, next func(*sql.Tx) http.Handler) {
	if db == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil {
		http.Error(w, "service unavailable", 503)
		return
	}
	// Complete a bounded body read BEFORE acquiring identity row locks. The
	// listener's read timeout bounds a slow sender; no slow body holds DB locks.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "payload too large", 413)
		} else {
			http.Error(w, "invalid payload", 400)
		}
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		http.Error(w, "service unavailable", 503)
		return
	}
	defer tx.Rollback() // Includes handler panic, request cancellation and errors.
	digest := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	args := append([]any{}, identity[:2]...)
	args = append(args, digest[:])
	args = append(args, identity[2:]...)
	var allowed bool
	if err = tx.QueryRowContext(ctx, query, args...).Scan(&allowed); err != nil {
		http.Error(w, "service unavailable", 503)
		return
	}
	if !allowed {
		http.Error(w, "unauthorized", 401)
		return
	}
	// A client leaf can expire while its body is received or while database
	// authorization waits for a revocation lock. Recheck its actual validity
	// at the authorization point, including operators without DB date columns.
	leaf := r.TLS.PeerCertificates[0]
	now := time.Now().UTC()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		http.Error(w, "unauthorized", 401)
		return
	}
	guarded := r.WithContext(ctx)
	guarded.Body = io.NopCloser(bytes.NewReader(body))
	response := &heldResponse{header: make(http.Header)}
	next(tx).ServeHTTP(response, guarded)
	if response.overflow {
		http.Error(w, "service unavailable", 503)
		return
	}
	if response.status >= 400 {
		_ = tx.Rollback()
		response.flush(w)
		return
	}
	// No success or lease token leaves the process until COMMIT succeeds.
	if err = tx.Commit(); err != nil {
		http.Error(w, "service unavailable", 503)
		return
	}
	response.flush(w)
}
