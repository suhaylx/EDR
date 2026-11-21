package edr

import (
    "errors"
    "net/http"
    "time"
)

// AgentIdentityHandler is an mTLS-only identity probe. It MUST be placed behind
// direct TLS configured with tls.RequireAndVerifyClientCert and a controlled
// agent CA. A bearer token or request-supplied tenant/device ID cannot act as
// agent identity. This probe does not enroll devices or authorize telemetry.
func AgentIdentityHandler(registry AgentIdentityRegistry) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Cache-Control", "no-store")
        if r.Method != http.MethodGet {
            w.Header().Set("Allow", http.MethodGet)
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        if registry == nil {
            http.Error(w, "agent identity registry unavailable", http.StatusServiceUnavailable)
            return
        }
        identity, err := VerifyAgentCertificate(r.Context(), r.TLS, registry, time.Now().UTC())
        if errors.Is(err, ErrAgentRegistryUnavailable) {
            http.Error(w, "agent identity registry unavailable", http.StatusServiceUnavailable)
            return
        }
        if err != nil {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        reply(w, http.StatusOK, map[string]string{
            "tenant_id": identity.TenantID,
            "agent_id": identity.AgentID,
        })
    })
}
