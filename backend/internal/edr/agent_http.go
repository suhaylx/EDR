package edr

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// agentIdentityContextKey cannot be set by a client-controlled HTTP header.
type agentIdentityContextKey struct{}

// AgentIdentityFromContext returns an authenticated endpoint principal passed
// from AgentHTTPGuard to a downstream agent-only handler.
func AgentIdentityFromContext(ctx context.Context) (AgentIdentity, bool) {
	identity, ok := ctx.Value(agentIdentityContextKey{}).(AgentIdentity)
	return identity, ok && identity.TenantID != "" && identity.AgentID != ""
}

// AgentHTTPGuard is a fail-closed authorization boundary for a future,
// separately mounted agent API. It is NOT connected to the current lab server.
// A real listener must first use RequireAndVerifyClientCert and a controlled
// agent CA; VerifyAgentCertificate additionally binds the verified leaf to an
// enrolled non-revoked tenant/device fingerprint.
//
// All downstream agent routes MUST use canonical, unescaped paths beginning:
// /agent/v1/tenants/{tenant_id}/agents/{agent_id}/{operation}
// The path tenant/device must match the authenticated certificate registration.
// This wrapper never authorizes the operator/dashboard API.
func AgentHTTPGuard(registry AgentIdentityRegistry, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if registry == nil || next == nil {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		identity, err := VerifyAgentCertificate(r.Context(), r.TLS, registry, time.Now().UTC())
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, ErrAgentRegistryUnavailable) {
				status = http.StatusServiceUnavailable
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		requested, ok := agentRouteIdentity(r.URL)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if requested != identity {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), agentIdentityContextKey{}, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func agentRouteIdentity(u *url.URL) (AgentIdentity, bool) {
	if u == nil || u.RawPath != "" || u.EscapedPath() != u.Path {
		return AgentIdentity{}, false
	}
	p := strings.Split(u.Path, "/")
	if len(p) < 8 || p[0] != "" || p[1] != "agent" || p[2] != "v1" ||
		p[3] != "tenants" || p[5] != "agents" || !validID(p[4]) || !validID(p[6]) ||
		p[4] == "." || p[4] == ".." || p[6] == "." || p[6] == ".." {
		return AgentIdentity{}, false
	}
	for _, part := range p[7:] {
		if !validID(part) || part == "." || part == ".." {
			return AgentIdentity{}, false
		}
	}
	return AgentIdentity{TenantID: p[4], AgentID: p[6]}, true
}
