package edr

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

func TestSOCApplicationSessionStaticAndBrowserBoundary(t *testing.T) {
	leaf, cert, pool := createTestAgentCertificate(t, time.Now(), []string{"spiffe://turansec.local/tenants/tenantA/operators/analyst"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	fp := sha256.Sum256(leaf.Raw)
	var revoked atomic.Bool
	db := scanDB(t, func(query string, args []driver.NamedValue) (driver.Rows, error) {
		if !strings.Contains(query, "FROM edr_soc_operators") {
			t.Errorf("unexpected SQL %s", query)
		}
		if revoked.Load() {
			return &scanRows{columns: []string{"fingerprint", "role"}}, nil
		}
		return &scanRows{columns: []string{"fingerprint", "role"}, values: [][]driver.Value{{fp[:], "viewer"}}}, nil
	})
	ui := fstest.MapFS{"index.html": {Data: []byte("<main>Operator SOC</main>")}, "assets/app.js": {Data: []byte("export {}")}, "private.json": {Data: []byte("must not be served")}}
	server := httptest.NewUnstartedServer(SOCApplicationHandler(db, db, ui))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, SessionTicketsDisabled: true}
	server.StartTLS()
	defer server.Close()
	tr := server.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
	client := &http.Client{Transport: tr}
	defer tr.CloseIdleConnections()
	for _, tc := range []struct {
		method, path, origin, site string
		want                       int
	}{
		{"GET", "/soc/v1/session", "", "", 200}, {"GET", "/", "", "", 200}, {"GET", "/soc/", "", "", 200}, {"GET", "/assets/app.js", "", "", 200},
		{"GET", "/private.json", "", "", 404}, {"GET", "/lab/", "", "", 404}, {"GET", "/api/overview", "", "", 404},
		{"GET", "/soc/v1/tenants/other/endpoints", "", "", 403}, {"GET", "/soc/v1/session?tenant=other", "", "", 400},
		{"POST", "/soc/v1/session", "", "", 405}, {"GET", "/soc/v1/session", "https://evil.invalid", "cross-site", 403},
		{"POST", "/soc/v1/tenants/tenantA/scan-jobs", "null", "", 403}, {"GET", "/soc/v1/session", server.URL, "same-origin", 200},
	} {
		t.Run(tc.method+tc.path+tc.origin, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, server.URL+tc.path, nil)
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Sec-Fetch-Site", tc.site)
			req.Header.Set("X-Tenant-ID", "other")
			req.Header.Set("X-Operator-Role", "scanner")
			req.Header.Set("Authorization", "Bearer untrusted")
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != tc.want {
				t.Fatalf("status=%d want=%d", res.StatusCode, tc.want)
			}
			if res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Content-Security-Policy") == "" {
				t.Fatal("secure response headers missing")
			}
			if tc.path == "/soc/v1/session" && tc.want == 200 {
				var v map[string]string
				if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
					t.Fatal(err)
				}
				if len(v) != 4 || v["tenant_id"] != "tenantA" || v["operator_id"] != "analyst" || v["role"] != "viewer" {
					t.Fatalf("untrusted session identity: %+v", v)
				}
				if _, err := time.Parse(time.RFC3339, v["server_time"]); err != nil {
					t.Fatal("session lacks server UTC timestamp")
				}
			}
		})
	}
	revoked.Store(true)
	res, err := client.Get(server.URL + "/soc/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("certificate revocation not checked on reused TLS connection")
	}
	if res, err := server.Client().Get(server.URL + "/"); err == nil {
		res.Body.Close()
		t.Fatal("static UI accepted absent client certificate")
	}
}

func TestAgentCertificateRejectsTLS12BeforeRegistry(t *testing.T) {
	leaf, _, _ := createTestAgentCertificate(t, time.Now(), []string{"spiffe://turansec.local/tenants/tenantA/agents/linuxA"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	state := &tls.ConnectionState{Version: tls.VersionTLS12, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	_, err := VerifyAgentCertificate(t.Context(), state, testIdentityRegistry{}, time.Now())
	if err != ErrAgentUnauthenticated {
		t.Fatalf("TLS1.2 authorization result %v", err)
	}
}
