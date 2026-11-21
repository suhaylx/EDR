package edr

import (
	"database/sql"
	"net/http"
	"time"
)

// NewAgentMTLSServerFromFiles binds the controlled on-disk certificate
// materials to the dedicated TLS-only, tenant-scoped agent handler. It never
// starts a listener, creates enrollment records or enables the developer API.
// The database must be connected, migrated and access-scoped by Agent 2.
func NewAgentMTLSServerFromFiles(addr string, db *sql.DB, certPath, keyPath, agentCAPath string, now time.Time) (*http.Server, error) {
	cert, roots, err := LoadAgentTLSMaterials(certPath, keyPath, agentCAPath, now)
	if err != nil {
		return nil, err
	}
	return NewAgentMTLSServer(addr, db, cert, roots)
}
