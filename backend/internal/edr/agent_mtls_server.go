package edr

import (
    "crypto/tls"
    "crypto/x509"
    "database/sql"
    "errors"
    "net"
    "net/http"
    "time"
)

// NewAgentMTLSServer constructs a dedicated agent-only listener. It does not
// start the server, install a PostgreSQL driver, or load credentials.
// Callers must supply a separately provisioned server certificate, controlled
// agent CA pool, and a connected PostgreSQL database with least-privilege roles.
// Never multiplex this handler with the lab dashboard or bearer-token API.
func NewAgentMTLSServer(addr string,db *sql.DB,serverCert tls.Certificate,agentCAs *x509.CertPool)(*http.Server,error){
    if db==nil||agentCAs==nil||len(serverCert.Certificate)==0{
        return nil,errors.New("agent mTLS requires database, trusted client CA, and server certificate")
    }
    host,_,err:=net.SplitHostPort(addr)
    if err!=nil||host==""{
        return nil,errors.New("agent listener requires explicit host:port")
    }
    if host=="0.0.0.0"||host=="::"{
        return nil,errors.New("wildcard agent listener requires explicit security review")
    }
    handler:=AgentHTTPGuard(PostgresAgentIdentityRegistry{DB:db},
        AgentScanQueueHandler(PostgresScanJobQueue{DB:db}))
    return &http.Server{
        Addr:addr,
        Handler:handler,
        TLSConfig:&tls.Config{
            MinVersion:tls.VersionTLS13,
            ClientAuth:tls.RequireAndVerifyClientCert,
            ClientCAs:agentCAs,
            Certificates:[]tls.Certificate{serverCert},
        },
        ReadHeaderTimeout:5*time.Second,
        ReadTimeout:15*time.Second,
        WriteTimeout:15*time.Second,
        IdleTimeout:45*time.Second,
        MaxHeaderBytes:16<<10,
    },nil
}
