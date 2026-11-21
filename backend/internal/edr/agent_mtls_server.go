package edr

import (
    "crypto/tls"
    "crypto/x509"
    "database/sql"
    "errors"
    "net"
    "net/http"
    "strconv"
    "time"
)

// NewAgentMTLSServer constructs a dedicated agent-only listener. It does not
// start the server, install a PostgreSQL driver, or load credentials.
// Callers must supply a separately provisioned server certificate, controlled
// agent CA pool, and a connected PostgreSQL database with least-privilege roles.
// Never multiplex this handler with the lab dashboard or bearer-token API.
func NewAgentMTLSServer(addr string,db *sql.DB,serverCert tls.Certificate,agentCAs *x509.CertPool)(*http.Server,error){
    if db==nil||agentCAs==nil||len(agentCAs.Subjects())==0||len(serverCert.Certificate)==0||serverCert.PrivateKey==nil{
        return nil,errors.New("agent mTLS requires database, trusted client CA, and server certificate")
    }
    host,portText,err:=net.SplitHostPort(addr)
    if err!=nil || host=="" || portText=="" {
        return nil,errors.New("agent listener requires explicit numeric loopback host:port")
    }
    port,err:=strconv.Atoi(portText)
    if err!=nil || port<1 || port>65535 {
        return nil,errors.New("agent listener requires valid TCP port")
    }
    ip:=net.ParseIP(host)
    if ip==nil || !ip.IsLoopback() {
        // Never bind an agent-identity API to a public interface by default.
        // Remote lab hosts must use an approved tunnel or a separately
        // reviewed management-network listener with explicit firewall rules.
        return nil,errors.New("agent listener must bind a loopback IP")
    }
    handler:=AgentHTTPGuard(PostgresAgentIdentityRegistry{DB:db},
        AgentScanQueueHandler(PostgresScanJobQueue{DB:db}))
    return &http.Server{
        Addr:addr,
        Handler:handler,
        TLSConfig:&tls.Config{
            MinVersion:tls.VersionTLS13,
            ClientAuth:tls.RequireAndVerifyClientCert,
            SessionTicketsDisabled:true,
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
