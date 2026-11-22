// edrd is the isolated, PostgreSQL-backed mTLS candidate service. Enrollment,
// schema migration and production deployment remain explicit administrator tasks.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/turansec/edr/backend/internal/edr"
)

var version = "development"
var sourceSHA = "uncommitted"

type configuration struct {
	AgentListen     string `json:"agent_listen"`
	SOCListen       string `json:"soc_listen"`
	ServerCertFile  string `json:"server_cert_file"`
	ServerKeyFile   string `json:"server_key_file"`
	AgentCAFile     string `json:"agent_ca_file"`
	OperatorCAFile  string `json:"operator_ca_file"`
	RegistryDSNFile string `json:"registry_dsn_file"`
	RuntimeDSNFile  string `json:"runtime_dsn_file"`
	UIDir           string `json:"ui_dir"`
}

// Credential paths are local files, never literal passwords on a command line.
// Errors deliberately exclude contents, DSNs and parser diagnostics.
func boundedFile(path string, private bool, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("configuration paths must be absolute")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit {
		return nil, errors.New("required file is missing, non-regular or oversized")
	}
	if private && runtime.GOOS != "windows" && before.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private configuration and key files require owner-only permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open required file")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || (private && runtime.GOOS != "windows" && after.Mode().Perm()&0077 != 0) {
		return nil, errors.New("file changed or permissions are unsafe")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(b) == 0 || int64(len(b)) > limit {
		return nil, errors.New("cannot read bounded required file")
	}
	return b, nil
}

func loadConfig(path string) (configuration, error) {
	var c configuration
	b, err := boundedFile(path, true, 16<<10)
	if err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return c, errors.New("invalid service configuration")
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return c, errors.New("configuration must contain one JSON document")
	}
	if c.AgentListen == "" {
		c.AgentListen = "127.0.0.1:9443"
	}
	if c.SOCListen == "" {
		c.SOCListen = "127.0.0.1:9444"
	}
	if c.AgentListen == c.SOCListen {
		return c, errors.New("agent and operator listeners must be distinct")
	}
	if dir := os.Getenv("EDR_SOC_UI_DIR"); dir != "" {
		c.UIDir = dir
	}
	if !filepath.IsAbs(c.UIDir) {
		return c, errors.New("ui_dir must be an absolute built frontend directory")
	}
	if c.RegistryDSNFile == c.RuntimeDSNFile {
		return c, errors.New("registry and runtime require separate database credentials")
	}
	return c, nil
}

func loadCA(path string) (*x509.CertPool, map[[32]byte]bool, error) {
	b, err := boundedFile(path, false, 1<<20)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	ids := map[[32]byte]bool{}
	for len(bytes.TrimSpace(b)) > 0 {
		block, rest := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, errors.New("CA file must contain only PEM CA certificates")
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
			return nil, nil, errors.New("CA certificate is invalid or expired")
		}
		pool.AddCert(cert)
		ids[sha256.Sum256(cert.RawSubjectPublicKeyInfo)] = true
		b = rest
	}
	if len(ids) == 0 {
		return nil, nil, errors.New("CA trust store is empty")
	}
	return pool, ids, nil
}

type databaseIdentity struct {
	Host     string
	Port     uint16
	Database string
	User     string
}

func connectDB(ctx context.Context, path, expectedRole string) (*sql.DB, databaseIdentity, error) {
	b, err := boundedFile(path, true, 16<<10)
	if err != nil {
		return nil, databaseIdentity{}, err
	}
	cfg, err := pgx.ParseConfig(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, databaseIdentity{}, errors.New("invalid database connection configuration")
	}
	// This candidate is loopback-only, including PostgreSQL. Remote databases
	// require a separately reviewed trust/network deployment configuration.
	ip := net.ParseIP(cfg.Host)
	if ip == nil || !ip.IsLoopback() || cfg.Database == "" || cfg.User == "" || len(cfg.Fallbacks) > 0 {
		return nil, databaseIdentity{}, errors.New("database requires one explicit loopback target and named role/database")
	}
	cfg.ConnectTimeout = 5 * time.Second
	cfg.RuntimeParams["search_path"] = "pg_catalog, public, pg_temp"
	cfg.RuntimeParams["statement_timeout"] = "10000"
	cfg.RuntimeParams["lock_timeout"] = "5000"
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	fail := func() (*sql.DB, databaseIdentity, error) {
		db.Close()
		return nil, databaseIdentity{}, errors.New("database connection, migration or least-privilege check failed")
	}
	if db.PingContext(ctx) != nil {
		return fail()
	}
	var user, database string
	var unsafe bool
	var member bool
	err = db.QueryRowContext(ctx, `SELECT current_user,current_database(),
 r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls,
 pg_has_role(current_user,$1,'member')
 FROM pg_roles r WHERE r.rolname=current_user`, expectedRole).Scan(&user, &database, &unsafe, &member)
	if err != nil || unsafe || !member {
		return fail()
	}
	var ddl bool
	err = db.QueryRowContext(ctx, `SELECT has_schema_privilege(current_user,'public','CREATE') OR has_database_privilege(current_user,current_database(),'TEMP') OR pg_has_role(current_user,'edr_api_functions','member')`).Scan(&ddl)
	if err != nil || ddl {
		return fail()
	}
	var excess bool
	err = db.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=current_user::regrole AND m.roleid<>$1::regrole)
 OR EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=$1::regrole)
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname LIKE 'edr_%' AND c.relkind IN ('r','p')
 AND (has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))
 OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='public' AND p.proname LIKE 'edr_%' AND pg_has_role(current_user,p.proowner,'member'))`, expectedRole).Scan(&excess)
	if err != nil || excess {
		return fail()
	}
	// Existing function signatures alone cannot prove that the wall-clock
	// fixes have been applied. Migrations 0013 and 0014 publish these capabilities
	// atomically with their replacements; serving roles cannot alter them.
	for _, capability := range []string{"scan_lease_wallclock", "enrollment_wallclock"} {
		var capabilityVersion int
		err = db.QueryRowContext(ctx, `SELECT version FROM public.edr_schema_capabilities WHERE capability=$1`, capability).Scan(&capabilityVersion)
		if err != nil || capabilityVersion != 1 {
			db.Close()
			return nil, databaseIdentity{}, fmt.Errorf("required database capability %s version 1 is unavailable or incompatible", capability)
		}
	}
	// Require the complete serving schema before opening either HTTP listener.
	// WHERE false checks actual column privileges without reading user records.
	queries := []string{
		`SELECT tenant_id,disabled_at,runtime_lock FROM public.edr_tenants WHERE false`,
		`SELECT tenant_id,agent_id,platform,revoked_at,runtime_lock FROM public.edr_agents WHERE false`,
	}
	if expectedRole == "edr_identity_ro" {
		queries = append(queries, `SELECT fingerprint_sha256,not_before,not_after,revoked_at FROM public.edr_agent_certificates WHERE false`,
			`SELECT tenant_id,operator_id,fingerprint_sha256,role,revoked_at,runtime_lock FROM public.edr_soc_operators WHERE false`)
	} else {
		queries = append(queries, `SELECT tenant_id,agent_id,scan_ready,last_seen,received_count FROM public.edr_agent_heartbeats WHERE false`,
			`SELECT job_id,tenant_id,agent_id,state,request_key,created_by_operator FROM public.edr_scan_jobs WHERE false`,
			`SELECT job_id,tenant_id,agent_id,verdict FROM public.edr_scan_job_results WHERE false`,
			`SELECT alert_id,tenant_id,assigned_to,resolution_note FROM public.edr_soc_alerts WHERE false`,
			`SELECT activity_id,tenant_id,alert_id,actor_id,action,note FROM public.edr_soc_alert_activity WHERE false`)
	}
	for _, query := range queries {
		rows, e := db.QueryContext(ctx, query)
		if e != nil {
			return fail()
		}
		rows.Close()
	}
	for _, signature := range []string{
		"edr_claim_scan_job(varchar,varchar,text,uuid,integer)",
		"edr_renew_scan_job_lease(varchar,varchar,uuid,text,uuid,integer)",
		"edr_complete_scan_job_with_result(varchar,varchar,uuid,uuid,text,text,text)",
		"edr_record_agent_heartbeat(varchar,varchar,text,varchar,varchar,varchar,boolean)",
		"edr_enqueue_operator_scan_job(varchar,varchar,varchar,uuid,varchar,text)",
		"edr_cancel_operator_scan_job(varchar,varchar,uuid)",
		"edr_soc_change_alert_state(varchar,varchar,uuid,text,text)",
		"edr_soc_assign_alert(varchar,varchar,uuid,varchar)",
		"edr_soc_add_alert_note(varchar,varchar,uuid,text)",
		"edr_authorize_agent_certificate(varchar,varchar,bytea)",
		"edr_authorize_operator_certificate(varchar,varchar,bytea,text)",
	} {
		var allowed bool
		e := db.QueryRowContext(ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, "public."+signature).Scan(&allowed)
		if e != nil || allowed != (expectedRole == "edr_runtime") {
			return fail()
		}
	}
	return db, databaseIdentity{Host: ip.String(), Port: cfg.Port, Database: database, User: user}, nil
}

func serve(ctx context.Context, c configuration) error {
	certPEM, err := boundedFile(c.ServerCertFile, false, 1<<20)
	if err != nil {
		return err
	}
	keyPEM, err := boundedFile(c.ServerKeyFile, true, 1<<20)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.New("invalid server certificate/private key")
	}
	agentCA, agentRoots, err := loadCA(c.AgentCAFile)
	if err != nil {
		return err
	}
	operatorCA, operatorRoots, err := loadCA(c.OperatorCAFile)
	if err != nil {
		return err
	}
	for root := range agentRoots {
		if operatorRoots[root] {
			return errors.New("agent and operator trust roots must be separate")
		}
	}
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	registryDB, registryID, err := connectDB(startup, c.RegistryDSNFile, "edr_identity_ro")
	if err != nil {
		return err
	}
	defer registryDB.Close()
	runtimeDB, runtimeID, err := connectDB(startup, c.RuntimeDSNFile, "edr_runtime")
	if err != nil {
		return err
	}
	defer runtimeDB.Close()
	if registryID.Host != runtimeID.Host || registryID.Port != runtimeID.Port || registryID.Database != runtimeID.Database || registryID.User == runtimeID.User {
		return errors.New("database handles require one database and different registry/runtime logins")
	}
	uiRoot, err := os.OpenRoot(c.UIDir)
	if err != nil {
		return errors.New("cannot open built frontend directory")
	}
	defer uiRoot.Close()
	info, err := fs.Stat(uiRoot.FS(), "index.html")
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("frontend build is missing index.html")
	}
	agent, err := edr.NewAgentMTLSServer(c.AgentListen, registryDB, cert, agentCA)
	if err != nil {
		return err
	}
	agent.Handler = edr.AgentAuthenticatedScanHandler(registryDB, runtimeDB)
	soc, err := edr.NewSOCMTLSServer(c.SOCListen, registryDB, cert, operatorCA)
	if err != nil {
		return err
	}
	soc.Handler = edr.SOCApplicationHandler(registryDB, runtimeDB, uiRoot.FS())
	// TLS handshake failures are expected denials, not credential-bearing logs.
	agent.ErrorLog = log.New(io.Discard, "", 0)
	soc.ErrorLog = log.New(io.Discard, "", 0)
	agentListener, err := net.Listen("tcp", agent.Addr)
	if err != nil {
		return errors.New("cannot bind agent listener")
	}
	defer agentListener.Close()
	socListener, err := net.Listen("tcp", soc.Addr)
	if err != nil {
		return errors.New("cannot bind operator listener")
	}
	defer socListener.Close()
	errs := make(chan error, 2)
	go func() { errs <- agent.ServeTLS(agentListener, "", "") }()
	go func() { errs <- soc.ServeTLS(socListener, "", "") }()
	log.Printf("edrd started version=%s source=%s transport=mTLS database=PostgreSQL status=candidate", version, sourceSHA)
	var servingErr error
	select {
	case <-ctx.Done():
	case servingErr = <-errs:
	}
	shutdown, stop := context.WithTimeout(context.Background(), 8*time.Second)
	defer stop()
	_ = agent.Shutdown(shutdown)
	_ = soc.Shutdown(shutdown)
	if servingErr != nil && !errors.Is(servingErr, http.ErrServerClosed) {
		return errors.New("authenticated listener stopped unexpectedly")
	}
	return nil
}

func main() {
	configPath := flag.String("config", "", "absolute path to owner-only JSON configuration")
	showVersion := flag.Bool("version", false, "print build identity")
	flag.Parse()
	if *showVersion {
		fmt.Printf("edrd %s source=%s\n", version, sourceSHA)
		return
	}
	if *configPath == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: edrd --config /absolute/path/edrd.json")
		os.Exit(2)
	}
	c, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err = serve(ctx, c); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
