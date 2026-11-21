package edr

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestPostgresChallengeIssuerRandomnessAndDigestOnlyStorage(t *testing.T) {
	seen := map[string]bool{}
	var fingerprints [][32]byte
	db := scanDB(t, func(query string, args []driver.NamedValue) (driver.Rows, error) {
		if query != issueEnrollmentChallengeSQL || len(args) != 6 {
			t.Fatalf("unexpected challenge SQL: %s args %d", query, len(args))
		}
		id, ok := args[0].Value.(string)
		if !ok || !validUUID(id) || id[14] != '4' ||
			!strings.ContainsRune("89ab", rune(id[19])) || seen[id] {
			t.Fatalf("invalid or reused random UUIDv4 %q", id)
		}
		seen[id] = true
		if args[1].Value != "tenantA" || args[2].Value != "win01" ||
			args[4].Value != int64(300) || args[5].Value != "pinned-issuer" {
			t.Fatalf("unscoped challenge issuance args: %#v", args)
		}
		digest, ok := args[3].Value.([]byte)
		if !ok || len(digest) != 32 {
			t.Fatal("only 32-byte SHA-256 digest should reach PostgreSQL")
		}
		var fp [32]byte
		copy(fp[:], digest)
		fingerprints = append(fingerprints, fp)
		return &scanRows{columns: []string{"issued"}, values: [][]driver.Value{{true}}}, nil
	})
	store := PostgresEnrollmentChallengeIssuer{DB: db}
	var secrets [][32]byte
	for i := 0; i < 4; i++ {
		challenge, err := store.IssueEnrollmentChallenge(
			context.Background(), "tenantA", "win01", "pinned-issuer", 300)
		if err != nil || challenge == nil {
			t.Fatalf("challenge generation %d: %+v %v", i, challenge, err)
		}
		if !seen[challenge.ChallengeID] || challenge.TTLSeconds != 300 ||
			challenge.ChallengeSecret == ([32]byte{}) {
			t.Fatal("invalid returned challenge metadata")
		}
		if fingerprints[i] != sha256.Sum256(challenge.ChallengeSecret[:]) {
			t.Fatal("database did not receive exact secret digest")
		}
		for _, prior := range secrets {
			if prior == challenge.ChallengeSecret {
				t.Fatal("cryptographic challenge secret reused")
			}
		}
		secrets = append(secrets, challenge.ChallengeSecret)
		clear(challenge.ChallengeSecret[:])
	}
}

func TestPostgresChallengeIssuerFailsClosed(t *testing.T) {
	seenQueries := 0
	db := scanDB(t, func(_ string, _ []driver.NamedValue) (driver.Rows, error) {
		seenQueries++
		return &scanRows{columns: []string{"issued"}, values: [][]driver.Value{{false}}}, nil
	})
	store := PostgresEnrollmentChallengeIssuer{DB: db}
	for _, tc := range []struct {
		name,tenant,agent,actor string
		ttl int
	}{
		{"cross-slash","../tenantA","win01","actor",300},
		{"empty-device","tenantA","","actor",300},
		{"empty-actor","tenantA","win01","",300},
		{"actor-whitespace","tenantA","win01"," actor ",300},
		{"low-ttl","tenantA","win01","actor",59},
		{"long-ttl","tenantA","win01","actor",601},
	} {
		t.Run(tc.name,func(t *testing.T){
			challenge, err := store.IssueEnrollmentChallenge(
				context.Background(),tc.tenant,tc.agent,tc.actor,tc.ttl)
			if challenge!=nil || !errors.Is(err,ErrChallengeIssueInvalid){
				t.Fatalf("invalid challenge request accepted: %+v %v",challenge,err)
			}
		})
	}
	if seenQueries != 0 { t.Fatal("invalid requests reached database") }
	challenge, err := store.IssueEnrollmentChallenge(context.Background(),
		"tenantA","win01","actor",300)
	if challenge != nil || err != nil { t.Fatalf("ineligible challenge: %+v %v",challenge,err) }
	if seenQueries != 1 { t.Fatal("expected exactly one database query") }

	down := scanDB(t, func(string, []driver.NamedValue)(driver.Rows,error){
		return nil, errors.New("sensitive SQL error")
	})
	challenge,err=(PostgresEnrollmentChallengeIssuer{DB:down}).
		IssueEnrollmentChallenge(context.Background(),"tenantA","win01","actor",300)
	if challenge!=nil || !errors.Is(err,ErrChallengeIssueUnavailable) ||
		strings.Contains(err.Error(),"sensitive") {
		t.Fatalf("database failure leaked or allowed issuance: %+v %v",challenge,err)
	}
	if c,err:=(PostgresEnrollmentChallengeIssuer{}).
		IssueEnrollmentChallenge(context.Background(),"tenantA","win01","actor",300);
		c!=nil || !errors.Is(err,ErrChallengeIssueUnavailable){
		t.Fatalf("nil DB accepted: %+v %v",c,err)
	}
	_ = io.EOF // keep driver failure mode explicit
}
