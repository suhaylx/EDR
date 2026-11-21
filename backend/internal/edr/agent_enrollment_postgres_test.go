package edr

import (
    "context"
    "database/sql/driver"
    "errors"
    "strings"
    "testing"
    "time"
)

func enrollmentFixture()EnrollmentAuthorization{
    now:=time.Now().UTC()
    return EnrollmentAuthorization{
        ChallengeID:testUUID,TenantID:"tenantA",AgentID:"win01",
        Platform:"windows",CertificateNotBefore:now.Add(-time.Minute),
        CertificateNotAfter:now.Add(time.Hour),ActorID:"issuer-test",
    }
}

func TestPostgresEnrollmentStoreAtomicCall(t *testing.T){
    db:=scanDB(t,func(q string,args []driver.NamedValue)(driver.Rows,error){
        if !strings.Contains(q,"edr_complete_agent_enrollment")||len(args)!=9{
            t.Fatalf("unexpected enrollment query: %s args %#v",q,args)
        }
        if args[0].Value!=testUUID||args[1].Value!="tenantA"||
            args[2].Value!="win01"||args[4].Value!="windows"||
            args[8].Value!="issuer-test"{
            t.Fatalf("incorrect enrollment scope: %#v",args)
        }
        digest,ok:=args[3].Value.([]byte)
        if !ok||len(digest)!=32{t.Fatalf("invalid challenge digest: %#v",args[3].Value)}
        fp,ok:=args[5].Value.([]byte)
        if !ok||len(fp)!=32{t.Fatalf("invalid fingerprint: %#v",args[5].Value)}
        return &scanRows{columns:[]string{"enrolled"},values:[][]driver.Value{{true}}},nil
    })
    enrolled,err:=(PostgresEnrollmentStore{DB:db}).CompleteInitialEnrollment(
        context.Background(),enrollmentFixture())
    if err!=nil||!enrolled{t.Fatalf("enrollment: %v %v",enrolled,err)}
}

func TestPostgresEnrollmentStoreRejectsInvalidAndUnavailable(t *testing.T){
    fixture:=enrollmentFixture()
    cases:=[]struct{name string;change func(*EnrollmentAuthorization)}{
        {"bad challenge",func(a *EnrollmentAuthorization){a.ChallengeID="invalid"}},
        {"bad tenant",func(a *EnrollmentAuthorization){a.TenantID="../other"}},
        {"bad platform",func(a *EnrollmentAuthorization){a.Platform="macos"}},
        {"missing actor",func(a *EnrollmentAuthorization){a.ActorID=""}},
        {"expired certificate",func(a *EnrollmentAuthorization){a.CertificateNotAfter=time.Now().Add(-time.Minute)}},
        {"future certificate",func(a *EnrollmentAuthorization){a.CertificateNotBefore=time.Now().Add(time.Hour)}},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            a:=fixture;tc.change(&a)
            _,err:=(PostgresEnrollmentStore{}).CompleteInitialEnrollment(context.Background(),a)
            if !errors.Is(err,ErrEnrollmentInvalid){t.Fatalf("expected invalid input: %v",err)}
        })
    }
    _,err:=(PostgresEnrollmentStore{}).CompleteInitialEnrollment(context.Background(),fixture)
    if !errors.Is(err,ErrEnrollmentUnavailable){t.Fatalf("missing DB: %v",err)}
}

func TestPostgresEnrollmentStoreHidesDatabaseErrors(t *testing.T){
    db:=scanDB(t,func(string,[]driver.NamedValue)(driver.Rows,error){
        return nil,errors.New("sensitive postgres detail")
    })
    _,err:=(PostgresEnrollmentStore{DB:db}).CompleteInitialEnrollment(
        context.Background(),enrollmentFixture())
    if !errors.Is(err,ErrEnrollmentUnavailable)||strings.Contains(err.Error(),"sensitive"){
        t.Fatalf("SQL error must not leak: %v",err)
    }
}

func TestPostgresEnrollmentStoreRejectsFalseResult(t *testing.T){
    db:=scanDB(t,func(string,[]driver.NamedValue)(driver.Rows,error){
        return &scanRows{columns:[]string{"enrolled"},values:[][]driver.Value{{false}}},nil
    })
    enrolled,err:=(PostgresEnrollmentStore{DB:db}).CompleteInitialEnrollment(
        context.Background(),enrollmentFixture())
    if err!=nil||enrolled{t.Fatalf("replayed challenge accepted: %v %v",enrolled,err)}
}
