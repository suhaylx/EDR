package edr

import "testing"

func TestQADevelopmentBearerScheme(t *testing.T) {
 const token = "DEVELOPMENT_QA_TOKEN_123"
 cases := []struct{
  name string
  header string
  secret string
  want bool
 }{
  {"valid","Bearer "+token,token,true},
  {"no_header","",token,false},
  {"bare_token",token,token,false},
  {"basic_scheme","Basic "+token,token,false},
  {"wrong_case","bearer "+token,token,false},
  {"unknown_scheme","Token "+token,token,false},
  {"no_separator","Bearer"+token,token,false},
  {"double_separator","Bearer  "+token,token,false},
  {"wrong_token","Bearer OTHER",token,false},
  {"suffix","Bearer "+token+"EXTRA",token,false},
  {"trailing_space","Bearer "+token+" ",token,false},
  {"empty_config","Bearer ","",false},
  {"empty_secret_for_other_token","Bearer "+token,"",false},
 }
 for _,tc := range cases {
  t.Run(tc.name,func(t *testing.T) {
   got:=validDevelopmentBearer(tc.header,tc.secret)
   if got!=tc.want {t.Fatalf("%s: accepted=%v, want=%v",tc.name,got,tc.want)}
  })
 }
}
