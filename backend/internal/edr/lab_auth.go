package edr

import (
 "crypto/subtle"
 "strings"
)

// validDevelopmentBearer validates only the dev lab Authorization scheme.
// This is not endpoint mTLS, operator identity, or production tenant RBAC.
func validDevelopmentBearer(header, token string) bool {
 return token != "" && strings.HasPrefix(header, "Bearer ") &&
   subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(header, "Bearer ")), []byte(token)) == 1
}
