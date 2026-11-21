package edr

import (
 "io"
 "net/http"
 "strings"
 "unicode"
 "unicode/utf8"
)

// containsUnsafeSOCText rejects terminal/HTTP control characters and
// directional-formatting overrides in attacker-influenced SOC display text.
// This is an input defense; dashboard rendering must still escape HTML.
func containsUnsafeSOCText(value string) bool {
 if !utf8.ValidString(value){return true}
 return strings.IndexFunc(value,func(r rune)bool{
  return unicode.IsControl(r) || r==0x061C || r==0xFEFF || r==0xFFFD ||
   (r>=0x202A && r<=0x202E) || // bidi embeddings/overrides
   (r>=0x2066 && r<=0x2069) || // bidi isolates
   r==0x200E || r==0x200F // left/right marks
 })>=0
}

// requestBodyIsEmpty uses a bounded complete read, not a single Read call.
// io.Reader may legitimately return (0,nil) before later yielding data;
// accepting that as EOF would let a client hide a request payload.
func requestBodyIsEmpty(w http.ResponseWriter,r *http.Request)bool{
 r.Body=http.MaxBytesReader(w,r.Body,1)
 body,err:=io.ReadAll(r.Body)
 return err==nil&&len(body)==0
}
