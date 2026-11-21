package edr

import (
 "strings"
 "unicode"
)

// containsUnsafeSOCText rejects terminal/HTTP control characters and
// directional-formatting overrides in attacker-influenced SOC display text.
// This is an input defense; dashboard rendering must still escape HTML.
func containsUnsafeSOCText(value string) bool {
 return strings.IndexFunc(value,func(r rune)bool{
  return unicode.IsControl(r) ||
   (r>=0x202A && r<=0x202E) || // bidi embeddings/overrides
   (r>=0x2066 && r<=0x2069) || // bidi isolates
   r==0x200E || r==0x200F // left/right marks
 })>=0
}
