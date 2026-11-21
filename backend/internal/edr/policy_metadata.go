package edr

import "time"

// PolicyMetadata intentionally omits raw Sysmon XML. It is a read-only lab
// presentation contract, not proof of endpoint policy application. Production
// requires authenticated operator identity and tenant-qualified reads.
type PolicyMetadata struct {
 ID string `json:"id"`
 Name string `json:"name"`
 Platform string `json:"platform"`
 Revision int `json:"revision"`
 SHA256 string `json:"sha256"`
 CreatedAt time.Time `json:"created_at"`
}

func policyCatalogMetadata(policies []Policy) []PolicyMetadata {
 result := make([]PolicyMetadata, 0, len(policies))
 for _, p := range policies {
  result = append(result, PolicyMetadata{
   ID:p.ID,Name:p.Name,Platform:p.Platform,Revision:p.Revision,
   SHA256:p.SHA256,CreatedAt:p.CreatedAt,
  })
 }
 return result
}
