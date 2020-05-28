package logging

// Valid returns true if a resource is valid according to HSDP rules, false otherwise
func (r *Resource) Valid() bool {
	if r.EventId == "" || r.TransactionId == "" || r.LogTime == "" || r.LogData.Message == "" {
		return false
	}
	return true
}

type bundleErrorResponse struct {
	Issue []struct {
		Severity string `json:"severity"`
		Code     string `json:"code"`
		Details  struct {
			Coding []struct {
				System string `json:"system"`
				Code   string `json:"code"`
			} `json:"coding"`
			Text string `json:"text"`
		} `json:"details"`
		Diagnostics string   `json:"diagnostics"`
		Location    []string `json:"location"`
	} `json:"issue"`
	ResourceType string `json:"resourceType"`
}
