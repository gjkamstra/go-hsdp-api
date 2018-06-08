package iam

// Organization represents a IAM Organization resource
type Organization struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	DistinctName   string `json:"distinctName"`
	OrganizationID string `json:"organizationId"`
}
