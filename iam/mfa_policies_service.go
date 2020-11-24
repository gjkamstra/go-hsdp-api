package iam

import (
	"bytes"
	"net/http"

)

const (
	MFAPoliciesAPIVersion = "2"
	SCIMBasePath          = "authorize/scim/v2/"
)

type MFAPoliciesService struct {
	client *Client

}

// GetMFAPolicyByID retrieves a MFAPolicy by ID
func (p *MFAPoliciesService) GetMFAPolicyByID(MFAPolicyID string) (*MFAPolicy, *Response, error) {
	req, err := p.client.NewRequest(IDM, "GET", SCIMBasePath+"MFAPolicies/"+MFAPolicyID, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("api-version", MFAPoliciesAPIVersion)
	req.Header.Set("Content-Type", "application/scim+json")

	var MFAPolicy MFAPolicy

	resp, err := p.client.Do(req, &MFAPolicy)
	if err != nil {
		return nil, resp, err
	}
	if MFAPolicy.ID != MFAPolicyID {
		return nil, resp, ErrNotFound
	}
	return &MFAPolicy, resp, err
}

// UpdateMFAPolicy updates a MFAPolicy
func (p *MFAPoliciesService) UpdateMFAPolicy(policy *MFAPolicy) (*MFAPolicy, *Response, error) {

	req, _ := p.client.NewRequest(IDM, "PUT", SCIMBasePath+"MFAPolicies/"+policy.ID, policy, nil)
	req.Header.Set("api-version", MFAPoliciesAPIVersion)
	req.Header.Set("Content-Type", "application/scim+json")
	if policy.Meta == nil {
		return nil, nil, ErrMissingEtagInformation
	}
	req.Header.Set("If-Match", policy.Meta.Version)

	var updatedMFAPolicy MFAPolicy
	resp, err := p.client.Do(req, &updatedMFAPolicy)

	if err != nil {
		return nil, resp, err
	}
	return &updatedMFAPolicy, resp, nil

}

// CreateMFAPolicy creates a MFAPolicy
func (p *MFAPoliciesService) CreateMFAPolicy(policy MFAPolicy) (*MFAPolicy, *Response, error) {
	policy.Schemas = append(policy.Schemas, "urn:ietf:params:scim:schemas:core:philips:hsdp:2.0:MFAPolicy")
	policy.SetActive(true)

	req, _ := p.client.NewRequest(IDM, "POST", SCIMBasePath+"MFAPolicies", &policy, nil)
	req.Header.Set("api-version", MFAPoliciesAPIVersion)
	req.Header.Set("Content-Type", "application/scim+json")
	req.Header.Set("Accept", "application/scim+json")

	var createdMFAPolicy MFAPolicy

	resp, err := p.client.Do(req, &createdMFAPolicy)
	if err != nil {
		return nil, resp, err
	}
	return &createdMFAPolicy, resp, err
}

// DeleteMFAPolicy deletes the given MFAPolicy
func (p *MFAPoliciesService) DeleteMFAPolicy(policy MFAPolicy) (bool, *Response, error) {
	req, err := p.client.NewRequest(IDM, "DELETE", SCIMBasePath+"MFAPolicies/"+policy.ID, nil, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("api-version", MFAPoliciesAPIVersion)
	req.Header.Set("Content-Type", "application/json")

	var deleteResponse bytes.Buffer

	resp, err := p.client.Do(req, &deleteResponse)
	if resp == nil || resp.StatusCode != http.StatusNoContent {
		return false, resp, nil
	}
	return true, resp, err
}
