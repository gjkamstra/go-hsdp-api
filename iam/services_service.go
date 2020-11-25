package iam

import (
	"bytes"
	"net/http"
	"strings"
)

const servicesAPIVersion = "1"

// Service represents a IAM service resource
type Service struct {
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name"`
	Description    string   `json:"description"` // RITM0021326
	ApplicationID  string   `json:"applicationId"`
	Validity       int      `json:"validity,omitempty"`
	ServiceID      string   `json:"serviceId,omitempty"`
	OrganizationID string   `json:"organizationId,omitempty"`
	ExpiresOn      string   `json:"expiresOn,omitempty"`
	PrivateKey     string   `json:"privateKey,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	DefaultScopes  []string `json:"defaultScopes,omitempty"`
}

// ServicesService provides operations on IAM Sessions resources
type ServicesService struct {
	client *Client
}

// GetServiceOptions describes search criteria for looking up services
type GetServiceOptions struct {
	ID             *string `url:"_id,omitempty"`
	Name           *string `url:"name,omitempty"`
	ApplicationID  *string `url:"applicationId,omitempty"`
	OrganizationID *string `url:"organizationId,omitempty"`
	ServiceID      *string `url:"serviceId,omitempty"`
}

func fixHSDPPEM(pemString string) string {
	pre := strings.Replace(pemString,
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\n", -1)
	return strings.Replace(pre,
		"-----END RSA PRIVATE KEY-----",
		"\n-----END RSA PRIVATE KEY-----", -1)
}

// GetServiceByID looks up a service by ID
func (p *ServicesService) GetServiceByID(id string) (*Service, *Response, error) {
	return p.GetService(&GetServiceOptions{ID: &id}, nil)
}

// GetServiceByName looks up a service by name
func (p *ServicesService) GetServiceByName(name string) (*Service, *Response, error) {
	return p.GetService(&GetServiceOptions{Name: &name}, nil)
}

// GetServicesByApplicationID finds all services which belong to the applicationID
func (p *ServicesService) GetServicesByApplicationID(applicationID string) (*[]Service, *Response, error) {
	opt := &GetServiceOptions{
		ApplicationID: String(applicationID),
	}
	req, err := p.client.NewRequest(IDM, "GET", "authorize/identity/Service", opt, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("api-version", servicesAPIVersion)

	var responseStruct struct {
		Total int       `json:"total"`
		Entry []Service `json:"entry"`
	}

	resp, err := p.client.Do(req, &responseStruct)
	if err != nil {
		return nil, resp, err
	}
	return &responseStruct.Entry, resp, err
}

// CreateService creates a Service
func (p *ServicesService) CreateService(service Service) (*Service, *Response, error) {
	req, _ := p.client.NewRequest(IDM, "POST", "authorize/identity/Service", &service, nil)
	req.Header.Set("api-version", servicesAPIVersion)
	req.Header.Set("Content-Type", "application/json")

	var createdService Service

	resp, err := p.client.Do(req, &createdService)
	if err != nil {
		return nil, resp, err
	}
	return &createdService, resp, err
}

// GetService looks up a services based on GetServiceOptions
func (p *ServicesService) GetService(opt *GetServiceOptions, options ...OptionFunc) (*Service, *Response, error) {
	services, resp, err := p.GetServices(opt, options...)
	if err != nil {
		return nil, resp, err
	}
	return &(*services)[0], resp, nil
}

// GetServices looks up services based on GetServiceOptions
func (p *ServicesService) GetServices(opt *GetServiceOptions, options ...OptionFunc) (*[]Service, *Response, error) {
	req, err := p.client.NewRequest(IDM, "GET", "authorize/identity/Service", opt, options)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("api-version", servicesAPIVersion)
	req.Header.Set("Content-Type", "application/json")

	var bundleResponse struct {
		Total int       `json:"total"`
		Entry []Service `json:"entry"`
	}

	resp, err := p.client.Do(req, &bundleResponse)
	if err != nil {
		return nil, resp, err
	}
	return &bundleResponse.Entry, resp, err
}

// DeleteService deletes the given Service
func (p *ServicesService) DeleteService(service Service) (bool, *Response, error) {
	req, err := p.client.NewRequest(IDM, "DELETE", "authorize/identity/Service/"+service.ID, nil, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("api-version", servicesAPIVersion)
	req.Header.Set("Content-Type", "application/json")

	var deleteResponse interface{}

	resp, err := p.client.Do(req, &deleteResponse)
	if resp == nil || resp.StatusCode != http.StatusNoContent {
		return false, resp, err
	}
	return true, resp, nil
}

// AddScopes add scopes to the service
func (p *ServicesService) AddScopes(service Service, scopes []string, defaultScopes []string) (bool, *Response, error) {
	return p.updateScopes(service, "add", scopes, defaultScopes)
}

// RemoveScopes add scopes to the service
func (p *ServicesService) RemoveScopes(service Service, scopes []string, defaultScopes []string) (bool, *Response, error) {
	return p.updateScopes(service, "remove", scopes, defaultScopes)
}

func (p *ServicesService) updateScopes(service Service, action string, scopes []string, defaultScopes []string) (bool, *Response, error) {
	var requestBody = struct {
		Action        string   `json:"action"`
		Scopes        []string `json:"scopes,omitempty"`
		DefaultScopes []string `json:"defaultScopes,omitempty"`
	}{
		action,
		scopes,
		defaultScopes,
	}
	req, err := p.client.NewRequest(IDM, "PUT", "authorize/identity/Service/"+service.ID+"/$scopes", requestBody, nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("api-version", servicesAPIVersion)
	req.Header.Set("Content-Type", "application/json")

	var putResponse bytes.Buffer

	resp, err := p.client.Do(req, &putResponse)
	if err != nil {
		return false, resp, err
	}
	if resp.StatusCode != http.StatusNoContent {
		return false, resp, ErrOperationFailed
	}
	return true, resp, nil
}
