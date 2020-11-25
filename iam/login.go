package iam

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CodeLogin
func (c *Client) CodeLogin(code string, redirectURI string) error {
	// Authorize
	req, err := c.NewRequest(IAM, "POST", "authorize/oauth2/token", nil, nil)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", code)
	if len(redirectURI) > 0 {
		form.Add("redirect_uri", redirectURI)
	}
	body := form.Encode()
	req.SetBasicAuth(c.config.OAuth2ClientID, c.config.OAuth2Secret)
	req.Body = ioutil.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))

	return c.doTokenRequest(req)
}

// Login logs in a user with `username` and `password`
func (c *Client) Login(username, password string) error {
	req, err := c.NewRequest(IAM, "POST", "authorize/oauth2/token", nil, nil)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Add("username", username)
	form.Add("password", password)
	form.Add("grant_type", "password")
	if len(c.config.Scopes) > 0 {
		scopes := strings.Join(c.config.Scopes, " ")
		form.Add("scope", scopes)
	}
	req.SetBasicAuth(c.config.OAuth2ClientID, c.config.OAuth2Secret)
	req.Body = ioutil.NopCloser(strings.NewReader(form.Encode()))
	req.ContentLength = int64(len(form.Encode()))

	return c.doTokenRequest(req)
}

func (c *Client) doTokenRequest(req *http.Request) error {
	var tokenResponse tokenResponse

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Api-Version", loginAPIVersion)
	resp, err := c.Do(req, &tokenResponse)

	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed: %d", resp.StatusCode)
	}
	if tokenResponse.AccessToken == "" {
		return ErrNotAuthorized
	}
	c.tokenType = oAuthToken
	c.token = tokenResponse.AccessToken
	if tokenResponse.RefreshToken != "" { // Doesn't always contain new refresh token
		c.refreshToken = tokenResponse.RefreshToken
	}
	if tokenResponse.IDToken != "" {
		c.idToken = tokenResponse.IDToken
	}
	c.expiresAt = time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	c.scopes = strings.Split(tokenResponse.Scope, " ")
	return nil
}
