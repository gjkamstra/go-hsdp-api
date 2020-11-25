package iam

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"errors"

	signer "github.com/philips-software/go-hsdp-signer"
	"github.com/stretchr/testify/assert"
)

var (
	muxIAM       *http.ServeMux
	serverIAM    *httptest.Server
	muxIDM       *http.ServeMux
	serverIDM    *httptest.Server
	signerHSDP   *signer.Signer
	token        string
	refreshToken string

	client *Client
)

func setup(t *testing.T) func() {
	muxIAM = http.NewServeMux()
	serverIAM = httptest.NewServer(muxIAM)
	muxIDM = http.NewServeMux()
	serverIDM = httptest.NewServer(muxIDM)
	sharedKey := "SharedKey"
	secretKey := "SecretKey"
	var err error

	signerHSDP, err = signer.New(sharedKey, secretKey)
	assert.Nil(t, err)

	client, err = NewClient(nil, &Config{
		OAuth2ClientID: "TestClient",
		OAuth2Secret:   "Secret",
		SharedKey:      sharedKey,
		SecretKey:      secretKey,
		IAMURL:         serverIAM.URL,
		IDMURL:         serverIDM.URL,
		Signer:         signerHSDP,
	})
	assert.Nil(t, err)

	token = "44d20214-7879-4e35-923d-f9d4e01c9746"
	token2 := "55d20214-7879-4e35-923d-f9d4e01c9746"
	refreshToken = "31f1a449-ef8e-4bfc-a227-4f2353fde547"

	muxIAM.HandleFunc("/authorize/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			assert.Equal(t, "POST", r.Method)
		}
		err := r.ParseForm()
		assert.Nil(t, err)
		username := r.Form.Get("username")
		returnToken := token
		if username == "username2" {
			returnToken = token2
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{
    		"scope": "auth_iam_introspect mail tdr.contract tdr.dataitem",
    		"access_token": "`+returnToken+`",
    		"refresh_token": "`+refreshToken+`",
    		"expires_in": 1799,
    		"token_type": "Bearer"
		}`)
	})

	return func() {
		serverIAM.Close()
		serverIDM.Close()
	}
}

func TestWithMissingSigner(t *testing.T) {
	muxIAM = http.NewServeMux()
	serverIAM = httptest.NewServer(muxIAM)
	muxIDM = http.NewServeMux()
	serverIDM = httptest.NewServer(muxIDM)
	var err error

	client, err = NewClient(nil, &Config{
		OAuth2ClientID: "TestClient",
		OAuth2Secret:   "Secret",
		IAMURL:         serverIAM.URL,
		IDMURL:         serverIDM.URL,
	})
	assert.Nil(t, err)
	assert.NotNil(t, client)
	assert.Nil(t, client.signer)
	resp, err := client.DoSigned(&http.Request{}, nil)
	assert.Nil(t, resp)
	assert.Equal(t, ErrNoValidSignerAvailable, err)
}

func TestLogin(t *testing.T) {
	teardown := setup(t)
	defer teardown()

	token := "44d20214-7879-4e35-923d-f9d4e01c9746"

	err := client.Login("username", "password")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, token, client.Token())
	assert.Equal(t, serverIAM.URL+"/", client.BaseIAMURL().String())
	assert.Equal(t, serverIDM.URL+"/", client.BaseIDMURL().String())
	assert.Equal(t, refreshToken, client.RefreshToken())
}

func TestCodeLogin(t *testing.T) {
	muxIAM = http.NewServeMux()
	serverIAM = httptest.NewServer(muxIAM)
	muxIDM = http.NewServeMux()
	serverIDM = httptest.NewServer(muxIDM)

	defer serverIAM.Close()
	defer serverIDM.Close()

	sharedKey := "SharedKey"
	secretKey := "SecretKey"
	authorizationCode := "a0c26ee4-e5b2-40ab-964e-8af999db44d5"
	redirectURI := "https://foo/bar"

	cfg := &Config{
		OAuth2ClientID: "TestClient",
		OAuth2Secret:   "Secret",
		SharedKey:      sharedKey,
		SecretKey:      secretKey,
		IAMURL:         serverIAM.URL,
		IDMURL:         serverIDM.URL,
		Scopes:         []string{"introspect", "cn"},
	}
	client, err := NewClient(nil, cfg)
	assert.Nil(t, err)

	token := "44d20214-7879-4e35-923d-f9d4e01c9746"

	muxIAM.HandleFunc("/authorize/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if !assert.Equal(t, "POST", r.Method) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := r.ParseForm(); !assert.Nilf(t, err, "Unable to parse form") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !assert.Equal(t, "authorization_code", strings.Join(r.Form["grant_type"], " ")) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !assert.Equal(t, authorizationCode, strings.Join(r.Form["code"], " ")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !assert.Equal(t, redirectURI, strings.Join(r.Form["redirect_uri"], " ")) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{
    		"scope": "`+strings.Join(cfg.Scopes, " ")+`",
    		"access_token": "`+token+`",
    		"refresh_token": "31f1a449-ef8e-4bfc-a227-4f2353fde547",
    		"expires_in": 1799,
    		"token_type": "Bearer"
		}`)
	})
	err = client.CodeLogin(authorizationCode, redirectURI)
	assert.Nilf(t, err, fmt.Sprintf("Unexpected error: %v", err))
	assert.Equal(t, token, client.Token())
}

func TestLoginWithScopes(t *testing.T) {
	muxIAM = http.NewServeMux()
	serverIAM = httptest.NewServer(muxIAM)
	muxIDM = http.NewServeMux()
	serverIDM = httptest.NewServer(muxIDM)

	defer serverIAM.Close()
	defer serverIDM.Close()

	sharedKey := "SharedKey"
	secretKey := "SecretKey"

	cfg := &Config{
		OAuth2ClientID: "TestClient",
		OAuth2Secret:   "Secret",
		SharedKey:      sharedKey,
		SecretKey:      secretKey,
		IAMURL:         serverIAM.URL,
		IDMURL:         serverIDM.URL,
		Scopes:         []string{"introspect", "cn"},
	}
	client, _ = NewClient(nil, cfg)

	token := "44d20214-7879-4e35-923d-f9d4e01c9746"

	muxIAM.HandleFunc("/authorize/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected ‘POST’ request")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Unable to parse form")
		}
		if strings.Join(r.Form["scope"], " ") != "introspect cn" {
			t.Fatalf("Expected scope to be `introspect cn` in test")
		}
		if strings.Join(r.Form["grant_type"], " ") != "password" {
			t.Fatalf("Exepcted grant_type to be `password` in test")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{
    		"scope": "`+strings.Join(cfg.Scopes, " ")+`",
    		"access_token": "`+token+`",
    		"refresh_token": "31f1a449-ef8e-4bfc-a227-4f2353fde547",
    		"expires_in": 1799,
    		"token_type": "Bearer"
		}`)
	})

	err := client.Login("username", "password")
	assert.Nil(t, err)
	assert.True(t, client.HasScopes("introspect", "cn"))
}

func TestHasScopes(t *testing.T) {
	teardown := setup(t)
	defer teardown()

	err := client.Login("username", "password")
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, client.HasScopes("mail"))
	assert.True(t, client.HasScopes("tdr.contract", "tdr.dataitem"))
	assert.False(t, client.HasScopes("missing"))
	assert.False(t, client.HasScopes("mail", "bogus"))
}

func TestIAMRequest(t *testing.T) {
	teardown := setup(t)
	defer teardown()

	req, err := client.NewRequest(IAM, "GET", "/foo", nil, nil)
	if err != nil {
		t.Errorf("Expected no no errors, got: %v", err)
	}
	if req == nil {
		t.Errorf("Expected valid request")
	}
	req, _ = client.NewRequest(IAM, "POST", "/foo", nil, []OptionFunc{
		func(r *http.Request) error {
			r.Header.Set("Foo", "Bar")
			return nil
		},
	})
	if req.Header.Get("Foo") != "Bar" {
		t.Errorf("Expected OptionFuncs to be processed")
	}
	testErr := errors.New("test error")
	req, err = client.NewRequest(IAM, "POST", "/foo", nil, []OptionFunc{
		func(r *http.Request) error {
			return testErr
		},
	})
	assert.Nil(t, req)
	assert.Equal(t, testErr, err)
}

func TestIDMRequest(t *testing.T) {
	teardown := setup(t)
	defer teardown()

	client.SetToken("xxx")
	client.SetTokens("xxx", "yyy", "zzz", time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	req, err := client.NewRequest(IDM, "GET", "/foo", nil, nil)

	if err != nil {
		t.Errorf("Expected no no errors, got: %v", err)
	}
	if req == nil {
		t.Errorf("Expected valid request")
	}
	req, _ = client.NewRequest(IDM, "POST", "/foo", nil, []OptionFunc{
		func(r *http.Request) error {
			r.Header.Set("Foo", "Bar")
			return nil
		},
	})
	assert.Equal(t, "Bar", req.Header.Get("Foo"))

	testErr := errors.New("test error")
	req, err = client.NewRequest(IDM, "POST", "/foo", nil, []OptionFunc{
		func(r *http.Request) error {
			return testErr
		},
	})
	assert.Nil(t, req)
	assert.NotNil(t, err)
}

func TestWithToken(t *testing.T) {
	teardown := setup(t)
	defer teardown()

	if client.WithToken("fooz").Token() != "fooz" {
		t.Errorf("Unexpected token")
	}

}

func TestWithLogin(t *testing.T) {
	teardown := setup(t)
	defer teardown()

	newClient, err := client.WithLogin("username2", "password")
	assert.NotNil(t, newClient)
	assert.Nil(t, err)
	assert.Equal(t, "55d20214-7879-4e35-923d-f9d4e01c9746", newClient.Token())
	assert.NotEqual(t, client, newClient)
}

func TestDebug(t *testing.T) {
	teardown := setup(t)
	defer teardown()

	tmpfile, err := ioutil.TempFile("", "example")
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	sharedKey := "SharedKey"
	secretKey := "SecretKey"

	client, err = NewClient(nil, &Config{
		OAuth2ClientID: "TestClient",
		OAuth2Secret:   "Secret",
		SharedKey:      sharedKey,
		SecretKey:      secretKey,
		IAMURL:         serverIAM.URL,
		IDMURL:         serverIDM.URL,
		Debug:          true,
		DebugLog:       tmpfile.Name(),
	})

	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	defer client.Close()
	defer os.Remove(tmpfile.Name()) // clean up

	err = client.Login("username", "password")
	assert.Nil(t, err)

	fi, err := tmpfile.Stat()
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if fi.Size() == 0 {
		t.Errorf("Expected something to be written to DebugLog")
	}

}

func TestTokenRefresh(t *testing.T) {
	muxIAM = http.NewServeMux()
	serverIAM = httptest.NewServer(muxIAM)
	muxIDM = http.NewServeMux()
	serverIDM = httptest.NewServer(muxIDM)

	defer serverIAM.Close()
	defer serverIDM.Close()

	sharedKey := "SharedKey"
	secretKey := "SecretKey"

	cfg := &Config{
		OAuth2ClientID: "TestClient",
		OAuth2Secret:   "Secret",
		SharedKey:      sharedKey,
		SecretKey:      secretKey,
		IAMURL:         serverIAM.URL,
		IDMURL:         serverIDM.URL,
		Scopes:         []string{"introspect", "cn"},
	}
	client, err := NewClient(nil, cfg)
	assert.Nil(t, err)

	token := "44d20214-7879-4e35-923d-f9d4e01c9746"
	refreshToken := "13614f90-9cdf-4962-aea3-01cd51fa56b9"
	newToken := "90b208cd-aaf3-45bb-9410-ba3f42255b9d"
	newRefreshToken := "9c45339e-38c8-4dac-b290-5c3ac571c369"

	muxIAM.HandleFunc("/authorize/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if !assert.Equal(t, "POST", r.Method) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if err := r.ParseForm(); !assert.Nilf(t, err, "Unable to parse form") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		grantType := strings.Join(r.Form["grant_type"], " ")
		receveidRefreshToken := strings.Join(r.Form["refresh_token"], " ")

		w.Header().Set("Content-Type", "application/json")
		switch grantType {
		case "refresh_token":
			if !assert.Equal(t, refreshToken, receveidRefreshToken) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{
				"scope": "`+strings.Join(cfg.Scopes, " ")+`",
				"access_token": "`+newToken+`",
				"refresh_token": "`+newRefreshToken+`",
				"expires_in": 1799,
				"token_type": "Bearer"
			}`)
		case "password":
			err := r.ParseForm()
			assert.Nil(t, err)
			username := r.Form.Get("username")
			if !assert.Equal(t, "username", username) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{
				"scope": "`+strings.Join(cfg.Scopes, " ")+`",
				"access_token": "`+token+`",
				"refresh_token": "`+refreshToken+`",
				"expires_in": 1799,
				"token_type": "Bearer"
			}`)
		}

	})
	err = client.Login("username", "password")
	assert.Nil(t, err)

	err = client.tokenRefresh()
	assert.Nilf(t, err, fmt.Sprintf("Unexpected error: %v", err))
	assert.Equal(t, newToken, client.Token())
	assert.Equal(t, newRefreshToken, client.RefreshToken())
	httpClient := client.HttpClient()
	assert.NotNil(t, httpClient)
}

func TestAutoconfig(t *testing.T) {
	cfg := &Config{
		OAuth2ClientID: "TestClient",
		OAuth2Secret:   "Secret",
		SharedKey:      "foo",
		SecretKey:      "bar",
		Region:         "us-east",
		Environment:    "client-test",
	}
	// Explicit config always wins over autoconfig
	foo := "https://foo.com"
	cfg.IAMURL = foo
	cfg.IDMURL = foo
	_, _ = NewClient(nil, cfg)
	assert.Equal(t, foo, cfg.IAMURL)
	assert.Equal(t, foo, cfg.IDMURL)
}
