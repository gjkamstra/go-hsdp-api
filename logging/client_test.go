package logging

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	jsonpb "google.golang.org/protobuf/encoding/protojson"

	signer "github.com/philips-software/go-hsdp-signer"
)

var (
	muxLogger    *http.ServeMux
	serverLogger *httptest.Server
	client       *Client
)

const (
	productKey   = "859722b3-64dd-4be8-a522-c2dbf88c86b5"
	sharedKey    = "SharedKey"
	sharedSecret = "SharedSecret"
)

func makeValidResource() *Resource {
	validResource := &Resource{
		Id:                  "deb545e2-ccea-4868-99fe-b9dfbf5ce56e",
		ResourceType:        "LogEvent",
		ServerName:          "foo.bar.com",
		ApplicationName:     "some-space",
		EventId:             "1",
		Category:            "Tracelog",
		Component:           "PHS",
		TransactionId:       "5bc4ce05-37b5-4f08-89e4-ed73790f8058",
		ServiceName:         "mcvs",
		ApplicationInstance: "85e597cb-2648-4187-78ec-2c58",
		ApplicationVersion:  "0.0.0",
		OriginatingUser:     "ActiveUser",
		LogTime:             "2017-10-15T01:53:20Z",
		Severity:            "INFO",
		LogData: &LogData{
			Message: "Hello world",
		},
	}
	return validResource
}

func makeInvalidResource() *Resource {
	invalidResource := &Resource{
		Id:                  "deb545e2-ccea-4868-99fe-b9dfbf5ce56e",
		ResourceType:        "LogEvent",
		ServerName:          "foo.bar.com",
		ApplicationName:     "some-space",
		EventId:             "1",
		Category:            "Tracelog",
		Component:           "PHS",
		TransactionId:       "",
		ServiceName:         "mcvs",
		ApplicationInstance: "85e597cb-2648-4187-78ec-2c58",
		ApplicationVersion:  "0.0.0",
		OriginatingUser:     "ActiveUser",
		LogTime:             "2017-10-15T01:53:20Z",
		Severity:            "INFO",
		LogData: &LogData{
			Message: "Hello World",
		},
	}
	return invalidResource
}
func setup(t *testing.T, config Config, method string, statusCode int, responseBody string) (func(), error) {
	var err error

	muxLogger = http.NewServeMux()
	serverLogger = httptest.NewServer(muxLogger)
	if config.BaseURL != "" { // So we can test for missing BaseURL
		config.BaseURL = serverLogger.URL
	}

	client, err = NewClient(nil, config)
	if err != nil {
		return func() {
			serverLogger.Close()
		}, err
	}

	muxLogger.HandleFunc("/core/log/LogEvent", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s, _ := signer.New(sharedKey, sharedSecret)
		if ok, _ := s.ValidateRequest(r); !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		body, _ := ioutil.ReadAll(r.Body)
		var bodyString = string(body)
		if bodyString == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var bundle Bundle
		err := jsonpb.Unmarshal(body, &bundle)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if bundle.ProductKey != productKey {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(w, `{
				"issue": [
					{
						"severity": "error",
						"code": "value",
						"details": {
							"coding": [
								{
									"system": "https://www.hl7.org/fhir/valueset-operation-outcome.html",
									"code": "MSG_PARAM_INVALID"
								}
							],
							"text": "Invalid parameter value"
						},
						"diagnostics": "Invalid parameter value"
					}
				],
				"resourceType": "OperationOutcome"
			}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if responseBody != "" {
			_, _ = w.Write([]byte(responseBody))
		}
	})

	return func() {
		serverLogger.Close()
	}, nil
}

func TestStoreResources(t *testing.T) {
	teardown, err := setup(t, Config{
		SharedKey:    sharedKey,
		SharedSecret: sharedSecret,
		ProductKey:   productKey,
		BaseURL:      "http://foo",
	}, "POST", http.StatusCreated, "")
	if teardown != nil {
		defer teardown()
	}
	if err != nil {
		t.Fatal(err)
	}

	var resource = []*Resource{
		makeValidResource(),
	}

	resp, err := client.StoreResources(resource, len(resource))
	if err != nil {
		t.Errorf("Unexpected response: %v", err)
		return
	}
	if resp == nil {
		t.Errorf("Unexpected nil value for response")
		return
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected HTTP 201, Got: %d", resp.StatusCode)
	}
}

func TestStoreResourcesWithInvalidKey(t *testing.T) {
	teardown, err := setup(t, Config{
		SharedKey:    sharedKey,
		SharedSecret: sharedSecret,
		ProductKey:   "089db3e5-3e3e-4445-8903-29cc848194b1",
		BaseURL:      "http://foo",
	}, "POST", http.StatusCreated, "")
	if teardown != nil {
		defer teardown()
	}

	if err != nil {
		t.Fatal(err)
	}

	var resource = []*Resource{
		makeValidResource(),
	}

	resp, err := client.StoreResources(resource, len(resource))
	if err == nil {
		t.Errorf("Expected error message")
	}
	if resp == nil {
		t.Errorf("Unexpected nil value for response")
		return
	}
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("Expected HTTP %d, Got: %d", http.StatusUnprocessableEntity, resp.StatusCode)
	}
}

func TestStoreResourcesWithInvalidKeypair(t *testing.T) {
	_ = os.Setenv("DEBUG", "true")
	teardown, err := setup(t, Config{
		SharedKey:    "bogus",
		SharedSecret: "keys",
		ProductKey:   productKey,
		BaseURL:      "http://foo",
	}, "POST", http.StatusCreated, "")
	if teardown != nil {
		defer teardown()
	}
	if err != nil {
		t.Fatal(err)
	}

	var resource = []*Resource{
		makeValidResource(),
	}

	resp, err := client.StoreResources(resource, len(resource))
	if !assert.NotNil(t, err) {
		return
	}
	assert.NotNil(t, resp)
	_ = err.Error() // Just to up coverage
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.NotNil(t, err)
}

func TestConfig(t *testing.T) {
	_ = os.Setenv("DEBUG", "false")
	var errSet = []struct {
		config Config
		err    error
	}{
		{Config{SharedKey: "", SharedSecret: "bar", ProductKey: "key", BaseURL: "http://foo"}, ErrMissingSharedKey},
		{Config{SharedKey: "foo", SharedSecret: "", ProductKey: "key", BaseURL: "http://foo"}, ErrMissingSharedSecret},
		{Config{SharedKey: "foo", SharedSecret: "bar", ProductKey: "", BaseURL: "http://foo"}, ErrMissingProductKey},
		{Config{SharedKey: "foo", SharedSecret: "bar", ProductKey: "key", BaseURL: ""}, ErrMissingBaseURL},
	}
	for _, tt := range errSet {
		teardown, err := setup(t, tt.config, "POST", http.StatusCreated, "")

		if err != tt.err {
			t.Errorf("Unexpected error: %v, expected: %v", err, tt.err)
		}
		if teardown != nil {
			teardown()
		}
	}
}

func TestStoreResourcesWithBadResources(t *testing.T) {
	_ = os.Setenv("DEBUG", "true")
	teardown, err := setup(t, Config{
		SharedKey:    sharedKey,
		SharedSecret: sharedSecret,
		ProductKey:   productKey,
		BaseURL:      "http://foo",
	}, "POST", http.StatusBadRequest, `{
  "issue": [
    {
      "severity": "error",
      "code": "invalid",
      "details": {
        "coding": [
          {
            "system": "https://www.hl7.org/fhir/valueset-operation-outcome.html",
            "code": "MSG_PARAM_INVALID"
          }
        ],
        "text": "Mandatory fields are Missing or field data passed is invalid"
      },
      "diagnostics": "Invalid or missing parameter. Refer to API specification",
      "location": [
        "entry[0].resource.transactionId"
      ]
    }
  ],
  "resourceType": "OperationOutcome"
}`)
	if teardown != nil {
		defer teardown()
	}
	if err != nil {
		t.Fatal(err)
	}

	var resource = []*Resource{
		makeInvalidResource(),
	}

	resp, err := client.StoreResources(resource, len(resource))
	if !assert.NotNil(t, err) {
		return
	}
	if !assert.NotNil(t, resp) {
		return
	}
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, ErrBatchErrors, err)

	resp, err = client.StoreResources([]*Resource{makeValidResource()}, 1)
	if !assert.NotNil(t, err) {
		return
	}
	if !assert.NotNil(t, resp) {
		return
	}
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, ErrBatchErrors, err)
}
