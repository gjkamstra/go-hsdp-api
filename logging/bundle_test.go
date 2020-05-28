package logging

import (
	"testing"

	"github.com/stretchr/testify/assert"
	jsonpb "google.golang.org/protobuf/encoding/protojson"
)

func TestBundle(t *testing.T) {
	var b = Bundle{
		ResourceType: "transaction",
	}
	assert.Equal(t, "transaction", b.ResourceType)
}

func TestBundleEncoding(t *testing.T) {
	var payload = `{
		"resourceType": "bundle",
		"type": "transaction",
		"total": 1,
		"productKey": "840f4a21-5e7d-4479-909d-c9a1d6c54960",
		"entry": [
		  {
			"resource": {
			  "resourceType": "LogEvent",
			  "id": "0b57440d-3d3e-4c3a-a5ca-8e95fbac63e5",
			  "applicationName": "Foundation-Security",
			  "eventId": "IdentityAccessManagement-1101101",
			  "category": "TRACELOG",
			  "component": "IAM-USRAUTH",
			  "transactionId": "b75e8f52-c719-4ca1-aab0-8e8fb7f565e8",
			  "serviceName": "IdentityAccessManagement",
			  "applicationInstance": "INST-00001",
			  "applicationVersion": "1.0.0",
			  "originatingUser": "ActiveUser",
			  "serverName": "iam.pcftest.com",
			  "logTime": "2015-05-04T10:54:24+0000",
			  "severity": "INFO",
			  "custom": {
				"key1": "value1",
				"key2": {
				  "innerkey": "innervalue"
				}
			  },
			  "logData": {
				"message": "SGVsbG8="
			  }
			}
		  }
		]
	  }`

	bundle := &Bundle{}
	err := jsonpb.Unmarshal([]byte(payload), bundle)

	if !assert.Equal(t, nil, err) {
		return
	}
	if !assert.Equal(t, int64(1), bundle.Total) {
		return
	}
	resource := bundle.Entry[0].Resource
	assert.Equal(t, "SGVsbG8=", resource.LogData.Message)
	if !assert.Equal(t, nil, err) {
		return
	}
	inner := resource.Custom.Fields["key2"]
	if !assert.NotNil(t, inner) {
		return
	}
	//inner := resource.Custom.Fields["key2"].
	//assert.Equal(t, "innervalue", inner["innerkey"].(string))
}
