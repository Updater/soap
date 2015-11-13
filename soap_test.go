package soap_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/Bridgevine/tmp.soap"
)

// mockServer returns a pointer to a server to handle incomming requests.
// This server will respond with exactly the same request received.
func mockServer() *httptest.Server {
	f := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "text/xml")

		defer r.Body.Close()

		var buf bytes.Buffer
		buf.ReadFrom(r.Body)
		fmt.Fprintln(w, buf.String())
	}

	return httptest.NewServer(http.HandlerFunc(f))
}

type useCase struct {
	name            string
	reqSOAPHeaders  []interface{}
	reqPayload      []interface{}
	expectedHeaders []interface{}
	expectedPayload []interface{}
	expectedFault   soap.Fault
	hdrTypesInfo    interface{}
	bdyTypesInfo    interface{}
}

func TestClients(t *testing.T) {
	// The http server mockup will send back the same request received.
	// Base on that, our reqPayload should be the payload that we want to be able to unmarshal.
	commonTests := []useCase{
		useCase{
			name:            "When sending soap headers and body payload",
			reqSOAPHeaders:  soapHeaders,
			reqPayload:      []interface{}{sample001},
			expectedHeaders: soapHeaders,
			expectedPayload: []interface{}{&sample002},
			hdrTypesInfo:    map[string]reflect.Type{"MessageID": reflect.TypeOf(soap.MessageID{}), "Action": reflect.TypeOf(soap.Action{}), "To": reflect.TypeOf(soap.To{})},
			bdyTypesInfo:    map[string]reflect.Type{"Sample00": reflect.TypeOf(Sample00{})},
		},
	}

	soap11Tests := []useCase{
		useCase{
			name:            "When sending SOAP 1.1 Fault without Details as the body payload",
			reqPayload:      []interface{}{fault11WoD},
			expectedPayload: []interface{}{&fault11WoD},
			expectedFault:   &fault11WoD,
			bdyTypesInfo:    map[string]interface{}{"Fault": &soap.Fault11{}},
		},
		useCase{
			name:            "When sending SOAP 1.1 Fault with Details as the body payload",
			reqPayload:      []interface{}{fault11WD},
			expectedPayload: []interface{}{&fault11WD},
			expectedFault:   &fault11WD,
			bdyTypesInfo:    map[string]reflect.Type{"Fault": reflect.TypeOf(soap.Fault11{})},
		},
	}

	soap12Tests := []useCase{
		useCase{
			name:            "When sending SOAP 1.2 Fault without Details as the body payload",
			reqPayload:      []interface{}{fault12WoD},
			expectedPayload: []interface{}{&fault12WoD},
			expectedFault:   &fault12WoD,
			bdyTypesInfo:    map[string]interface{}{"Fault": &soap.Fault12{}},
		},
		useCase{
			name:            "When sending SOAP 1.2 Fault with Details as the body payload",
			reqPayload:      []interface{}{fault12WD},
			expectedPayload: []interface{}{&fault12WD},
			expectedFault:   &fault12WD,
			bdyTypesInfo:    map[string]reflect.Type{"Fault": reflect.TypeOf(soap.Fault12{})},
		},
	}

	server := mockServer()
	defer server.Close()

	testFunc := func(version string, tests []useCase) {
		client, err := soap.NewClient(version, server.URL, 0)
		if err != nil {
			t.Errorf("\t\t%s Should not get an error, but unexpected error received when creating SOAP Client.", failure)
			t.Errorf("\t\t  Error = [%v]", err)
			return
		}

		for _, n := range tests {
			t.Log("")
			t.Logf("\t%s", n.name)
			{
				req := soap.Request{
					Action:      "TestingAction",
					HTTPHeaders: nil,
					Header:      n.reqSOAPHeaders,
					Payload:     n.reqPayload,
				}

				respEnv, err := client.Do(req)
				if err != nil {
					t.Errorf("\t\t%s Should not get an error, but unexpected error received after sending the request.", failure)
					t.Errorf("\t\t  Error = [%v]", err)
					continue
				}

				if len(n.expectedHeaders) > 0 {
					if respEnv.Header() == nil || len(respEnv.Header().Content) == 0 {
						t.Errorf("\t\t%s Should get some header items.", failure)
					} else {
						t.Logf("\t\t%s Should get some header items.", success)

						receivedHeaders, err := soap.UnmarshalXMLElement(respEnv.Header().Content, n.hdrTypesInfo)
						if err != nil {
							t.Errorf("\t\t%s Should not get an error, but unexpected error received when unmarshalling the header items.", failure)
							t.Errorf("\t\t  Error = [%v]", err)
						} else if len(receivedHeaders) == 0 {
							t.Errorf("\t\t%s Should get some header items after unmarshalling.", failure)
						} else if !reflect.DeepEqual(n.expectedHeaders, receivedHeaders) {
							t.Errorf("\t\t%s Should get the same header items as expected.", failure)
						} else {
							t.Logf("\t\t%s Should get the same header items as expected.", success)
						}
					}
				} else if respEnv.Header() != nil && len(respEnv.Header().Content) > 0 {
					t.Errorf("\t\t%s Should not get header items.", failure)
				} else {
					t.Logf("\t\t%s Should not get header items.", success)
				}

				if len(n.expectedPayload) > 0 {
					if len(respEnv.Body().Payload()) == 0 {
						t.Errorf("\t\t%s Should get some body payload.", failure)
						continue
					}
					t.Logf("\t\t%s Should get some body payload.", success)

					receivedPayload, err := soap.UnmarshalXMLElement(respEnv.Body().Payload(), n.bdyTypesInfo)
					if err != nil {
						t.Errorf("\t\t%s Should not get an error, but unexpected error received when unmarshalling the body payload.", failure)
						t.Errorf("\t\t  Error = [%v]", err)
						continue
					}
					if len(receivedPayload) == 0 {
						t.Errorf("\t\t%s Should not get an empty Body Payload after unmarshalling.", failure)
						continue
					}

					if !reflect.DeepEqual(n.expectedPayload, receivedPayload) {
						t.Errorf("\t\t%s Should get the same body payload as expected.", failure)
						continue
					}
					t.Logf("\t\t%s Should get the same body payload as expected.", success)

					if n.expectedFault != nil {
						if respEnv.Body().Fault() == nil {
							t.Errorf("\t\t%s Should get a Fault.", failure)
							continue
						}
						t.Logf("\t\t%s Should get a Fault [Code: %v] [Description: %v] [Details-Lenght: %v] .", success, respEnv.Body().Fault().GetCode(), respEnv.Body().Fault().Description(), len(respEnv.Body().Fault().Details()))

						if !reflect.DeepEqual(n.expectedFault, respEnv.Body().Fault()) {
							t.Errorf("\t\t%s Should get the same fault as expected.", failure)
							continue
						}
						t.Logf("\t\t%s Should get the same fault as expected.", success)
					} else if respEnv.Body().Fault() != nil {
						t.Errorf("\t\t%s Should not get Fault.", failure)
					} else {
						t.Logf("\t\t%s Should not get Fault.", success)
					}

					continue
				}

				results, err := soap.UnmarshalXMLElement(respEnv.Body().Payload(), n.bdyTypesInfo)
				if len(results) > 0 {
					t.Errorf("\t\t%s Should get an empty body.", failure)
					continue
				}
				t.Logf("\t\t%s Should get an empty body.", success)
			}
		}
	}

	t.Log("Given the need to test the ability of a SOAP 1.1 client to send requests and process responses.")
	{
		testFunc(soap.V11, append(commonTests, soap11Tests...))
	}

	t.Log("")
	t.Log("Given the need to test the ability of a SOAP 1.2 client to send requests and process responses.")
	{
		testFunc(soap.V12, append(commonTests, soap12Tests...))
	}
}

func TestClientErrors(t *testing.T) {
	server := mockServer()
	defer server.Close()

	tests := []struct {
		name        string
		endpointURL string
		soapHeaders []interface{}
		payload     []interface{}
		shouldFail  bool
	}{
		{
			name:        "When sending request without specifying the URL of the endpoint.",
			soapHeaders: soapHeaders,
			payload:     []interface{}{sample001},
			shouldFail:  true,
		},
		{
			name:        "When sending request specifying the URL of the endpoint.",
			endpointURL: server.URL,
			soapHeaders: soapHeaders,
			payload:     []interface{}{sample001},
			shouldFail:  false,
		},
		{
			name:        "When sending header items that cannot be marshalled.",
			endpointURL: server.URL,
			soapHeaders: []interface{}{Sample02{}},
			payload:     []interface{}{sample001},
			shouldFail:  true,
		},
		{
			name:        "When sending header items that can be marshalled.",
			endpointURL: server.URL,
			soapHeaders: soapHeaders,
			payload:     []interface{}{sample001},
			shouldFail:  false,
		},
		{
			name:        "When sending a payload that cannot be marshalled.",
			endpointURL: server.URL,
			soapHeaders: soapHeaders,
			payload:     []interface{}{Sample02{}},
			shouldFail:  true,
		},
		{
			name:        "When sending a payload that can be marshalled.",
			endpointURL: server.URL,
			soapHeaders: soapHeaders,
			payload:     []interface{}{sample001},
			shouldFail:  false,
		},
	}

	t.Log("")
	t.Log("Given the need to test the ability of a SOAP client to return errors.")
	{
		for _, n := range tests {
			t.Log("")
			t.Logf("\t%s", n.name)
			{
				client, err := soap.NewClient(soap.V11, n.endpointURL, 0)
				if err != nil {
					t.Errorf("\t\t%s Should not get an error, but unexpected error received when creating SOAP Client.", failure)
					t.Errorf("\t\t  Error = [%v]", err)
					continue
				}

				req := soap.Request{
					Action:      "TestingAction",
					HTTPHeaders: nil,
					Header:      n.soapHeaders,
					Payload:     n.payload,
				}

				_, err = client.Do(req)

				if n.shouldFail {
					if err == nil {
						t.Errorf("\t\t%s Should get an error.", failure)
						continue
					}
					t.Logf("\t\t%s Should get an error.", success)
					t.Logf("\t\t  Error = [%v]", err)
					continue
				}

				if err != nil {
					t.Errorf("\t\t%s Should not get an error.", failure)
					t.Logf("\t\t  Error = [%v]", err)
					continue
				}
				t.Logf("\t\t%s Should not get an error.", success)
			}
		}
	}
}
