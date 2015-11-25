package soap_test

import (
	"reflect"
	"testing"

	"github.com/Bridgevine/t-soap"
)

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

func TestEncodeEnvelope(t *testing.T) {

	commonTests := []useCase{
		useCase{
			name:            "When preparing soap headers and body payload",
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
			name:            "When preparing SOAP 1.1 Fault without Details as the body payload",
			reqPayload:      []interface{}{fault11WoD},
			expectedPayload: []interface{}{&fault11WoD},
			expectedFault:   &fault11WoD,
			bdyTypesInfo:    map[string]interface{}{"Fault": &soap.Fault11{}},
		},
		useCase{
			name:            "When preparing SOAP 1.1 Fault with Details as the body payload",
			reqPayload:      []interface{}{fault11WD},
			expectedPayload: []interface{}{&fault11WD},
			expectedFault:   &fault11WD,
			bdyTypesInfo:    map[string]reflect.Type{"Fault": reflect.TypeOf(soap.Fault11{})},
		},
	}

	testFunc := func(version string, tests []useCase) {
		for _, n := range tests {
			t.Log("")
			t.Logf("\t%s", n.name)
			{
				sc, err := soap.NewClient(soap.V11)
				reqEnv, err := sc.NewRequestBuilder().
					SetAction("TestingAction").
					AddSOAPHeaders(n.reqSOAPHeaders).
					AddPayload(n.reqPayload).
					Build()

				if err != nil {
					t.Errorf("\t\t%s Should not get an error, but unexpected error received after trying to build envelope request.", failure)
					t.Errorf("\t\t  Error = [%v]", err)
					continue
				}

				data, err := sc.EncodeEnvelope(reqEnv)
				if data == nil || err != nil {
					t.Errorf("\t\t%s Should not get an error, but unexpected error received after trying to encode envelope request.", failure)
					t.Errorf("\t\t  Error = [%v]", err)
					continue
				}
			}
		}
	}

	t.Log("Given the need to test the ability of a SOAP 1.1 client to prepare requests and process responses.")
	{
		testFunc(soap.V11, append(commonTests, soap11Tests...))
	}
}

/*
func TestEncodeEnvelope(t *testing.T) {
	
	
	
}
*/