package soap_test

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/Bridgevine/t-soap"
	"github.com/Bridgevine/t-soap/ws"
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
			hdrTypesInfo:    map[string]reflect.Type{"MessageID": reflect.TypeOf(ws.MessageID{}), "Action": reflect.TypeOf(ws.Action{}), "To": reflect.TypeOf(ws.To{})},
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
			t.Logf("\t%s", n.name)
			{
				ec, err := soap.NewEnvelopeConfig(soap.V11)
				if err != nil {
					t.Errorf("\t\t%s Should not get an error, but unexpected error received after trying to build envelope request.", failure)
					t.Errorf("\t\t  Error = [%v]", err)
					continue
				}
				_, err = ec.SetAction("TestingAction").
					SetSOAPHeaders(n.reqSOAPHeaders).
					SetPayload(n.reqPayload).
					GetHTTPBinding()

				if err != nil {
					t.Errorf("\t\t%s Should not get an error, but unexpected error received after trying to build envelope request.", failure)
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

func ExampleNewEnvelopeConfig_setSOAP11Empty() {
	ec, err := soap.NewEnvelopeConfig(soap.V11)
	if err != nil {
		panic(err)
	}

	req, err := ec.GetHTTPBinding()

	fmt.Println(string(req.Message))

	// Output:
	// <Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body></Body></Envelope>
}

func ExampleNewEnvelopeConfig_setSOAP11Header() {
	type hdr struct {
		Username string
	}

	ec, err := soap.NewEnvelopeConfig(soap.V11)
	if err != nil {
		panic(err)
	}

	req, err := ec.SetSOAPHeaders([]hdr{hdr{"John Doe"}}).
		GetHTTPBinding()

	fmt.Println(string(req.Message))

	// Output:
	// <Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Header><hdr><Username>John Doe</Username></hdr></Header><Body></Body></Envelope>
}

func ExampleNewEnvelopeConfig_setSOAP11Payload() {
	type GetWeather struct {
		CityName    string
		CountryName string
	}

	ec, err := soap.NewEnvelopeConfig(soap.V11)
	if err != nil {
		panic(err)
	}

	req, err := ec.SetPayload(GetWeather{CityName: "Miami", CountryName: "United States"}).
		GetHTTPBinding()

	fmt.Println(string(req.Message))

	// Output:
	// <Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body><GetWeather><CityName>Miami</CityName><CountryName>United States</CountryName></GetWeather></Body></Envelope>
}

func ExampleNewEnvelopeConfig_setSOAP12Payload() {
	type GetWeather struct {
		CityName    string
		CountryName string
	}

	ec, err := soap.NewEnvelopeConfig(soap.V12)
	if err != nil {
		panic(err)
	}

	req, err := ec.SetPayload(GetWeather{CityName: "Miami", CountryName: "United States"}).
		GetHTTPBinding()

	fmt.Println(string(req.Message))

	// Output:
	// <Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body><GetWeather><CityName>Miami</CityName><CountryName>United States</CountryName></GetWeather></Body></Envelope>
}

func ExampleDecodeEnvelope_setSOAP11() {
	type ConvertTemp struct {
		XMLName     xml.Name `xml:"http://www.webserviceX.NET ConvertTemp"`
		Temperature float32  `xml:"Temperature,omitempty"`
		FromUnit    string   `xml:"FromUnit,omitempty"`
		ToUnit      string   `xml:"ToUnit,omitempty"`
	}

	ec, err := soap.NewEnvelopeConfig(soap.V12)
	if err != nil {
		panic(err)
	}

	req, err := ec.SetPayload(ConvertTemp{Temperature: 100.00, FromUnit: "degreeFahrenheit", ToUnit: "degreeCelsius"}).
		SetAction("http://www.webserviceX.NET/ConvertTemp").
		GetHTTPBinding()

	r, err := http.NewRequest("POST", "http://www.webservicex.net/ConvertTemperature.asmx", bytes.NewBuffer(req.Message))
	if err != nil {
		panic(err)
	}
	r.Header = req.Header

	var client http.Client
	resp, err := client.Do(r)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	respEnv, err := soap.DecodeEnvelope(soap.V12, resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(respEnv.Body().Payload()))

	// Output:
	// <ConvertTempResponse xmlns="http://www.webserviceX.NET/"><ConvertTempResult>0</ConvertTempResult></ConvertTempResponse>
}

func ExampleEncodeEnvelope_setSOAP11Empty() {
	var e soap.Envelope11

	req, err := soap.EncodeEnvelope("", &e)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(req.Message))

	// Output:
	// <Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body></Body></Envelope>
}

func ExampleEncodeEnvelope_setSOAP12Empty() {
	var e soap.Envelope12

	req, err := soap.EncodeEnvelope("", &e)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(req.Message))

	// Output:
	// <Envelope xmlns="http://www.w3.org/2003/05/soap-envelope"><Body></Body></Envelope>
}
