package soap

import "encoding/xml"

// Fault represents behaviors supported by a Fault.
type Fault interface {
	GetCode() string
	Description() string
	Details() []byte
}

// FaultDetail is a container for carrying application specific error information
// about errors occurred on the endpoint that we will be communicating with.
// The type of the errors is not known until the response is received, that is why
// the Items property is an slice of interface{}.
type FaultDetail struct {
	Items []byte `xml:",innerxml"`
}

// Fault11 models a fault under SOAP 1.1.
type Fault11 struct {
	XMLName xml.Name     `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`
	Code    string       `xml:"faultcode"`
	String  string       `xml:"faultstring"`
	Actor   string       `xml:"faultactor,omitempty"`
	Detail  *FaultDetail `xml:"detail,omitempty"`
}

// GetCode implements the GetCode method of the Fault interface.
func (f *Fault11) GetCode() string {
	return f.Code
}

// Description implements the Description method of the Fault interface.
func (f *Fault11) Description() string {
	return f.String
}

// Details implements the Details method of the Fault interface.
func (f *Fault11) Details() []byte {
	if f.Detail != nil {
		return f.Detail.Items
	}

	return nil
}

// Fault12 models a fault under SOAP 1.2.
type Fault12 struct {
	XMLName xml.Name     `xml:"http://www.w3.org/2003/05/soap-envelope Fault"`
	Code    Code         `xml:"Code"`
	Reason  Reason       `xml:"Reason"`
	Node    string       `xml:"Node,omitempty"`
	Role    string       `xml:"Role,omitempty"`
	Detail  *FaultDetail `xml:"Detail,omitempty"`
}

// GetCode implements the GetCode method of the Fault interface.
func (f *Fault12) GetCode() string {
	return f.Code.Value
}

// Description implements the Description method of the Fault interface.
func (f *Fault12) Description() string {
	if len(f.Reason.Items) == 0 {
		return ""
	}

	// returning the first reason in the slice, should be enhanced.
	return f.Reason.Items[0].Value
}

// Details implements the Details method of the Fault interface.
func (f *Fault12) Details() []byte {
	if f.Detail != nil {
		return f.Detail.Items
	}

	return nil
}

// Subcode models the SOAP 1.2 subcode element.
// Specifications can be found at http://www.w3.org/TR/2003/REC-soap12-part1-20030624/#faultsubcodeelement.
type Subcode struct {
	Value   string   `xml:"Value"`
	Subcode *Subcode `xml:"Subcode,omitempty"`
}

// Code models the SOAP 1.2 code element.
// Specifications can be found at http://www.w3.org/TR/2003/REC-soap12-part1-20030624/#faultcodeelement.
type Code struct {
	Value   string   `xml:"Value"`
	Subcode *Subcode `xml:"Subcode,omitempty"`
}

// Text models the SOAP 1.2 text element.
// The Text element information item is intended to carry the text
// of a human readable explanation of the fault.
// Specifications can be found at http://www.w3.org/TR/2003/REC-soap12-part1-20030624/#reasontextelement.
type Text struct {
	Language string `xml:"lang,attr"`
	Value    string `xml:",chardata"`
}

// Reason models the SOAP 1.2 reason element.
// The Reason element information item is intended to provide a human
// readable explanation of the fault.
// Specifications can be found at http://www.w3.org/TR/2003/REC-soap12-part1-20030624/#faultstringelement.
type Reason struct {
	Items []Text `xml:"Text"`
}

// FaultDetails2 represents the content of Body.Fault.Details() field.
type FaultDetails2 struct {
	Message       string `xml:"message"`
	SOAPErrorCode string `xml:"soapErrorCode"`
}
