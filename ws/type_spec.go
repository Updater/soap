package ws

import "encoding/xml"

// ==============================================================================
// Web Services Addressing (WSA)	[http://www.w3.org/Submission/ws-addressing/]
// ==============================================================================

// EndpointReference models a web service endpoint reference.
// More details can be found at http://www.w3.org/Submission/ws-addressing/#_Toc77464317.
type EndpointReference struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing EndpointReference"`
	ID      string   `xml:"Id,attr,omitempty"`

	// Address is an URI that identifies the endpoint. This may be a network
	// address or a logical address.
	Address string `xml:"Address"`

	ReferenceProperties *ReferenceProperties `xml:"ReferenceProperties,omitempty"`
	ReferenceParameters *ReferenceParameters `xml:"ReferenceParameters,omitempty"`
	PortType            string               `xml:"PortType,omitempty"`
	ServiceName         *ServiceName         `xml:"ServiceName,omitempty"`
	Policy              *Policy              `xml:"Policy,omitempty"`

	// Items is an extensibility mechanism to allow additional elements to be specified.
	Items []interface{} `xml:",omitempty"`
}

// ReferenceProperties contains the elements that convey the [reference properties]
// of the reference. More details can be found at
// http://www.w3.org/Submission/ws-addressing/#_Toc77464319.
type ReferenceProperties struct {
	// Each item represents an individual [reference property].
	Items []interface{} `xml:",omitempty"`
}

// ReferenceParameters contains the elements that convey the [reference parameters]
// of the reference. More details can be found at
// http://www.w3.org/Submission/ws-addressing/#_Toc77464319.
type ReferenceParameters struct {
	// Each item represents an individual [reference parameter].
	Items []interface{} `xml:",omitempty"`
}

// ServiceName specifies the <wsdl:service> definition that contains a WSDL
// description of the endpoint being referenced. More details can be found at
// http://www.w3.org/Submission/ws-addressing/#_Toc77464319.
type ServiceName struct {
	// PortName specifies the name of the <wsdl:port> definition that corresponds
	// to the endpoint being referenced.
	PortName string `xml:"PortName,attr,omitempty"`
	Value    string `xml:",chardata"`
}

// Policy specifies a policy that is relevant to the interaction with the endpoint.
// More details can be found at http://www.w3.org/Submission/ws-addressing/#_Toc77464319.
type Policy struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2002/12/policy Policy"`
}

// MessageID conveys the [message id] property. This element MUST be present if
// wsa:ReplyTo or wsa:FaultTo is present.
type MessageID struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing MessageID"`
	ID      string   `xml:"Id,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// RelatesTo will typically be used on response messages to indicate that it is
// related to a previously-known message and to define that relationship. This
// element MUST be present if the message is a reply.
type RelatesTo struct {
	XMLName          xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing RelatesTo"`
	ID               string   `xml:"Id,attr,omitempty"`
	RelationshipType string   `xml:"RelationshipType,attr,omitempty"`

	// Value conveys the [message id] of the related message.
	Value string `xml:",chardata"`
}

// From provides the value for the [source endpoint] property.
type From struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing From"`
	ID      string   `xml:"Id,attr,omitempty"`
	Address string   `xml:"Address"`
}

// To provides the value for the [destination endpoint] property.
// To is nothing more than the target web service's URL. Typically, this URL
// is the same as the HTTP request's URL, but it is not required to be.
type To struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing To"`
	ID      string   `xml:"Id,attr,omitempty"`
	Address string   `xml:",chardata"`
}

// ReplyTo provides the value for the [reply endpoint] property.
// This element MUST be present if a reply is expected. If this element is present,
// wsa:MessageID MUST be present.
type ReplyTo struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing ReplyTo"`
	ID      string   `xml:"Id,attr,omitempty"`
	Address string   `xml:"Address"`
}

// FaultTo provides the value for the [fault endpoint] property. If this element
// is present, wsa:MessageID MUST be present. If the response to a message is a
// SOAP fault, the fault should be sent to the fault endpoint in the FaultTo element.
type FaultTo struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing FaultTo"`
	ID      string   `xml:"Id,attr,omitempty"`
	Address string   `xml:"Address"`
}

// Action represents the in-envelope version of the SOAP HTTP Action header.
type Action struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing Action"`
	ID      string   `xml:"Id,attr,omitempty"`
	Value   string   `xml:",chardata"`
}
