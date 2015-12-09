package soap

import (
	"bytes"
	"encoding/xml"
	"net/http"
)

// Header models the header section of the SOAP Envelope.
type Header struct {
	Content []byte `xml:",innerxml"`
}

// Envelope represents behaviors supported by a SOAP Envelope.
type Envelope interface {
	Header() *Header
	Body() Body
	GetHTTPRequest(action string) (*http.Request, error)
	setHeader(*Header)
	version() string
}

// Envelope11 models an envelope following the SOAP 1.1 Envelope specs.
type Envelope11 struct {
	XMLName    xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	HeaderElem *Header  `xml:"Header,omitempty"`
	BodyElem   Body11   `xml:"Body"`
}

// Header implements the Header method of the Envelope interface.
func (e *Envelope11) Header() *Header {
	return e.HeaderElem
}

// Body implements the Body method of the Envelope interface.
func (e *Envelope11) Body() Body {
	return &e.BodyElem
}

// setHeader implements the setHeader method of the Envelope interface.
func (e *Envelope11) setHeader(hdr *Header) {
	e.HeaderElem = hdr
}

// version returns the SOAP version of the Envelope.
func (e *Envelope11) version() string {
	return V11
}

func (e *Envelope11) GetHTTPRequest(action string) (*http.Request, error) {
	body, err := xml.Marshal(e)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header = getHTTPHeaders(e.version(), action)

	return req, nil
}

// Envelope12 models an envelope following the SOAP 1.2 Envelope specs.
type Envelope12 struct {
	XMLName    xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
	HeaderElem *Header  `xml:"Header,omitempty"`
	BodyElem   Body12   `xml:"Body"`
}

// Header implements the Header method of the Envelope interface.
func (e *Envelope12) Header() *Header {
	return e.HeaderElem
}

// Body implements the Body method of the Envelope interface.
func (e *Envelope12) Body() Body {
	return &e.BodyElem
}

// setHeader implements the setHeader method of the Envelope interface.
func (e *Envelope12) setHeader(hdr *Header) {
	e.HeaderElem = hdr
}

// version returns the SOAP version of the Envelope.
func (e *Envelope12) version() string {
	return V12
}

func (e *Envelope12) GetHTTPRequest(action string) (*http.Request, error) {
	body, err := xml.Marshal(e)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header = getHTTPHeaders(e.version(), action)

	return req, nil
}
