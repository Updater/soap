package soap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
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

func getHTTPRequest(env Envelope, action string) (*http.Request, error) {
	body, err := xml.Marshal(env)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header = getHTTPHeaders(env.version(), action)

	return req, nil
}

func envelopeMarshalXML(env Envelope, xmlns map[string]string, e *xml.Encoder, start xml.StartElement) error {
	var keys []string
	for k := range xmlns {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	for _, k := range keys {
		start.Attr = append(
			start.Attr,
			xml.Attr{Name: xml.Name{Local: fmt.Sprintf("xmlns:%s", k)}, Value: xmlns[k]},
		)
	}

	if err := e.EncodeToken(start); err != nil {
		return err
	}

	if err := e.EncodeElement(env.Header(), xml.StartElement{Name: xml.Name{Local: "Header"}}); err != nil {
		return err
	}

	if err := e.EncodeElement(env.Body(), xml.StartElement{Name: xml.Name{Local: "Body"}}); err != nil {
		return err
	}

	if err := e.EncodeToken(start.End()); err != nil {
		return err
	}

	return nil
}

// Envelope11 models an envelope following the SOAP 1.1 Envelope specs.
type Envelope11 struct {
	XMLName    xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Xmlns      map[string]string
	HeaderElem *Header `xml:"Header,omitempty"`
	BodyElem   Body11  `xml:"Body"`
}

func (x Envelope11) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Local: "x:Envelope"}
	return e.EncodeElement(struct {
		XMLx       string  `xml:"xmlns:x,attr"`
		HeaderElem *Header `xml:"x:Header,omitempty"`
		BodyElem   Body11  `xml:"x:Body"`
	}{
		XMLx:       "http://schemas.xmlsoap.org/soap/envelope/",
		HeaderElem: x.HeaderElem,
		BodyElem:   x.BodyElem,
	}, start)
}

// Header implements the Header method of the Envelope interface.
func (e *Envelope11) Header() *Header {
	return e.HeaderElem
}

// Body implements the Body method of the Envelope interface.
func (e *Envelope11) Body() Body {
	return &e.BodyElem
}

// GetHTTPRequest TODO.
func (e *Envelope11) GetHTTPRequest(action string) (*http.Request, error) {
	return getHTTPRequest(e, action)
}

// setHeader implements the setHeader method of the Envelope interface.
func (e *Envelope11) setHeader(hdr *Header) {
	e.HeaderElem = hdr
}

// version returns the SOAP version of the Envelope.
func (e *Envelope11) version() string {
	return V11
}

// Envelope12 models an envelope following the SOAP 1.2 Envelope specs.
type Envelope12 struct {
	XMLName    xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
	Xmlns      map[string]string
	HeaderElem *Header `xml:"Header,omitempty"`
	BodyElem   Body12  `xml:"Body"`
}

// Header implements the Header method of the Envelope interface.
func (e *Envelope12) Header() *Header {
	return e.HeaderElem
}

// Body implements the Body method of the Envelope interface.
func (e *Envelope12) Body() Body {
	return &e.BodyElem
}

// GetHTTPRequest TODO.
func (e *Envelope12) GetHTTPRequest(action string) (*http.Request, error) {
	return getHTTPRequest(e, action)
}

// setHeader implements the setHeader method of the Envelope interface.
func (e *Envelope12) setHeader(hdr *Header) {
	e.HeaderElem = hdr
}

// version returns the SOAP version of the Envelope.
func (e *Envelope12) version() string {
	return V12
}

// MarshalXML sets the SOAP 1.2 namespace and calls the generic envelope XML marshaller.
func (e *Envelope12) MarshalXML(enc *xml.Encoder, start xml.StartElement) error {
	start.Name = xml.Name{Space: "http://www.w3.org/2003/05/soap-envelope", Local: "Envelope"}

	return envelopeMarshalXML(e, e.Xmlns, enc, start)
}
