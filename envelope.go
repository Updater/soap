package soap

import "encoding/xml"

// Header models the header section of the SOAP Envelope.
type Header struct {
	Content []byte `xml:",innerxml"`
}

// Envelope represents behaviors supported by a SOAP Envelope.
type Envelope interface {
	Header() *Header
	setHeader(*Header)
	Body() Body
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

// setHeader implements the setHeader method of the Envelope interface.
func (e *Envelope11) setHeader(hdr *Header) {
	e.HeaderElem = hdr
}

// Body implements the Body method of the Envelope interface.
func (e *Envelope11) Body() Body {
	return &e.BodyElem
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

// setHeader implements the setHeader method of the Envelope interface.
func (e *Envelope12) setHeader(hdr *Header) {
	e.HeaderElem = hdr
}

// Body implements the Body method of the Envelope interface.
func (e *Envelope12) Body() Body {
	return &e.BodyElem
}
