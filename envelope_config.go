package soap

import (
	"encoding/xml"
	"net/http"
)

// EnvelopeConfig is an structure to contain builder parameters.
type EnvelopeConfig struct {
	version string
	action  string
	headers []interface{}
	payload []interface{}
}

// SetAction set the required SOAP action.
func (ec *EnvelopeConfig) SetAction(act string) *EnvelopeConfig {
	ec.action = act
	return ec
}

// SetSOAPHeaders sets SOAP headers.
func (ec *EnvelopeConfig) SetSOAPHeaders(hdrs ...interface{}) *EnvelopeConfig {
	ec.headers = hdrs

	return ec
}

// SetPayload sets required payload.
func (ec *EnvelopeConfig) SetPayload(items ...interface{}) *EnvelopeConfig {
	ec.payload = items

	return ec
}

// Build builds SOAP request.
func (ec *EnvelopeConfig) Build() (Envelope, error) {
	bdy, err := xml.Marshal(ec.payload)
	if err != nil {
		return nil, err
	}

	var e Envelope
	switch ec.version {
	case V12:
		e = &Envelope12{BodyElem: Body12{PayloadElem: bdy}}
	case V11:
		e = &Envelope11{BodyElem: Body11{PayloadElem: bdy}}
	default:
		return nil, ErrInvalidVersion
	}

	if len(ec.headers) > 0 {
		hdr, err := xml.Marshal(ec.headers)
		if err != nil {
			return nil, err
		}

		if len(hdr) > 0 {
			e.setHeader(&Header{Content: hdr})
		}
	}

	return e, nil
}

// GetHTTPBinding builds an Envelope and returns its HTTPBinding representation.
func (ec *EnvelopeConfig) GetHTTPBinding() (*HTTPBinding, error) {
	e, err := ec.Build()
	if err != nil {
		return nil, err
	}

	m, err := xml.Marshal(e)
	if err != nil {
		return nil, err
	}

	th := make(map[string]string)
	if ec.version == V12 {
		th["Content-Type"] = "application/soap+xml; charset=utf-8; action=\"" + ec.action + "\""
	} else {
		th["Content-Type"] = "text/xml; charset=utf-8"
		th["SOAPAction"] = ec.action
	}

	h := make(http.Header)
	for k, v := range th {
		h.Add(k, v)
	}

	return &HTTPBinding{
		Message:  m,
		Header:   h,
		Envelope: e,
	}, nil
}

// NewEnvelopeConfig creates a new EnvelopeConfig based on the provided SOAP version.
func NewEnvelopeConfig(version string) (*EnvelopeConfig, error) {
	if !(version == V11 || version == V12) {
		return nil, ErrInvalidVersion
	}

	return &EnvelopeConfig{version: version}, nil
}
