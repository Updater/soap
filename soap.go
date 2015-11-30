package soap

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
)

// Constants to represent the different SOAP versions.
const (
	V11 string = "1.1"
	V12 string = "1.2"
)

// HTTPBinding models the data needed to populate a http.Client object.
// Where a buffer of Message is to be used as the body param of a NewRequest object.
// A buffer of the Message field can also be used as the body param of a http.Post object.
// The Header represents the http header to be used on the http.Client object.
// Envelope represents the underlying object of the Message field.
type HTTPBinding struct {
	Message  []byte
	Header   http.Header
	Envelope Envelope
}

// GetHTTPBinding returns data ([]bytes) to be sent when using a http post.
func GetHTTPBinding(action string, e Envelope) (*HTTPBinding, error) {
	m, err := xml.Marshal(e)
	if err != nil {
		return nil, err
	}

	th := make(map[string]string)
	switch e.(type) {
	case *Envelope12:
		th["Content-Type"] = "application/soap+xml; charset=utf-8; action=\"" + action + "\""
	case *Envelope11:
		th["Content-Type"] = "text/xml; charset=utf-8"
		th["SOAPAction"] = action
	default:
		return nil, ErrInvalidVersion
	}

	h := make(http.Header)
	for k, v := range th {
		h.Add(k, v)
	}

	hb := HTTPBinding{
		Message:  m,
		Header:   h,
		Envelope: e,
	}

	return &hb, nil
}

// DecodeEnvelope function returns an Response structure who contains a received SOAP envelope & a pointer to Request.
func DecodeEnvelope(version string, r io.Reader) (Envelope, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r)
	if err != nil {
		return nil, err
	}

	var e Envelope
	switch version {
	case V12:
		e = &Envelope12{}
	case V11:
		e = &Envelope11{}
	default:
		return nil, ErrInvalidVersion
	}

	if err := xml.Unmarshal(buf.Bytes(), e); err != nil {
		return nil, err
	}

	return e, nil
}
