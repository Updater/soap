package soap

import (
	"bytes"
	"encoding/xml"
	"net/http"
)

// EnvBuilder is a SOAP Envelope builder.
type EnvBuilder struct {
	headers []interface{}
	payload []interface{}
	env     Envelope
}

// SetHeaders sets the SOAP headers, overriding the previous ones.
func (bldr *EnvBuilder) SetHeaders(hdrs ...interface{}) *EnvBuilder {
	bldr.headers = hdrs
	return bldr
}

// SetPayload sets the payload, overriding the previous one.
func (bldr *EnvBuilder) SetPayload(items ...interface{}) *EnvBuilder {
	bldr.payload = items
	return bldr
}

// Env will return the latest envelope built with this builder.
// If neither Build nor BuildHTTPRequest has been called successfully,
// nil will be returned.
func (bldr *EnvBuilder) Env() Envelope {
	return bldr.env
}

// Build builds an Envelope for the specified SOAP version.
func (bldr *EnvBuilder) Build(version string) (Envelope, error) {
	if !isValidVersion(version) {
		return nil, ErrInvalidVersion
	}

	bdy, err := xml.Marshal(bldr.payload)
	if err != nil {
		return nil, err
	}

	var env Envelope = &Envelope11{BodyElem: Body11{PayloadElem: bdy}}
	if version == V12 {
		env = &Envelope12{BodyElem: Body12{PayloadElem: bdy}}
	}

	if len(bldr.headers) > 0 {
		hdr, err := xml.Marshal(bldr.headers)
		if err != nil {
			return nil, err
		}

		if len(hdr) > 0 {
			env.setHeader(&Header{Content: hdr})
		}
	}

	return env, nil
}

// BuildHTTPRequest builds a HTTP Request.
func (bldr *EnvBuilder) BuildHTTPRequest(version string, action string) (*http.Request, error) {
	env, err := bldr.Build(version)
	if err != nil {
		return nil, err
	}

	body, err := xml.Marshal(env)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header = getHTTPHeaders(version, action)

	return req, nil
}

// NewEnvBuilder returns a new Envelope builder.
func NewEnvBuilder() *EnvBuilder {
	return &EnvBuilder{}
}

// NewEnvelope returns a new Envelope based on the parameters passed.
func NewEnvelope(version string, header interface{}, payload interface{}) (Envelope, error) {
	return NewEnvBuilder().
		SetHeaders(header).
		SetPayload(payload).
		Build(version)
}
