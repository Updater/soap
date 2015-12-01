package soap

import "encoding/xml"

// EnvBuilder represents the behaviors that an Envelope builder must satisfy.
type EnvBuilder interface {
	SetHeaders(hdrs ...interface{}) EnvBuilder
	AddHeaders(hdrs ...interface{}) EnvBuilder
	SetPayload(items ...interface{}) EnvBuilder
	AddPayload(items ...interface{}) EnvBuilder
	Build(version string) (Envelope, error)
}

// envBuilder is an implementation of the EnvBuilder interface.
type envBuilder struct {
	headers []interface{}
	payload []interface{}
}

// SetHeaders sets the SOAP headers, overriding the previous ones.
func (bldr *envBuilder) SetHeaders(hdrs ...interface{}) EnvBuilder {
	bldr.headers = hdrs
	return bldr
}

// AddHeaders adds the specified headers to the current headers.
func (bldr *envBuilder) AddHeaders(hdrs ...interface{}) EnvBuilder {
	if len(hdrs) > 0 {
		bldr.headers = append(bldr.headers, hdrs...)
	}

	return bldr
}

// SetPayload sets the payload, overriding the previous one.
func (bldr *envBuilder) SetPayload(items ...interface{}) EnvBuilder {
	bldr.payload = items
	return bldr
}

// AddPayload adds the specified items to the current payload.
func (bldr *envBuilder) AddPayload(items ...interface{}) EnvBuilder {
	if len(items) > 0 {
		bldr.payload = append(bldr.payload, items...)
	}

	return bldr
}

// Build builds an Envelope for the specified SOAP version.
func (bldr *envBuilder) Build(version string) (Envelope, error) {
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

// NewEnvBuilder returns a new Envelope builder.
func NewEnvBuilder() EnvBuilder {
	return &envBuilder{}
}

// NewEnvelope returns a new Envelope based on the parameters passed.
func NewEnvelope(version string, header, payload interface{}) (Envelope, error) {
	return NewEnvBuilder().
		AddHeaders(header).
		AddPayload(payload).
		Build(version)
}
