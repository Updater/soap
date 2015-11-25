package soap

import (
	"bytes"
	"encoding/xml"
	"io"
	"time"
)

// Constants to represent the different SOAP versions.
const (
	V11 string = "1.1"
	V12 string = "1.2"
)

// RequestBuilder is an interface who implement a SOAP request.
type RequestBuilder interface {
	SetAction(act string) RequestBuilder
	AddSOAPHeaders(hdrs ...interface{}) RequestBuilder
	AddPayload(items ...interface{}) RequestBuilder
	Build() (*Request, error)
}

// Request represents a SOAP request.
type Request struct {
	Env       Envelope
	createdAt time.Time
}

// CreatedAt returns the time the request was created at.
func (req *Request) CreatedAt() time.Time {
	return req.createdAt
}

// Response models a received SOAP envelope and a pointer to Request structure.
type Response struct {
	Env        Envelope
	Request    *Request
	receivedAt time.Time
}

// Client represents a SOAP client that will be used
// to prepare requests and process responses.
type Client struct {
	// The SOAP version.
	// It should be one of the constants defined to represent the SOAP versions.
	// If an invalid value is passed, version 1.1 (V11) will be used.
	version string
	req     *Request
}

// NewRequestBuilder creates a new request builder.
func (c *Client) NewRequestBuilder() RequestBuilder {
	return &reqBuilder{
		version: c.version,
	}
}

// EncodeEnvelope function builds a request SOAP envelope and return data ([]bytes) to be sent.
func (c *Client) EncodeEnvelope(req *Request) ([]byte, error) {
	//To keep request on SOAP client.
	c.req = req

	e, err := xml.Marshal(req.Env)
	if err != nil {
		return nil, err
	}

	return e, nil
}

// DecodeEnvelope function returns an Response structure who contains a received SOAP envelope & a pointer to Request.
func (c *Client) DecodeEnvelope(resp io.Reader) (*Response, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(resp)
	if err != nil {
		return nil, err
	}

	var respEnv Envelope = &Envelope11{}
	if c.version == V12 {
		respEnv = &Envelope12{}
	}

	if err := xml.Unmarshal(buf.Bytes(), respEnv); err != nil {
		return nil, err
	}

	r := Response{
		Env:        respEnv,
		Request:    c.req,
		receivedAt: time.Now(),
	}

	return &r, nil
}

// NewClient intialize a SOAP client
func NewClient(version string) (*Client, error) {
	c := &Client{
		version: version,
	}

	return c, nil
}
