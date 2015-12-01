package soap

import (
	"encoding/xml"
	"net/http"
	"time"
)

// Request represents a SOAP request.
type Request struct {
	Env         Envelope
	HTTPHeaders http.Header
	createdAt   time.Time
	sentAt      time.Time
}

// NewRequest TODO.
func NewRequest(action string, env Envelope) *Request {
	return &Request{
		Env:         env,
		HTTPHeaders: getHTTPHeaders(env.version(), action),
		createdAt:   time.Now(),
	}
}

// CreatedAt returns the time the request was created.
func (req *Request) CreatedAt() time.Time {
	return req.createdAt
}

// SentAt returns the time the request was sent.
func (req *Request) SentAt() time.Time {
	return req.sentAt
}

// Response represents a SOAP response.
type Response struct {
	Env        Envelope
	Request    *Request
	receivedAt time.Time
}

// ReceivedAt returns the time the response was received.
func (res *Response) ReceivedAt() time.Time {
	return res.receivedAt
}

// Client represents a SOAP client that will be used
// to send requests and process responses.
type Client struct {
	// The URL of the endpoint to which the requests will be sent.
	url string

	// If different than nil, the HTTP Client adapter that
	// will be used to send the request.
	httpClient HTTPClientAdapter
}

// Do sends a SOAP request.
func (c *Client) Do(req *Request) (*Response, error) {
	payload, err := xml.Marshal(req.Env)
	if err != nil {
		return nil, err
	}

	httpReq := NewHTTPRequest("POST", c.url, payload)
	httpReq.Header = req.HTTPHeaders

	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = NewHTTPClientAdapter()
	}

	req.sentAt = time.Now()

	httpRes, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	env, err := decodeEnvelope(req.Env.version(), httpRes.Body)
	if err != nil {
		return nil, err
	}

	resp := Response{
		Env:        env,
		Request:    req,
		receivedAt: time.Now(),
	}

	return &resp, nil
}

// Option represents a configuration function for a SOAP client.
// An option will configure or set up internal details of a SOAP client.
type Option func(*Client)

// HTTPClient returns a configuration function to configure
// the HTTP Client that will be used to send the requests.
func HTTPClient(httpClient HTTPClientAdapter) Option {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// NewClient creates a new SOAP client and set its initial state.
// The url parameter represents the SOAP Service URL.
func NewClient(url string, opts ...Option) (*Client, error) {
	c := &Client{
		url: url,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}
