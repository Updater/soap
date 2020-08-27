package soap

import (
	"encoding/xml"
	"net/http"
	"time"

	soap_http "github.com/Updater/soap/http"
)

// Request represents a SOAP request.
type Request struct {
	Env         Envelope
	HTTPHeaders http.Header
	CreatedAt   time.Time
	SentAt      time.Time
}

// NewRequest TODO.
func NewRequest(action string, env Envelope) *Request {
	return &Request{
		Env:         env,
		HTTPHeaders: getHTTPHeaders(env.version(), action),
		CreatedAt:   time.Now(),
	}
}

// Response represents a SOAP response.
type Response struct {
	Env        Envelope
	Request    *Request
	ReceivedAt time.Time
	URL        string // URL that sent the response.
	Endpoint   string // An endpoint called by request.
	Method     string // A HTTP method used to contact the endpoint.
	StatusCode int    // HTTP status code received
	Payload    string // used when there is an error to strinify the body response
}

// Client represents a SOAP client that will be used
// to send requests and process responses.
type Client struct {
	// The URL of the endpoint to which the requests will be sent.
	url string

	// If different than nil, the HTTP Client adapter that
	// will be used to send the request.
	httpClient soap_http.ClientAdapter
}

// Do sends a SOAP request.
func (c *Client) Do(req *Request) (*Response, error) {
	payload, err := xml.Marshal(req.Env)
	if err != nil {
		return nil, err
	}

	httpReq := soap_http.NewRequest("POST", c.url, payload)
	httpReq.Header = req.HTTPHeaders
	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = soap_http.NewClientAdapter()
	}

	req.SentAt = time.Now()

	httpRes, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	env, err := decodeEnvelope(req.Env.version(), httpRes.Body)
	if err != nil {
		return &Response{
			Request:    req,
			ReceivedAt: time.Now(),
			URL:        c.url,
			Method:     httpReq.Method,
			StatusCode: httpRes.StatusCode,
			Payload:    string(httpRes.Body),
		}, err
	}

	resp := Response{
		Env:        env,
		Request:    req,
		ReceivedAt: time.Now(),
		URL:        c.url,
		Method:     httpReq.Method,
		StatusCode: httpRes.StatusCode,
	}

	return &resp, nil
}

// Option represents a configuration function for a SOAP client.
// An option will configure or set up internal details of a SOAP client.
type Option func(*Client)

// SetHTTPClient returns a configuration function to configure
// the HTTP Client that will be used to send the requests.
func SetHTTPClient(httpClient soap_http.ClientAdapter) Option {
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
