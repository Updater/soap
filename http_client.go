package soap

import (
	"bytes"
	"errors"
	"net/http"
	"time"

	bvhttp "github.com/Bridgevine/http"
)

// Errors that can be thrown.
var (
	ErrURLNotSpecified = errors.New("The URL of the endpoint has not been specified.")
)

// httpClient is an implementation of the HTTPClientAdapter interface that relies
// on the core http package.
type httpClient struct {
	// The timeout specifies a time limit for requests made by a client.
	// If greater than zero, the maximum amount of time to wait for a response.
	// A Timeout of zero means no timeout.
	timeout time.Duration

	// The HTTP client pool to be used by this implementation of the
	// HTTPClientAdapter interface.
	pool *bvhttp.ClientPool
}

// Do sends a request.
func (c *httpClient) Do(req *HTTPRequest) (*HTTPResponse, error) {
	if req.URL == "" {
		return nil, ErrURLNotSpecified
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, bytes.NewBuffer(req.Body))
	if err != nil {
		return nil, err
	}

	httpReq.Header = req.Header

	req.sentAt = time.Now()

	pool := c.pool
	if pool == nil {
		pool = bvhttp.DefaultClientPool
	}

	httpRes, err := pool.GetClient(c.timeout).Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpRes.Body.Close()

	var buf bytes.Buffer
	if _, err = buf.ReadFrom(httpRes.Body); err != nil {
		return nil, err
	}

	resp := HTTPResponse{
		Body:       buf.Bytes(),
		Request:    req,
		receivedAt: time.Now(),
	}

	return &resp, nil
}

// HTTPOption represents a configuration function for a HTTP client.
// An Option will configure or set up internal details of a HTTP client.
type HTTPOption func(*httpClient)

// Timeout returns a configuration function to configure the timeout of a client.
// The timeout parameter specifies a time limit for requests made by a client.
// A Timeout of zero means no timeout.
func Timeout(timeout time.Duration) HTTPOption {
	return func(c *httpClient) {
		c.timeout = timeout
	}
}

// HTTPClientPool returns a configuration function to configure the http client pool
// to be used by a client.
func HTTPClientPool(pool *bvhttp.ClientPool) HTTPOption {
	return func(c *httpClient) {
		c.pool = pool
	}
}

// NewHTTPClientAdapter creates a new HTTP client adapter and set its initial state.
func NewHTTPClientAdapter(opts ...HTTPOption) HTTPClientAdapter {
	c := &httpClient{}

	for _, opt := range opts {
		opt(c)
	}

	return c
}
