package http

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

// client is an implementation of the ClientAdapter interface that relies
// on the core http package.
type client struct {
	// The timeout specifies a time limit for requests made by a client.
	// If greater than zero, the maximum amount of time to wait for a response.
	// A Timeout of zero means no timeout.
	timeout time.Duration

	// The HTTP client pool to be used by this implementation of the
	// HTTPClientAdapter interface.
	pool *bvhttp.ClientPool

	username string

	password string
}

// Do sends a request.
func (c *client) Do(req *Request) (*Response, error) {
	if req.URL == "" {
		return nil, ErrURLNotSpecified
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, bytes.NewBuffer(req.Body))
	if err != nil {
		return nil, err
	}

	httpReq.Header = req.Header
	if len(c.username) > 0 {
		httpReq.SetBasicAuth(c.username, c.password)
	}

	req.SentAt = time.Now()

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

	resp := Response{
		Body:       buf.Bytes(),
		Request:    req,
		ReceivedAt: time.Now(),
	}

	return &resp, nil
}

// Option represents a configuration function for a HTTP client.
// An Option will configure or set up internal details of a HTTP client.
type Option func(*client)

// Timeout returns a configuration function to configure the timeout of a client.
// The timeout parameter specifies a time limit for requests made by a client.
// A Timeout of zero means no timeout.
func Timeout(timeout time.Duration) Option {
	return func(c *client) {
		c.timeout = timeout
	}
}

// Timeout returns a configuration function to configure the timeout of a client.
// The timeout parameter specifies a time limit for requests made by a client.
// A Timeout of zero means no timeout.
func BasicAuth(username string, password string) Option {
	return func(c *client) {
		c.username = username
		c.password = password
	}
}

// ClientPool returns a configuration function to configure the http client pool
// to be used by a client.
func ClientPool(pool *bvhttp.ClientPool) Option {
	return func(c *client) {
		c.pool = pool
	}
}

// NewClientAdapter creates a new HTTP client adapter and set its initial state.
func NewClientAdapter(opts ...Option) ClientAdapter {
	c := &client{}

	for _, opt := range opts {
		opt(c)
	}

	return c
}
