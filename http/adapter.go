package http

import (
	"net/http"
	"strings"
	"time"
)

// Request represents a HTTP request.
type Request struct {
	Method    string
	URL       string
	Header    http.Header
	Body      []byte
	CreatedAt time.Time
	SentAt    time.Time
}

// NewRequest creates a new Request.
func NewRequest(method, url string, body []byte) *Request {
	return &Request{
		Method:    strings.Trim(method, " "),
		URL:       url,
		Header:    make(http.Header),
		Body:      body,
		CreatedAt: time.Now(),
	}
}

// Response represents a HTTP response.
type Response struct {
	Body       []byte
	Request    *Request
	ReceivedAt time.Time
	StatusCode int
}

// ClientAdapter represents the behaviors that a HTTP Client adapter must satisfy.
type ClientAdapter interface {
	Do(req *Request) (*Response, error)
}
