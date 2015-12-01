package soap

import (
	"net/http"
	"strings"
	"time"
)

// HTTPRequest represents a HTTP request.
type HTTPRequest struct {
	Method    string
	URL       string
	Header    http.Header
	Body      []byte
	createdAt time.Time
	sentAt    time.Time
}

// NewHTTPRequest creates a new Request.
func NewHTTPRequest(method, url string, body []byte) *HTTPRequest {
	return &HTTPRequest{
		Method:    strings.Trim(method, " "),
		URL:       url,
		Header:    make(http.Header),
		Body:      body,
		createdAt: time.Now(),
	}
}

// CreatedAt returns the time the request was created.
func (req *HTTPRequest) CreatedAt() time.Time {
	return req.createdAt
}

// SentAt returns the time the request was sent.
func (req *HTTPRequest) SentAt() time.Time {
	return req.sentAt
}

// HTTPResponse represents a HTTP response.
type HTTPResponse struct {
	Body       []byte
	Request    *HTTPRequest
	receivedAt time.Time
}

// ReceivedAt returns the time the response was received at.
func (res *HTTPResponse) ReceivedAt() time.Time {
	return res.receivedAt
}

// HTTPClientAdapter represents the behaviors that a HTTP Client adapter must satisfy.
type HTTPClientAdapter interface {
	Do(req *HTTPRequest) (*HTTPResponse, error)
}
