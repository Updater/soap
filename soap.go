package soap

import (
	"encoding/xml"
	"time"
)

// Constants to represent the different SOAP versions.
const (
	V11 string = "1.1"
	V12 string = "1.2"
)

// Request models a SOAP request.
type Request struct {
	Action      string
	HTTPHeaders map[string]string
	Header      interface{}
	Payload     interface{}
}

// Client represents a SOAP client that will be used
// to send requests and process responses.
type Client struct {
	XMLClient

	// The SOAP version. Should be one of the constants defined to represent the SOAP versions.
	// If an invalid value is passed, version 1.1 (V11) will be used.
	Version string
}

// Do sends a SOAP request.
func (c *Client) Do(req Request) (Envelope, error) {
	bdyContent, err := xml.Marshal(req.Payload)
	if err != nil {
		return nil, err
	}

	var reqEnv Envelope = &Envelope11{BodyElem: Body11{PayloadElem: bdyContent}}
	if c.Version == V12 {
		reqEnv = &Envelope12{BodyElem: Body12{PayloadElem: bdyContent}}
	}

	if req.Header != nil {
		hdrContent, err := xml.Marshal(req.Header)
		if err != nil {
			return nil, err
		}

		if len(hdrContent) > 0 {
			reqEnv.setHeader(&Header{Content: hdrContent})
		}
	}

	if req.HTTPHeaders == nil {
		req.HTTPHeaders = make(map[string]string)
	}

	if c.Version == V12 {
		req.HTTPHeaders["Content-Type"] = "application/soap+xml; charset=utf-8; action=\"" + req.Action + "\""
	} else {
		req.HTTPHeaders["Content-Type"] = "text/xml; charset=utf-8"
		req.HTTPHeaders["SOAPAction"] = req.Action
	}

	resp, err := c.XMLClient.Do(req.HTTPHeaders, reqEnv)
	if err != nil {
		return nil, err
	}

	var respEnv Envelope = &Envelope11{}
	if c.Version == V12 {
		respEnv = &Envelope12{}
	}

	if err := xml.Unmarshal(resp, respEnv); err != nil {
		return nil, err
	}

	return respEnv, nil
}

// NewClient creates a new SOAP client and set its initial state.
// The version parameter represents the SOAP version.
// The url parameter represents the SOAP Service URL.
// The timeout parameter specifies a time limit for requests made by this Client.
// A Timeout of zero means no timeout.
func NewClient(version string, url string, timeout time.Duration) (*Client, error) {
	c := Client{Version: version}
	c.URL = url
	c.Timeout = timeout

	return &c, nil
}

// SetTLSConfig should be called to set/update the TLS Configuration
// to be shared by all the HTTP Clients.
func SetTLSConfig(certProvFile, certFile, keyFile string) {
	httpPool.SetTLSConfig(certProvFile, certFile, keyFile)
}
