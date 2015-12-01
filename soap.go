package soap

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strings"
)

// Constants to represent the different SOAP versions.
const (
	V11 string = "1.1"
	V12 string = "1.2"
)

// ErrInvalidVersion is an error returned when the specified version is not
// one of the allowed versions.
var ErrInvalidVersion = errors.New("version must be either 1.1 or 1.2")

// isValidVersion determines if the specified version is valid.
func isValidVersion(version string) bool {
	return version == V11 || version == V12
}

// getHTTPHeaders gets the required HTTP headers that must be sent
// with an HTTP request that carries a SOAP message.
func getHTTPHeaders(version, action string) http.Header {
	action = strings.Trim(version, " ")

	headers := make(http.Header)

	if version == V12 {
		headers.Set("Content-Type", "application/soap+xml; charset=utf-8; action=\""+action+"\"")
	} else {
		headers.Set("Content-Type", "text/xml; charset=utf-8")
		headers.Set("SOAPAction", action)
	}

	return headers
}

// GetHTTPHeaders gets the required HTTP headers that must be sent
// with an HTTP request that carries a SOAP message.
func GetHTTPHeaders(version, action string) (http.Header, error) {
	if !isValidVersion(version) {
		return nil, ErrInvalidVersion
	}

	return getHTTPHeaders(version, action), nil
}

// decodeEnvelope decodes the specified data into an Envelope
// of the specified version.
func decodeEnvelope(version string, data []byte) (Envelope, error) {
	var env Envelope = &Envelope11{}
	if version == V12 {
		env = &Envelope12{}
	}

	if err := xml.Unmarshal(data, env); err != nil {
		return nil, err
	}

	return env, nil
}

// DecodeEnvelope decodes the specified io.Reader into an Envelope
// of the specified version.
func DecodeEnvelope(version string, r io.Reader) (Envelope, error) {
	if !isValidVersion(version) {
		return nil, ErrInvalidVersion
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}

	return decodeEnvelope(version, buf.Bytes())
}
