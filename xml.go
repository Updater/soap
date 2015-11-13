package soap

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/Azure/azure-sdk-for-go/core/http"
)

// Errors that can be thrown.
var (
	ErrURLNotSpecified  = errors.New("The URL of the endpoint has not been specified.")
	ErrMissingTypesInfo = xml.UnmarshalError("The type information has not been specified.")
)

// XMLClient represents an XML client that will be used to send
// requests and process responses. The transport mechanism
// will be HTTP, and the payload on each request will be xml.
type XMLClient struct {
	// The URL of the endpoint to which the requests will be sent.
	URL string

	// If greater than zero, the maximum amount of time to wait for a response.
	Timeout time.Duration
}

// Do sends a Raw XML request over HTTP.
func (c *XMLClient) Do(headers map[string]string, payload interface{}) ([]byte, error) {
	if c.URL == "" {
		return nil, ErrURLNotSpecified
	}

	bdy, err := xml.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.URL, bytes.NewBuffer(bdy))
	if err != nil {
		return nil, err
	}

	if len(headers) > 0 {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}

	resp, err := httpPool.GetClient(c.Timeout).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// NewXMLClient creates a new XML client and set its initial state.
// The url parameter represents the URL of the endpoint to which
// the requests will be sent.
// The timeout parameter specifies a time limit for requests
// made by this Client. A Timeout of zero means no timeout.
func NewXMLClient(url string, timeout time.Duration) (*XMLClient, error) {
	c := XMLClient{
		URL:     url,
		Timeout: timeout,
	}

	return &c, nil
}

// UnmarshalXMLElement handles the unmarshalling of the details
// according to the specified types information.
func UnmarshalXMLElement(details []byte, typesInfo interface{}) ([]interface{}, error) {
	if typesInfo == nil {
		return nil, ErrMissingTypesInfo
	}

	mt, mtOK := typesInfo.(map[string]reflect.Type)
	mp, mpOK := typesInfo.(map[string]interface{})

	usingPtr := reflect.TypeOf(typesInfo).Kind() == reflect.Ptr
	usingMT := mtOK && len(mt) > 0
	usingMP := mpOK && len(mp) > 0

	// Checking if the type information was passed
	// using one of the three supported approaches.
	if !(usingPtr || usingMP || usingMT) {
		return nil, ErrMissingTypesInfo
	}

	var results []interface{}

	dec := xml.NewDecoder(bytes.NewReader(details))

	for {
		// Get the next token to be processed.
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				return results, nil
			}
			return nil, err
		}

		if tok == nil {
			return results, nil
		}

		switch se := tok.(type) {
		case xml.StartElement:
			if usingPtr {
				if err := dec.DecodeElement(typesInfo, &se); err != nil {
					return nil, err
				}
				results = append(results, typesInfo)
				continue
			}

			if usingMP {
				if ptr, ok := mp[se.Name.Local]; ok {
					if reflect.TypeOf(ptr).Kind() != reflect.Ptr {
						return nil, xml.UnmarshalError("non-pointer passed to unmarshal element " + se.Name.Local)
					}
					if err := dec.DecodeElement(ptr, &se); err != nil {
						return nil, err
					}
					results = append(results, ptr)
				}
				continue
			}

			if usingMT {
				if typ, ok := mt[se.Name.Local]; ok {
					ptr := reflect.New(typ).Interface()
					if err := dec.DecodeElement(ptr, &se); err != nil {
						return nil, err
					}
					results = append(results, ptr)
				}
				continue
			}
		}
	}
}
