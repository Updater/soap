package soap

import (
	"encoding/xml"
	"time"
)

// reqBuilder is an structure to contain builder parameters.
type reqBuilder struct {
	version string
	action  string
	headers []interface{}
	payload []interface{}
}

// SetAction set the required SOAP action.
func (bldr *reqBuilder) SetAction(act string) RequestBuilder {
	bldr.action = act
	return bldr
}

// AddSOAPHeaders appends required SOAP headers.
func (bldr *reqBuilder) AddSOAPHeaders(hdrs ...interface{}) RequestBuilder {
	if len(hdrs) > 0 {
		bldr.headers = append(bldr.headers, hdrs...)
	}

	return bldr
}

// AddPayload appends required payload.
func (bldr *reqBuilder) AddPayload(items ...interface{}) RequestBuilder {
	if len(items) > 0 {
		bldr.payload = append(bldr.payload, items...)
	}

	return bldr
}

// Build builds SOAP request.
func (bldr *reqBuilder) Build() (*Request, error) {
	bdy, err := xml.Marshal(bldr.payload)
	if err != nil {
		return nil, err
	}

	var env Envelope = &Envelope11{BodyElem: Body11{PayloadElem: bdy}}
	if bldr.version == V12 {
		env = &Envelope12{BodyElem: Body12{PayloadElem: bdy}}
	}

	if len(bldr.headers) > 0 {
		hdr, err := xml.Marshal(bldr.headers)
		if err != nil {
			return nil, err
		}

		if len(hdr) > 0 {
			env.setHeader(&Header{Content: hdr})
		}
	}

	req := Request{
		Env:       env,
		createdAt: time.Now(),
	}

	return &req, nil
}
