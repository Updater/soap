package soap

// Body represents behaviors supported by the Body element of a SOAP Envelope.
type Body interface {
	Fault() Fault
	Payload() []byte
}

// Body11 models the body element of the SOAP 1.1 Envelope.
type Body11 struct {
	FaultElem   *Fault11 `xml:"Fault,omitempty"`
	PayloadElem []byte   `xml:",innerxml"`
}

// Payload returns the payload contained in the body element of a SOAP 1.1 Envelope.
func (b *Body11) Payload() []byte {
	return b.PayloadElem
}

// Fault returns the fault element contained in the body element of a SOAP 1.1 Envelope, if present.
func (b *Body11) Fault() Fault {
	if b.FaultElem != nil {
		return b.FaultElem
	}

	return nil
}

// Body12 models the body element of the SOAP 1.2 Envelope.
type Body12 struct {
	FaultElem   *Fault12 `xml:"Fault,omitempty"`
	PayloadElem []byte   `xml:",innerxml"`
}

// Payload returns the payload contained in the body element of a SOAP 1.2 Envelope.
func (b *Body12) Payload() []byte {
	return b.PayloadElem
}

// Fault returns the fault element contained in the body element of a SOAP 1.2 Envelope, if present.
func (b *Body12) Fault() Fault {
	if b.FaultElem != nil {
		return b.FaultElem
	}

	return nil
}
