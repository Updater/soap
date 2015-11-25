package soap_test

import (
	"encoding/xml"
	"errors"
	"fmt"

	"github.com/Bridgevine/t-soap"
)

// These constants provide visual markers for test output.
const (
	success = "\u2713" // check mark
	failure = "X"      // uppercase x
)

// Sample00 represents a type that will be used in the test suites.
type Sample00 struct {
	XMLName xml.Name `xml:"http://bridgevine.com/ngdc/test Sample00"`
	ID      int      `xml:"id,attr"`
	Name    string   `xml:"name"`
}

// String implements the Stringer interface.
func (s Sample00) String() string {
	return fmt.Sprintf("Sample: XMLName[Space:%s Local:%s], ID=[%d], Name=[%s]", s.XMLName.Space, s.XMLName.Local, s.ID, s.Name)
}

// Sample01 represents a type that will be used in the test suites.
type Sample01 struct {
	XMLName xml.Name `xml:"http://bridgevine.com/ngdc/test Sample01"`
	ID      int      `xml:"id,attr"`
	Name    string   `xml:"name"`
}

// String implements the Stringer interface.
func (s Sample01) String() string {
	return fmt.Sprintf("Sample: XMLName[Space:%s Local:%s], ID=[%d], Name=[%s]", s.XMLName.Space, s.XMLName.Local, s.ID, s.Name)
}

type Sample02 struct {
	XMLName xml.Name `xml:"http://bridgevine.com/ngdc/test Sample02"`
	ID      int      `xml:"id,attr"`
	Name    string   `xml:"name"`
}

func (s Sample02) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return errors.New("Forced error when marshalling a value of type Sample02.")
}

var sample001 = Sample00{
	XMLName: xml.Name{
		Space: "http://bridgevine.com/ngdc/test",
		Local: "Sample00",
	},
	ID:   101,
	Name: "John Doe",
}

var sample002 = Sample00{
	XMLName: xml.Name{
		Space: "http://bridgevine.com/ngdc/test",
		Local: "Sample00",
	},
	ID:   101,
	Name: "John Doe",
}

var sample011 = Sample01{
	XMLName: xml.Name{
		Space: "http://bridgevine.com/ngdc/test",
		Local: "Sample01",
	},
	ID:   201,
	Name: "Jane Doe",
}

var sample012 = Sample01{
	XMLName: xml.Name{
		Space: "http://bridgevine.com/ngdc/test",
		Local: "Sample01",
	},
	ID:   201,
	Name: "Jane Doe",
}

var fltDetails, _ = xml.Marshal([]interface{}{sample011, sample012})

var fault11WoD = soap.Fault11{
	XMLName: xml.Name{
		Space: "http://schemas.xmlsoap.org/soap/envelope/",
		Local: "Fault",
	},
	Code:   "0001",
	String: "Description For 0001",
	Actor:  "Billing Department",
}

var fault11WD = soap.Fault11{
	XMLName: fault11WoD.XMLName,
	Code:    fault11WoD.Code,
	String:  fault11WoD.String,
	Actor:   fault11WoD.Actor,
	Detail: &soap.FaultDetail{
		Items: fltDetails,
	},
}

var fault12WoD = soap.Fault12{
	XMLName: xml.Name{
		Space: "http://www.w3.org/2003/05/soap-envelope",
		Local: "Fault",
	},
	Code: soap.Code{Value: "0001"},
	Reason: soap.Reason{
		Items: []soap.Text{
			soap.Text{Language: "en", Value: "Description For 0001"},
		},
	},
	Node: "Billing Node",
	Role: "Billing Department",
}

var fault12WD = soap.Fault12{
	XMLName: fault12WoD.XMLName,
	Code:    fault12WoD.Code,
	Node:    fault12WoD.Node,
	Role:    fault12WoD.Role,
	Detail: &soap.FaultDetail{
		Items: fltDetails,
	},
}

var soapHeaders = []interface{}{
	&soap.MessageID{
		XMLName: xml.Name{
			Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing",
			Local: "MessageID",
		},
		ID:    "messageid-id-0001",
		Value: "this is the message id",
	},
	&soap.Action{
		XMLName: xml.Name{
			Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing",
			Local: "Action",
		},
		ID:    "soap-header-id-0001",
		Value: "soap header action test",
	},
	&soap.To{
		XMLName: xml.Name{
			Space: "http://schemas.xmlsoap.org/ws/2004/08/addressing",
			Local: "To",
		},
		Address: "recipient address",
	},
}
