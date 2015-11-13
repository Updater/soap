package soap

import (
	"encoding/xml"
	"time"
)

// Constants that represent the different password types.
const (
	PasswordDigest string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
	PasswordText   string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
)

// Constants that represent the different encoding types.
const (
	Base64       string = "http://www.w3.org/2000/09/xmldsig#base64"
	Base64Binary string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
	HexBinary    string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#HexBinary"
	PlainText    string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Text"
)

// Constants that represent the different token types.
const (
	X509v1        string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v1"
	X509v3        string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
	X509PKIPathv1 string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1"
	PKCS7         string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#PKCS7"
)

// Constants that represent the different key identifier types.
const (
	X509SubjectKeyIdentifier string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier"
)

// Constants that represent the different canonicalization algorithms.
const (
	CanonicalXML10                    string = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	CanonicalXML10WithComments        string = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	CanonicalXML11                    string = "http://www.w3.org/2006/12/xml-c14n11"
	CanonicalXML11WithComments        string = "http://www.w3.org/2006/12/xml-c14n11#WithComments"
	ExclusiveCanonicalXML             string = "http://www.w3.org/2001/10/xml-exc-c14n#"
	ExclusiveCanonicalXMLWithComments string = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	MinimalCanonicalXML               string = "http://www.w3.org/2000/09/xmldsig#minimal"
)

// Constants that represent the different signature algorithms.
const (
	DSAwithSHA1     string = "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
	DSAwithSHA256   string = "http://www.w3.org/2009/xmldsig11#dsa-sha256"
	RSAwithSHA1     string = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	RSAwithSHA224   string = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"
	RSAwithSHA256   string = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	RSAwithSHA384   string = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	RSAwithSHA512   string = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	ECDSAwithSHA1   string = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
	ECDSAwithSHA224 string = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"
	ECDSAwithSHA256 string = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	ECDSAwithSHA384 string = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	ECDSAwithSHA512 string = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

// Constants that represent the different transforms types.
const (
	XSLT               string = "http://www.w3.org/TR/1999/REC-xslt-19991116"
	XPath              string = "http://www.w3.org/TR/1999/REC-xpath-19991116"
	XPathFilter20      string = "http://www.w3.org/2002/06/xmldsig-filter2"
	EnvelopedSignature string = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// Constants that represent the different message digest algorithms.
const (
	SHA1      string = "http://www.w3.org/2000/09/xmldsig#sha1"        // SHA1
	SHA224    string = "http://www.w3.org/2001/04/xmldsig-more#sha224" // SHA224
	SHA256    string = "http://www.w3.org/2001/04/xmlenc#sha256"       // SHA256
	SHA384    string = "http://www.w3.org/2001/04/xmlenc#sha384"       // SHA384
	SHA512    string = "http://www.w3.org/2001/04/xmlenc#sha512"       // SHA512
	RIPEMD160 string = "http://www.w3.org/2001/04/xmlenc#ripemd160"    // RIPEMD-160
)

// Constants that represent the different message authentication code (MAC) algorithms.
// HMAC stands for Hash-based Message Authentication Code.
const (
	HMACwithSHA1   string = "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
	HMACwithSHA224 string = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha224"
	HMACwithSHA256 string = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
	HMACwithSHA384 string = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"
	HMACwithSHA512 string = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
)

// Constants that represent the different types that
// can be used to identify the referent's type.
const (
	DSAKeyValueType        string = "http://www.w3.org/2000/09/xmldsig#DSAKeyValue"
	RSAKeyValueType        string = "http://www.w3.org/2000/09/xmldsig#RSAKeyValue"
	ECKeyValueType         string = "http://www.w3.org/2009/xmldsig11#ECKeyValue"
	DHKeyValueType         string = "http://www.w3.org/2001/04/xmlenc#DHKeyValue"
	X509DataType           string = "http://www.w3.org/2000/09/xmldsig#X509Data"
	PGPDataType            string = "http://www.w3.org/2000/09/xmldsig#PGPData"
	SPKIDataType           string = "http://www.w3.org/2000/09/xmldsig#SPKIData"
	MgmtDataType           string = "http://www.w3.org/2000/09/xmldsig#MgmtData"
	RawX509CertificateType string = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate"
	DEREncodedKeyValueType string = "http://www.w3.org/2009/xmldsig11#DEREncodedKeyValue"

	ObjectType              string = "http://www.w3.org/2000/09/xmldsig#Object"
	ManifestType            string = "http://www.w3.org/2000/09/xmldsig#Manifest"
	SignaturePropertiesType string = "http://www.w3.org/2000/09/xmldsig#SignatureProperties"

	EncryptedKeyType         string = "http://www.w3.org/2001/04/xmlenc#EncryptedKey"
	DerivedKeyType           string = "http://www.w3.org/2009/xmlenc11#DerivedKey"
	EncryptionPropertiesType string = "http://www.w3.org/2001/04/xmlenc#EncryptionProperties"
)

// Many deployments cannot assign a meaningful global URI to a given endpoint.
// To allow these "anonymous" endpoints to initiate message exchange patterns
// and receive replies, WS-Addressing defines the following well-known URI for
// use by endpoints that cannot have a stable, resolvable URI.
const AnonymousEndpointsURI string = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"

// Constants that represent the different encrypted data types.
const (
	ElementType string = "http://www.w3.org/2001/04/xmlenc#Element"
	ContentType string = "http://www.w3.org/2001/04/xmlenc#Content"
	EXIType     string = "http://www.w3.org/2009/xmlenc11#EXI" // EXI stands for Efficient XML Interchange.
)

// Constants that represent the different block encryption algorithms.
// CBC - Cipher-Block Chaining.
const (
	TripledesCbc string = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	AES128Cbc    string = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	AES192Cbc    string = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	AES256Cbc    string = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	AES128Gcm    string = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	AES192Gcm    string = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	AES256Gcm    string = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
)

// Constants that represent the different key derivation algorithms.
const (
	ConcatKDF string = "http://www.w3.org/2009/xmlenc11#ConcatKDF"
	PBKDF2    string = "http://www.w3.org/2009/xmlenc11#pbkdf2"
)

// Constants that represent the different key transport algorithms.
// Key Transport algorithms are public key encryption algorithms
// especially specified for encrypting and decrypting keys.
const (
	Rsa15        string = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	RsaOaepMGF1P string = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	RsaOaep      string = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)

// Constants that represent the different mask generation functions (MGF).
const (
	Mgf1SHA1   string = "http://www.w3.org/2009/xmlenc11#mgf1sha1"
	Mgf1SHA224 string = "http://www.w3.org/2009/xmlenc11#mgf1sha224"
	Mgf1SHA256 string = "http://www.w3.org/2009/xmlenc11#mgf1sha256"
	Mgf1SHA384 string = "http://www.w3.org/2009/xmlenc11#mgf1sha384"
	Mgf1SHA512 string = "http://www.w3.org/2009/xmlenc11#mgf1sha512"
)

// Constants that represent the different key agreement algorithms.
const (
	// DH represents the Diffie-Hellman Key Agreement
	// (Ephemeral-Static mode) with Legacy Key Derivation Function.
	DH string = "http://www.w3.org/2001/04/xmlenc#dh"

	// DhES represents the Diffie-Hellman Key Agreement
	// (Ephemeral-Static mode) with explicit Key Derivation Functions.
	DhES string = "http://www.w3.org/2009/xmlenc11#dh-es"

	// EcdhES represents the Elliptic Curve Diffie-Hellman
	// (Ephemeral-Static mode).
	EcdhES string = "http://www.w3.org/2009/xmlenc11#ECDH-ES"
)

// Constants that represent the different symmetric key wrap algorithms.
const (
	KwTRIPLEDES string = "http://www.w3.org/2001/04/xmlenc#kw-tripledes" // TRIPLEDES KeyWrap
	KwAES128    string = "http://www.w3.org/2001/04/xmlenc#kw-aes128"    // AES-128 KeyWrap
	KwAES192    string = "http://www.w3.org/2001/04/xmlenc#kw-aes192"    // AES-192 KeyWrap
	KwAES256    string = "http://www.w3.org/2001/04/xmlenc#kw-aes256"    // AES-256 KeyWrap
)

// =============================================================================
// Web Services Security Utility (WSU)
// =============================================================================

// Timestamp allows Timestamps to be applied anywhere element wildcards are
// present, including as a SOAP header.
type Timestamp struct {
	XMLName xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Timestamp"`
	ID      string   `xml:"Id,attr,omitempty"`
	Created *Created `xml:",omitempty"`
	Expires *Expires `xml:",omitempty"`
}

// Created models a timestamp used to indicate the creation time.
type Created struct {
	XMLName xml.Name  `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Created"`
	Value   time.Time `xml:",chardata"`
}

// Expires models a timestamp used to indicate the expiration time.
type Expires struct {
	XMLName xml.Name  `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Expires"`
	Value   time.Time `xml:",chardata"`
}

// ==================================================================================
// Web Services Security (WSS or WSSE)	[https://www.oasis-open.org/committees/wss/]
// ==================================================================================
/*

For details about OASIS Web Services Security (WSS), please refer to

	https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=wss

		Web Services Security: SOAP Message Security 1.1 (https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf)
		Web Services Security: SOAP Message Security 1.0 (http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0.pdf)

Some namespaces used in Web Services Security (WSS):

	soap11 	http://schemas.xmlsoap.org/soap/envelope/
	soap12 	http://www.w3.org/2003/05/soap-envelope
	wsse 	http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd
	wsse11 	http://docs.oasis-open.org/wss/oasis-wsswssecurity-secext-1.1.xsd
	wsu 	http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd
	xenc	http://www.w3.org/2001/04/xmlenc#
	ds		http://www.w3.org/2000/09/xmldsig#
	dsig11	http://www.w3.org/2009/xmldsig11#

Key Derivation

A key derived from a password may be used either in the calculation of a Message
Authentication Code (MAC) or as a symmetric key for encryption. When used in a MAC,
the key length will always be 160 bits. When used for encryption, an encryption
algorithm MUST NOT be used which requires a key of length greater than 160 bits.
A sufficient number of the high order bits of the key will be used for encryption.
Unneeded low order bits will be discarded. For example, if the AES-128 algorithm
is used, the high order 128 bits will be used and the low order 32 bits will be
discarded from the derived 160 bit value.

The <wsse11:Salt> element is constructed as follows. The high order 8 bits of the
Salt will have the value of 01 if the key is to be used in a MAC and 02 if the key
is to be used for encryption. The remaining 120 low order bits of the Salt should
be a random value.

The key is derived as follows. The password (which is UTF-8 encoded) and Salt are
concatenated in that order. Only the actual octets of the password are used, it
is not padded or zero terminated. This value is hashed using the SHA1 algorithm.
The result of this operation is also hashed using SHA1. This process is repeated
until the total number of hash operations equals the Iteration count.

In other words: K1 = SHA1(password + Salt)
				K2 = SHA1(K1)
				...
				Kn = SHA1(Kn-1)

Where + means concatenation and n is the iteration count.

The resulting 160 bit value is used in a MAC function or truncated to the
appropriate length for encryption.

*/

// SecurityHeader models a SOAP header block that provides a mechanism for
// attaching security-related information targeted at a specific recipient.
type SecurityHeader struct {
	XMLName xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Security"`

	// MustUnderstand is used to indicate whether a header block (or entry) is
	// mandatory or optional for the recipient to process. Under SOAP 1.1 the
	// value of the mustUnderstand attribute is either "1" or "0". The absence
	// of the mustUnderstand attribute is semantically equivalent to its presence
	// with the value "0". Under SOAP 1.2 the value of the mustUnderstand attribute
	// is either "true", "1", "false" or "0". The absence of the mustUnderstand
	// attribute is semantically equivalent to its presence with the value "false".
	MustUnderstand string `xml:"mustUnderstand,attr,omitempty"`

	// Actor allows a specific SOAP 1.1 actor to be identified. This attribute is
	// optional; however, no two header blocks may omit an actor or specify the
	// same actor.
	Actor string `xml:"actor,attr,omitempty"`

	// Role allows a specific SOAP 1.2 role to be identified. This attribute
	// is optional; however, no two header blocks may omit a role or specify
	// the same role.
	Role                string               `xml:"role,attr,omitempty"`
	Timestamp           *Timestamp           `xml:"Timestamp,omitempty"`
	BinarySecurityToken *BinarySecurityToken `xml:"BinarySecurityToken,omitempty"`
	UsernameToken       *UsernameToken       `xml:"UsernameToken,omitempty"`
	Signatures          []Signature          `xml:"Signature,omitempty"`

	// Items is an extensibility mechanism to allow different (extensible) types
	// of security information, based on a schema, to be passed. It could be
	// possible to remove all the previous references to Timestamp,
	// BinarySecurityToken, UsernameToken and Signature and just append the
	// needed elements to the Items slice.
	Items []interface{} `xml:",omitempty"`
}

// BinarySecurityToken defines a security token that is binary encoded
// (e.g. X.509 certificates and Kerberos [KERBEROS] tickets).
type BinarySecurityToken struct {
	XMLName xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd BinarySecurityToken"`

	// ID is an optional string label for this security token.
	ID string `xml:"Id,attr,omitempty"`

	// The EncodingType indicates, using a URI, the encoding format of the
	// binary data (e.g., base64 encoded).
	EncodingType string `xml:"EncodingType,attr"`

	// The ValueType indicates the "value space" of the encoded binary data
	// (e.g. an X.509 certificate).
	ValueType string `xml:"ValueType,attr"`

	// The Value represents binary-encoded security token.
	Value string `xml:",chardata"`
}

// SecurityTokenReference represents a reference to an X.509 token type in signature
// or encryption elements. A SecurityTokenReference MAY reference an X.509 token
// type by one of the following means:
//
//		- Reference to a Binary Security Token.
//		  The <wsse:SecurityTokenReference> element contains a <wsse:Reference>
//        element that references a local <wsse:BinarySecurityToken> element or
//        a remote data source that contains the token data itself.
//
//		- Reference to a Subject Key Identifier.
//		  The <wsse:SecurityTokenReference> element contains a <wsse:KeyIdentifier>
//        element that specifies the token data by means of a X.509
//        SubjectKeyIdentifier reference. A subject key identifier may only be
//        used to reference an X.509v3 certificate.
//
//		- Reference to an Issuer and Serial Number.
//		  The <wsse:SecurityTokenReference> element contains a <ds:X509Data>
//        element that contains a <ds:X509IssuerSerial> element that uniquely
//        identifies an end entity certificate by its X.509 Issuer and Serial Number.
type SecurityTokenReference struct {
	XMLName       xml.Name       `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd SecurityTokenReference"`
	ID            string         `xml:"Id,attr,omitempty"`
	Usage         string         `xml:"Usage,attr,omitempty"`
	TokenType     string         `xml:"TokenType,attr,omitempty"`
	Reference     *WSSEReference `xml:"Reference,omitempty"`
	KeyIdentifier *KeyIdentifier `xml:"KeyIdentifier,omitempty"`
	Embedded      *Embedded      `xml:"Embedded,omitempty"`
	X509Data      *X509Data      `xml:"X509Data,,omitempty"`

	// Items is an extensibility mechanism to allow different (extensible)
	// types of security information, based on a schema, to be passed.
	Items []interface{} `xml:",omitempty"`
}

// WSSEReference represents a reference to an external security token.
type WSSEReference struct {
	XMLName xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Reference"`
	ID      string   `xml:"Id,attr,omitempty"`
	URI     string   `xml:"URI,attr,omitempty"`

	// ValueType identifies the type of the referenced security token. In version
	// 1.1 of the WSS specification the use of this attribute to identify the type
	// of the referenced security token is deprecated. Profiles which require or
	// recommend the use of this attribute to identify the type of the referenced
	// security token SHOULD evolve to require or recommend the use of the
	// wsse:SecurityTokenReference/@wsse11:TokenType attribute to identify the
	// type of the referenced token.
	ValueType string `xml:"ValueType,attr,omitempty"`

	// Items is an extensibility mechanism to allow different (extensible) types
	// of security information, based on a schema, to be passed.
	Items []interface{} `xml:",omitempty"`
}

// KeyIdentifier represents a reference to an X.509v3 certificate by means of
// a reference to its X.509 SubjectKeyIdentifier attribute.
type KeyIdentifier struct {
	ID string `xml:"Id,attr,omitempty"`

	// The ValueType indicates  the type of KeyIdentifier being used.
	ValueType string `xml:"ValueType,attr,omitempty"`

	// The EncodingType indicates, using a URI, the encoding format of
	// the binary data (e.g., base64 encoded).
	EncodingType string `xml:"EncodingType,attr,omitempty"`

	// The Value represents binary-encoded key identifier.
	Value string `xml:",chardata"`
}

// Embedded represents a reference to an embedded security token.
type Embedded struct {
	ID        string `xml:"Id,attr,omitempty"`
	ValueType string `xml:"ValueType,attr,omitempty"`

	// Items is an extensibility mechanism to allow any security token,
	// based on schemas, to be embedded.
	Items []interface{} `xml:",omitempty"`
}

// UsernameToken models an optional element that can be included in the <Security>
// header block and is used to represent a claimed identity, it is an element
// introduced as a way of providing a username.
type UsernameToken struct {
	XMLName xml.Name `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd UsernameToken"`

	// ID is an optional string label for this security token.
	ID string `xml:"Id,attr,omitempty"`

	Username string    `xml:"Username"`
	Password *Password `xml:"Password,omitempty"`
	Nonce    *Nonce    `xml:"Nonce,omitempty"`

	// Created models an optional element in a UsernameToken element and specifies
	// a timestamp used to indicate the creation time, it also provides a countermeasure
	// for replay attacks.
	//
	// If either or both of <wsse:Nonce> and <wsu:Created> are present they MUST be
	// included in the digest value as follows:
	//
	// Password_Digest = Base64(SHA-1(nonce + created + password ))
	//
	// That is, concatenate the nonce, creation timestamp, and the password (or
	// shared secret or password equivalent), digest the combination using the
	// SHA-1 hash algorithm, then include the Base64 encoding of that result as
	// the password (digest). This helps obscure the password and offers a basis
	// for preventing replay attacks.
	Created *Created `xml:"Created,omitempty"`

	// Salt is a required element in a UsernameToken element to enable derivation
	// of a key from a password. The <wsse11:Salt> and <wsse11:Iteration>  are not
	// secret and MUST be conveyed in the UsernameToken when key derivation is used.
	// When key derivation is used the password MUST NOT be included in the
	// UsernameToken. The receiver will use its knowledge of the password to derive
	// the same key as the sender. The Salt element is combined with the password
	// and its value is a 128 bit number serilized as xs:base64Binary.
	Salt string `xml:"http://docs.oasis-open.org/wss/oasis-wsswssecurity-secext-1.1.xsd Salt,omitempty"`

	// Iteration indicates the number of times the hashing operation is repeated
	// when deriving the key and it is expressed as a xs:unsignedInteger value. If
	// it is not present, a value of 1000 is used for the iteration count.
	Iteration uint `xml:"http://docs.oasis-open.org/wss/oasis-wsswssecurity-secext-1.1.xsd Iteration,omitempty"`
}

// Password models an optional element in a UsernameToken element and provides
// password information (or equivalent, such as a hash).
type Password struct {
	Type  string `xml:"Type,attr,omitempty"`
	Value string `xml:",chardata"`
}

// Nonce models an optional element in a UsernameToken element and provides a
// countermeasure for replay attacks. A nonce is a random value that the sender
// creates to include in each UsernameToken that it sends.
//
// If either or both of <wsse:Nonce> and <wsu:Created> are present they MUST be
// included in the digest value as follows:
//
// Password_Digest = Base64(SHA-1(nonce + created + password ))
//
// That is, concatenate the nonce, creation timestamp, and the password (or
// shared secret or password equivalent), digest the combination using the SHA-1
// hash algorithm, then include the Base64 encoding of that result as the password
// (digest). This helps obscure the password and offers a basis for preventing
// replay attacks.
type Nonce struct {
	EncodingType string `xml:"EncodingType,attr,omitempty"`
	Value        string `xml:",chardata"`
}

// ===================================================================================================
// XML Signature (DS)	[http://www.w3.org/TR/xmldsig-core/] and [http://www.w3.org/TR/xmldsig-core1/]
// ===================================================================================================

// Signature models the signature element (root element) of an XML Signature.
// Specifications can be found at http://www.w3.org/TR/xmldsig-core/#sec-Signature.
type Signature struct {
	XMLName    xml.Name   `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	ID         string     `xml:"Id,attr,omitempty"`
	SignedInfo SignedInfo `xml:"SignedInfo"`

	// The SignatureValue contains the actual value of the digital signature; it
	// is always encoded using Base64.
	SignatureValue string `xml:"SignatureValue"`

	KeyInfo *KeyInfo `xml:"KeyInfo,omitempty"`
	Objects []Object `xml:"Object,omitempty"`
}

// SignedInfo contains or references the signed data and specifies what algorithms are used.
type SignedInfo struct {
	ID                     string                 `xml:"Id,attr,omitempty"`
	CanonicalizationMethod CanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        SignatureMethod        `xml:"SignatureMethod"`
	References             []DSReference          `xml:"Reference"`
}

// CanonicalizationMethod represents the canonicalization algorithm applied to
// the SignedInfo element prior to performing signature calculations.
type CanonicalizationMethod struct {
	Algorithm string        `xml:"Algorithm,attr"`
	Items     []interface{} `xml:",omitempty"`
}

// SignatureMethod represents the algorithm used for signature generation and validation.
type SignatureMethod struct {
	Algorithm        string        `xml:"Algorithm,attr"`
	HMACOutputLength int           `xml:"HMACOutputLength,omitempty"`
	Items            []interface{} `xml:",omitempty"`
}

// DSReference is an element that may occur one or more times.
type DSReference struct {
	ID string `xml:"Id,attr,omitempty"`

	// URI identifies the data object to be signed. This attribute may be omitted
	// on at most one Reference in a Signature. This attribute may be omitted
	// from at most one Reference in any particular SignedInfo, or Manifest.
	URI string `xml:"URI,attr,omitempty"`

	// Type contains information about the type of object being signed.
	// The Type attribute applies to the item being pointed at, not its contents.
	Type string `xml:"Type,attr,omitempty"`

	Transforms   *Transforms  `xml:"Transforms,omitempty"`
	DigestMethod DigestMethod `xml:"DigestMethod"`

	// DigestValue contains the encoded value of the digest. The digest is always
	// encoded using Base64.
	DigestValue string `xml:"DigestValue"`
}

// Transforms is a container for an ordered list of values of type Transform,
// these describe how the signer obtained the data object that was digested.
// The output of each Transform serves as input to the next Transform.
type Transforms struct {
	Items []Transform `xml:",omitempty"`
}

// Transform represents a transformation to be performed to a reference.
type Transform struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`

	// Algorithm specifies the name of the algorithm to be performed.
	Algorithm string `xml:"Algorithm,attr"`

	// Parameters provides additional data to govern the algorithm's processing
	// of the transform input.
	Parameters []interface{} `xml:",omitempty"`
}

// DigestMethod identifies the digest algorithm to be applied to the signed object.
type DigestMethod struct {
	XMLName   xml.Name      `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	Algorithm string        `xml:"Algorithm,attr"`
	Items     []interface{} `xml:",omitempty"`
}

// KeyInfo enables the recipient(s) to obtain the key needed to validate the signature.
// KeyInfo may contain keys, names, certificates and other public key management
// information, such as in-band key distribution or key agreement data.
type KeyInfo struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	ID      string   `xml:"Id,attr,omitempty"`

	// KeyName contains a string value (in which white space is significant) which
	// may be used by the signer to communicate a key identifier to the recipient.
	// Typically, KeyName contains an identifier related to the key pair used to
	// sign the message, but it may contain other protocol-related information
	// that indirectly identifies a key pair.
	KeyName string `xml:"KeyName,omitempty"`

	KeyValue               *KeyValue               `xml:"KeyValue,omitempty"`
	RetrievalMethod        *RetrievalMethod        `xml:"RetrievalMethod,omitempty"`
	X509Data               []X509Data              `xml:"X509Data,omitempty"`
	PGPData                *PGPData                `xml:"PGPData,omitempty"`
	SPKIData               *SPKIData               `xml:"SPKIData,omitempty"`
	MgmtData               string                  `xml:"MgmtData,omitempty"`
	SecurityTokenReference *SecurityTokenReference `xml:",omitempty"`
	DEREncodedKeyValue     *DEREncodedKeyValue     `xml:",omitempty"`
	KeyInfoReference       *KeyInfoReference       `xml:",omitempty"`
	EncryptedKey           *EncryptedKey           `xml:",omitempty"`
	DerivedKey             *DerivedKey             `xml:",omitempty"`
	AgreementMethod        *AgreementMethod        `xml:",omitempty"`

	// Items is an extensibility mechanism to allow different (extensible) types,
	// based on a schema, to be passed.
	Items []interface{} `xml:",omitempty"`
}

// KeyValue represents a single public key that may be useful in validating the signature.
type KeyValue struct {
	DSAKeyValue *DSAKeyValue `xml:"DSAKeyValue,omitempty"`
	RSAKeyValue *RSAKeyValue `xml:"RSAKeyValue,omitempty"`
	ECKeyValue  *ECKeyValue  `xml:",omitempty"`
	DHKeyValue  *DHKeyValue  `xml:",omitempty"`

	// Items is an extensibility mechanism to allow different (extensible) types,
	// based on a schema, to be passed.
	Items []interface{} `xml:",omitempty"`
}

// DSAKeyValue represents a DSA public key.
type DSAKeyValue struct {
	// P is a prime modulus meeting the [DSS] requirements.
	// P and Q are optional but P and Q must either both appear or both be absent.
	P string `xml:"P,omitempty"`

	// Q is an integer in the range 2**159 < Q < 2**160 which is a prime divisor of P-1.
	// P and Q are optional but P and Q must either both appear or both be absent.
	Q string `xml:"Q,omitempty"`

	// G is an integer with certain properties with respect to P and Q.
	G string `xml:"G,omitempty"`

	// Y is equivalent to: G**X mod P (where X is part of the private key and not made public).
	Y string `xml:"Y"`

	// J is equivalent to: (P - 1) / Q.
	J string `xml:"J,omitempty"`

	// Seed is a DSA prime generation seed.
	// Seed and PGenCounter are optional but Seed and PGenCounter must either both
	// appear or both be absent.
	Seed string `xml:"seed,omitempty"`

	// PGenCounter is a DSA prime generation counter.
	// Seed and PGenCounter are optional but Seed and PGenCounter must either both
	// appear or both be absent.
	PGenCounter string `xml:"pgenCounter,omitempty"`
}

// RSAKeyValue represents
type RSAKeyValue struct {
	Modulus  string `xml:"Modulus"`
	Exponent string `xml:"Exponent"`
}

// ECKeyValue represents an EC public key.
type ECKeyValue struct {
	XMLName      xml.Name      `xml:"http://www.w3.org/2009/xmldsig11# ECKeyValue"`
	ID           string        `xml:"Id,attr,omitempty"`
	ECParameters *ECParameters `xml:"ECParameters,omitempty"`
	NamedCurve   *NamedCurve   `xml:"NamedCurve,omitempty"`
	PublicKey    string        `xml:"PublicKey"`
}

// ECParameters TODO.
type ECParameters struct {
	FieldID FieldID `xml:"FieldID"`
	Curve   Curve   `xml:"Curve"`

	// Base specifies the base point P on the elliptic curve.
	Base string `xml:"Base"`

	// Order specifies the order n of the base point and is encoded as a positiveInteger.
	Order string `xml:"Order"`

	// Cofactor is an optional element that specifies the integer h = #E(Fq)/n.
	CoFactor int `xml:"CoFactor,omitempty"`

	ValidationData *ECValidationData `xml:"ValidationData,omitempty"`
}

// FieldID identifies the finite field over which the elliptic curve is defined.
type FieldID struct {
	Prime *PrimeFieldParamsType   `xml:"Prime,omitempty"`
	TnB   *TnBFieldParamsType     `xml:"TnB,omitempty"`
	PnB   *PnBFieldParamsType     `xml:"PnB,omitempty"`
	GnB   *CharTwoFieldParamsType `xml:"GnB,omitempty"`

	// Items is an extensibility mechanism to allow different (extensible) types,
	// based on a schema, to be passed.
	Items []interface{} `xml:",omitempty"`
}

// PrimeFieldParamsType represents a Prime field.
type PrimeFieldParamsType struct {
	// P represents the field size in bits. It is encoded as a positiveInteger.
	P string `xml:"P"`
}

// CharTwoFieldParamsType TODO.
type CharTwoFieldParamsType struct {
	M int `xml:"M"`
}

// TnBFieldParamsType TODO.
type TnBFieldParamsType struct {
	CharTwoFieldParamsType
	K int `xml:"K"`
}

// PnBFieldParamsType TODO.
type PnBFieldParamsType struct {
	CharTwoFieldParamsType
	K1 int `xml:"K1"`
	K2 int `xml:"K2"`
	K3 int `xml:"K3"`
}

// Curve specifies the coefficients a and b of the elliptic curve E.
type Curve struct {
	A string `xml:"A"`
	B string `xml:"B"`
}

// ECValidationData is an optional element that specifies the hash algorithm used
// to generate the elliptic curve E and the base point G verifiably at random.
// It also specifies the seed that was used to generate the curve and the base point.
type ECValidationData struct {
	Seed          string `xml:"seed"`
	HashAlgorithm string `xml:"hashAlgorithm,attr"`
}

// NamedCurve TODO.
type NamedCurve struct {
	URI string `xml:"URI,attr"`
}

// RetrievalMethod is used to convey a reference to KeyInfo information that is
// stored at another location.
type RetrievalMethod struct {
	URI        string      `xml:"URI,attr"`
	Type       string      `xml:"Type,attr,omitempty"`
	Transforms *Transforms `xml:"Transforms,omitempty"`
}

// X509Data TODO.
type X509Data struct {
	XMLName           xml.Name           `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509IssuerSerials []X509IssuerSerial `xml:"X509IssuerSerial,omitempty"`
	X509SKIs          []string           `xml:"X509SKI,omitempty"`
	X509SubjectNames  []string           `xml:"X509SubjectName,omitempty"`
	X509Certificates  []string           `xml:"X509Certificate,omitempty"`
	X509CRLs          []string           `xml:"X509CRL,omitempty"`
	X509Digests       []X509Digest       `xml:"X509Digest,omitempty"`
	Items             []interface{}      `xml:",omitempty"`
}

// X509IssuerSerial TODO.
type X509IssuerSerial struct {
	X509IssuerName   string `xml:"X509IssuerName"`
	X509SerialNumber int    `xml:"X509SerialNumber"`
}

// X509Digest represents a base64-encoded digest of a certificate.
// The X509IssuerSerial element has been deprecated in favor of the
// newly-introduced dsig11:X509Digest element.
type X509Digest struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2009/xmldsig11# X509Digest"`
	Algorithm string   `xml:"Algorithm,attr"`
	Value     string   `xml:",chardata"`
}

// PGPData is used to convey information related to PGP public key pairs and
// signatures on such keys.
type PGPData struct {
	// PGPKeyID is a Base64Binary sequence containing a standard PGP public key
	// identifier as defined in [PGP, section 11.2].
	PGPKeyID string `xml:"PGPKeyID,omitempty"`

	// PGPKeyPacket contains a base64-encoded Key Material Packet as defined in
	// [PGP, section 5.5].
	PGPKeyPacket string `xml:"PGPKeyPacket,omitempty"`

	// Items represents optional elements from an external namespace.
	Items []interface{} `xml:",omitempty"`
}

// SPKIData is used to convey information related to SPKI public key pairs,
// certificates and other SPKI data.
type SPKIData struct {
	// A SPKISexp is the Base64 encoding of a SPKI canonical S-expression.
	SPKISexps []string `xml:"SPKISexp,omitempty"`

	// Items represents optional elements from an external namespace within SPKIData.
	Items []interface{} `xml:",omitempty"`
}

// DEREncodedKeyValue was added to XML Signature 1.1 in order to support certain
// interoperability scenarios where at least one of signer and/or verifier are
// not able to serialize keys in the XML formats accepted by the KeyValue Element.
type DEREncodedKeyValue struct {
	XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# DEREncodedKeyValue"`
	ID      string   `xml:"Id,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// KeyInfoReference conveys a reference to a KeyInfo element at another
// location in the same or different document. The result of dereferencing
// a KeyInfoReference must be a KeyInfo element, or an XML document with
// a KeyInfo element as the root.
//
// The KeyInfoReference element is a desirable alternative to the use of
// RetrievalMethod when the data being referred to is a KeyInfo element
// and the use of RetrievalMethod would require one or more Transform
// child elements, which introduce security risk and implementation challenges.
type KeyInfoReference struct {
	XMLName xml.Name `xml:"http://www.w3.org/2009/xmldsig11# KeyInfoReference"`
	ID      string   `xml:"Id,attr,omitempty"`
	URI     string   `xml:"URI,attr"`
}

// Object represents a container that may contain any data.
type Object struct {
	ID       string        `xml:"Id,attr,omitempty"`
	MimeType string        `xml:"MimeType,attr,omitempty"`
	Encoding string        `xml:"Encoding,attr,omitempty"`
	Items    []interface{} `xml:",omitempty"`
}

// Manifest represents a list of References.
type Manifest struct {
	ID         string        `xml:"Id,attr,omitempty"`
	References []DSReference `xml:"Reference,omitempty"`
}

// SignatureProperties represents a container for values of the type SignatureProperty.
type SignatureProperties struct {
	ID         string              `xml:"Id,attr,omitempty"`
	Properties []SignatureProperty `xml:"SignatureProperty,omitempty"`
}

// SignatureProperty represents an additional information item concerning the
// generation of the signature(s) (i.e., date/time stamp or the serial number
// of cryptographic hardware used in signature generation).
type SignatureProperty struct {
	ID     string        `xml:"Id,attr,omitempty"`
	Target string        `xml:"Target,attr"`
	Items  []interface{} `xml:",omitempty"`
}

// =====================================================================================================
// XML Encryption (XENC)	[http://www.w3.org/TR/xmlenc-core/] and [http://www.w3.org/TR/xmlenc-core1/]
// =====================================================================================================

// Encrypted is the abstract type from which EncryptedData and EncryptedKey are derived.
type Encrypted struct {
	ID                   string                `xml:"Id,attr,omitempty"`
	Type                 string                `xml:"Type,attr,omitempty"`
	MimeType             string                `xml:"MimeType,attr,omitempty"`
	Encoding             string                `xml:"Encoding,attr,omitempty"`
	EncryptionMethod     *EncryptionMethod     `xml:"EncryptionMethod,omitempty"`
	KeyInfo              *KeyInfo              `xml:",omitempty"`
	CipherData           CipherData            `xml:"CipherData"`
	EncryptionProperties *EncryptionProperties `xml:"EncryptionProperties,omitempty"`
}

// EncryptionMethod describes the encryption algorithm applied to the cipher data.
type EncryptionMethod struct {
	Algorithm    string        `xml:"Algorithm,attr"`
	KeySize      int           `xml:"KeySize,omitempty"`
	OAEPparams   string        `xml:"OAEPparams,omitempty"`
	MGF          *MGF          `xml:",omitempty"`
	DigestMethod *DigestMethod `xml:",omitempty"`

	// Items is an extensibility mechanism to allow different (extensible) types,
	// based on a schema, to be passed.
	Items []interface{} `xml:",omitempty"`
}

// CipherData provides the encrypted data.
type CipherData struct {
	// CipherValue contains the encrypted octet sequence as base64 encoded text.
	CipherValue     string           `xml:"CipherValue,omitempty"`
	CipherReference *CipherReference `xml:"CipherReference,omitempty"`
}

// CipherReference identifies a source which, when processed, yields
// the encrypted octet sequence.
type CipherReference struct {
	URI        string      `xml:"URI,attr"`
	Transforms *Transforms `xml:"Transforms,omitempty"`
}

// EncryptionProperties is a container for EncryptionProperty values.
type EncryptionProperties struct {
	ID         string               `xml:"Id,attr,omitempty"`
	Properties []EncryptionProperty `xml:"EncryptionProperty,omitempty"`
}

// EncryptionProperty represents an additional information item concerning
// the generation of encrypted information.
type EncryptionProperty struct {
	ID     string        `xml:"Id,attr,omitempty"`
	Target string        `xml:"Target,attr,omitempty"`
	Items  []interface{} `xml:",omitempty"`
}

// EncryptedData element is the core element. Not only does its CipherData child
// contain the encrypted data, but it's also the element that replaces the
// encrypted element, or element content, or serves as the new document root.
type EncryptedData struct {
	Encrypted
	XMLName xml.Name `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedData"`
}

// EncryptedKey is used to transport encryption keys from the originator to
// a known recipient(s).
type EncryptedKey struct {
	Encrypted
	XMLName xml.Name `xml:"http://www.w3.org/2001/04/xmlenc# EncryptedKey"`

	// Recipient contains a hint as to which recipient this encrypted
	// key value is intended for. Its contents are application dependent.
	Recipient     string         `xml:"Recipient,attr,omitempty"`
	ReferenceList *ReferenceList `xml:"ReferenceList,omitempty"`

	// CarriedKeyName is an optional element for associating a user readable
	// name with the key value.
	CarriedKeyName string `xml:"CarriedKeyName,omitempty"`
}

// ReferenceList contains pointers to encrypted data and keys.
// ReferenceList is an element that contains pointers from a key value of
// an EncryptedKey or DerivedKey to items encrypted by that key value
// (EncryptedData or EncryptedKey elements).
type ReferenceList struct {
	DataReferences []XENCReference `xml:"DataReference,omitempty"`
	KeyReferences  []XENCReference `xml:"KeyReference,omitempty"`
}

// XENCReference represents a reference to an encrypted item.
type XENCReference struct {
	ID  string `xml:"Id,attr,omitempty"`
	URI string `xml:"URI,attr"`

	// Items is an extensibility mechanism to allow different (extensible) types,
	// based on a schema, to be passed.
	Items []interface{} `xml:",omitempty"`
}

// DerivedKey is used to transport information about a derived key
// from the originator to recipient(s).
type DerivedKey struct {
	XMLName xml.Name `xml:"http://www.w3.org/2009/xmlenc11# DerivedKey"`
	ID      string   `xml:"Id,attr,omitempty"`

	// Type can be used to further specify the type of the derived key if the
	// KeyDerivationMethod algorithm does not define an unambiguous encoding/representation.
	Type string `xml:"Type,attr,omitempty"`

	// Recipient contains a hint as to which recipient this derived key value is
	// intended for. Its contents are application dependent.
	Recipient           string               `xml:"Recipient,attr,omitempty"`
	KeyDerivationMethod *KeyDerivationMethod `xml:",omitempty"`
	ReferenceList       *ReferenceList       `xml:"ReferenceList,omitempty"`

	// DerivedKeyName identifies the derived key value.
	DerivedKeyName string `xml:"DerivedKeyName,omitempty"`

	// MasterKeyName associates a user readable name with the master key (or secret) value.
	MasterKeyName string `xml:"MasterKeyName,omitempty"`
}

// KeyDerivationMethod describes the key derivation algorithm applied to
// the master (underlying) key material.
type KeyDerivationMethod struct {
	XMLName         xml.Name         `xml:"http://www.w3.org/2009/xmlenc11# KeyDerivationMethod"`
	Algorithm       string           `xml:"Algorithm,attr"`
	ConcatKDFParams *ConcatKDFParams `xml:",omitempty"`
	PBKDF2Params    *PBKDF2Params    `xml:",omitempty"`

	// Items is an extensibility mechanism to allow different (extensible) types,
	// based on a schema, to be passed.
	Items []interface{} `xml:",omitempty"`
}

// ConcatKDFParams represents the several parameters that the ConcatKDF
// key derivation algorithm takes.
type ConcatKDFParams struct {
	XMLName      xml.Name `xml:"http://www.w3.org/2009/xmlenc11# ConcatKDFParams"`
	AlgorithmID  string   `xml:"AlgorithmID,attr,omitempty"`
	PartyUInfo   string   `xml:"PartyUInfo,attr,omitempty"`
	PartyVInfo   string   `xml:"PartyVInfo,attr,omitempty"`
	SuppPubInfo  string   `xml:"SuppPubInfo,attr,omitempty"`
	SuppPrivInfo string   `xml:"SuppPrivInfo,attr,omitempty"`

	// DigestMethod identifies the digest algorithm
	// used by the KDF (Key Derivation Function).
	DigestMethod DigestMethod
}

// PBKDF2Params represents the several parameters that
// the PBKDF2 key derivation algorithm takes.
type PBKDF2Params struct {
	XMLName        xml.Name            `xml:"http://www.w3.org/2009/xmlenc11# PBKDF2-params"`
	Salt           Salt                `xml:"Salt"`
	IterationCount int                 `xml:"IterationCount"`
	KeyLength      int                 `xml:"KeyLength"`
	PRFAlgorithm   AlgorithmIdentifier `xml:"PRF"`
}

// Salt models the Salt element inside the PBKDF2Params.
type Salt struct {
	Specified   string               `xml:"Specified,omitempty"`
	OtherSource *AlgorithmIdentifier `xml:"OtherSource,omitempty"`
}

// AlgorithmIdentifier represents an algorithm and its parameters.
type AlgorithmIdentifier struct {
	Algorithm string `xml:"Algorithm,attr"`

	// Parameters is an extensibility mechanism to allow
	// different parameter types, based on a schema, to be passed.
	Parameters []interface{} `xml:",omitempty"`
}

// MGF models the MGF element of type MGFType in the XML Encryption 1.1 Specifictions.
// MGF stands for Mask Generation Function.
type MGF struct {
	AlgorithmIdentifier
	XMLName xml.Name `xml:"http://www.w3.org/2009/xmlenc11# MGF"`
}

// AgreementMethod represents a Key Agreement algorithm for the derivation of a
// shared secret key based on a shared secret computed from certain types of
// compatible public keys from both the sender and the recipient.
type AgreementMethod struct {
	XMLName             xml.Name             `xml:"http://www.w3.org/2001/04/xmlenc# AgreementMethod"`
	Algorithm           string               `xml:"Algorithm,attr"`
	KANonce             string               `xml:"KA-Nonce,omitempty"`
	OriginatorKeyInfo   *KeyInfo             `xml:"OriginatorKeyInfo,omitempty"`
	RecipientKeyInfo    *KeyInfo             `xml:"RecipientKeyInfo,omitempty"`
	KeyDerivationMethod *KeyDerivationMethod `xml:",omitempty"`

	// Items is an extensibility mechanism to allow different types,
	// based on a schema, to be passed.
	Items []interface{} `xml:",omitempty"`
}

// DHKeyValue models a Diffie-Hellman Key Value.
type DHKeyValue struct {
	XMLName     xml.Name `xml:"http://www.w3.org/2001/04/xmlenc# DHKeyValue"`
	P           string   `xml:"P,omitempty"`
	Q           string   `xml:"Q,omitempty"`
	Generator   string   `xml:"Generator,omitempty"`
	Public      string   `xml:"Public"`
	Seed        string   `xml:"seed,omitempty"`
	PgenCounter string   `xml:"pgenCounter,omitempty"`
}

// ==============================================================================
// Web Services Addressing (WSA)	[http://www.w3.org/Submission/ws-addressing/]
// ==============================================================================

// EndpointReference models a web service endpoint reference.
// More details can be found at http://www.w3.org/Submission/ws-addressing/#_Toc77464317.
type EndpointReference struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing EndpointReference"`
	ID      string   `xml:"Id,attr,omitempty"`

	// Address is an URI that identifies the endpoint. This may be a network
	// address or a logical address.
	Address string `xml:"Address"`

	ReferenceProperties *ReferenceProperties `xml:"ReferenceProperties,omitempty"`
	ReferenceParameters *ReferenceParameters `xml:"ReferenceParameters,omitempty"`
	PortType            string               `xml:"PortType,omitempty"`
	ServiceName         *ServiceName         `xml:"ServiceName,omitempty"`
	Policy              *Policy              `xml:"Policy,omitempty"`

	// Items is an extensibility mechanism to allow additional elements to be specified.
	Items []interface{} `xml:",omitempty"`
}

// ReferenceProperties contains the elements that convey the [reference properties]
// of the reference. More details can be found at
// http://www.w3.org/Submission/ws-addressing/#_Toc77464319.
type ReferenceProperties struct {
	// Each item represents an individual [reference property].
	Items []interface{} `xml:",omitempty"`
}

// ReferenceParameters contains the elements that convey the [reference parameters]
// of the reference. More details can be found at
// http://www.w3.org/Submission/ws-addressing/#_Toc77464319.
type ReferenceParameters struct {
	// Each item represents an individual [reference parameter].
	Items []interface{} `xml:",omitempty"`
}

// ServiceName specifies the <wsdl:service> definition that contains a WSDL
// description of the endpoint being referenced. More details can be found at
// http://www.w3.org/Submission/ws-addressing/#_Toc77464319.
type ServiceName struct {
	// PortName specifies the name of the <wsdl:port> definition that corresponds
	// to the endpoint being referenced.
	PortName string `xml:"PortName,attr,omitempty"`
	Value    string `xml:",chardata"`
}

// Policy specifies a policy that is relevant to the interaction with the endpoint.
// More details can be found at http://www.w3.org/Submission/ws-addressing/#_Toc77464319.
type Policy struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2002/12/policy Policy"`
}

// MessageID conveys the [message id] property. This element MUST be present if
// wsa:ReplyTo or wsa:FaultTo is present.
type MessageID struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing MessageID"`
	ID      string   `xml:"Id,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// RelatesTo will typically be used on response messages to indicate that it is
// related to a previously-known message and to define that relationship. This
// element MUST be present if the message is a reply.
type RelatesTo struct {
	XMLName          xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing RelatesTo"`
	ID               string   `xml:"Id,attr,omitempty"`
	RelationshipType string   `xml:"RelationshipType,attr,omitempty"`

	// Value conveys the [message id] of the related message.
	Value string `xml:",chardata"`
}

// From provides the value for the [source endpoint] property.
type From struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing From"`
	ID      string   `xml:"Id,attr,omitempty"`
	Address string   `xml:"Address"`
}

// To provides the value for the [destination endpoint] property.
// To is nothing more than the target web service's URL. Typically, this URL
// is the same as the HTTP request's URL, but it is not required to be.
type To struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing To"`
	ID      string   `xml:"Id,attr,omitempty"`
	Address string   `xml:",chardata"`
}

// ReplyTo provides the value for the [reply endpoint] property.
// This element MUST be present if a reply is expected. If this element is present,
// wsa:MessageID MUST be present.
type ReplyTo struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing ReplyTo"`
	ID      string   `xml:"Id,attr,omitempty"`
	Address string   `xml:"Address"`
}

// FaultTo provides the value for the [fault endpoint] property. If this element
// is present, wsa:MessageID MUST be present. If the response to a message is a
// SOAP fault, the fault should be sent to the fault endpoint in the FaultTo element.
type FaultTo struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing FaultTo"`
	ID      string   `xml:"Id,attr,omitempty"`
	Address string   `xml:"Address"`
}

// Action represents the in-envelope version of the SOAP HTTP Action header.
type Action struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/ws/2004/08/addressing Action"`
	ID      string   `xml:"Id,attr,omitempty"`
	Value   string   `xml:",chardata"`
}
