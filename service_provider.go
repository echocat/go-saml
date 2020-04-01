package saml

import (
	"context"
	"net/url"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// NameIDFormat is the format of the id
type NameIDFormat string

// Element returns an XML element representation of n.
func (n NameIDFormat) Element() *etree.Element {
	el := etree.NewElement("")
	el.SetText(string(n))
	return el
}

// Name ID formats
//noinspection GoUnusedConst
const (
	UnspecifiedNameIDFormat  NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	TransientNameIDFormat    NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	EmailAddressNameIDFormat NameIDFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	PersistentNameIDFormat   NameIDFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// SignatureVerifier verifies a signature
//
// Can be implemented in order to override DefaultServiceProvider's default
// way of verifying signatures.
type SignatureVerifier interface {
	VerifySignature(validationContext *dsig.ValidationContext, el *etree.Element) error
}

// DefaultServiceProvider implements SAML Service provider.
//
// In SAML, service providers delegate responsibility for identifying
// clients to an identity provider. If you are writing an application
// that uses passwords (or whatever) stored somewhere else, then you
// are service provider.
//
// See the example directory for an example of a web application using
// the service provider interface.
type ServiceProvider interface {
	// GetEntityID is optional - if not specified then MetadataURL will be used
	GetEntityID(ctx context.Context) (string, error)

	// GetCertificatePair with its private key to sign requests
	GetCertificatePair(ctx context.Context) (CertificatePair, error)

	// GetNameIDFormat
	GetNameIDFormat(ctx context.Context) (string, error)

	// GetSLOBindingLocation returns URL for the IDP's Single Log Out Service binding
	// of the specified type (HTTPRedirectBinding or HTTPPostBinding)
	GetSLOBindingLocation(binding string) string

	// GetSSOBindingLocation returns URL for the IDP's Single Sign On Service binding
	// of the specified type (HTTPRedirectBinding or HTTPPostBinding)
	GetSSOBindingLocation(binding string) string

	// Metadata returns the service provider metadata
	GetIDPMetadata(context.Context) (*EntityDescriptor, error)

	// GetMetadataURL is the full URL to the metadata endpoint on this host,
	// i.e. https://example.com/saml/metadata
	GetMetadataURL(ctx context.Context) (url.URL, error)

	// GetAcsURL is the full URL to the SAML Assertion Customer Service endpoint
	// on this host, i.e. https://example.com/saml/acs
	GetAcsURL(ctx context.Context) (url.URL, error)

	// GetSloURL is the full URL to the SAML Single Logout endpoint on this host.
	// i.e. https://example.com/saml/slo
	GetSloURL(ctx context.Context) (url.URL, error)

	// GetMetadataValidDuration is a duration used to calculate validUntil
	// attribute in the metadata endpoint
	GetMetadataValidDuration(context.Context) (time.Duration, error)

	// GetForceAuthn
	GetForceAuthn(ctx context.Context) (*bool, error)

	// GetAllowIDPInitiated
	GetAllowIDPInitiated(ctx context.Context) (bool, error)

	// GetSignatureVerifier, if non-nil, allows you to implement an alternative way
	// to verify signatures.
	GetSignatureVerifier(ctx context.Context) (SignatureVerifier, error)
}

// MaxIssueDelay is the longest allowed time between when a SAML assertion is
// issued by the IDP and the time it is received by ParseResponse. This is used
// to prevent old responses from being replayed (while allowing for some clock
// drift between the SP and IDP).
var MaxIssueDelay = time.Second * 90

// MaxClockSkew allows for leeway for clock skew between the IDP and SP when
// validating assertions. It defaults to 180 seconds (matches shibboleth).
var MaxClockSkew = time.Second * 180

// DefaultValidDuration is how long we assert that the SP metadata is valid.
const DefaultValidDuration = time.Hour * 24 * 2
