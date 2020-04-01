package saml

import (
	"context"
	"net/url"
	"time"
)

type DefaultServiceProvider struct {
	// Entity ID is optional - if not specified then MetadataURL will be used
	EntityID string

	// CertificatePair with its private key to sign requests
	CertificatePair CertificatePair

	// MetadataURL is the full URL to the metadata endpoint on this host,
	// i.e. https://example.com/saml/metadata
	MetadataURL url.URL

	// AcsURL is the full URL to the SAML Assertion Customer Service endpoint
	// on this host, i.e. https://example.com/saml/acs
	AcsURL url.URL

	// SloURL is the full URL to the SAML Single Logout endpoint on this host.
	// i.e. https://example.com/saml/slo
	SloURL url.URL

	// IDPMetadata is the metadata from the identity provider.
	IDPMetadata *EntityDescriptor

	// AuthnNameIDFormat is the format used in the NameIDPolicy for
	// authentication requests
	AuthnNameIDFormat NameIDFormat

	// MetadataValidDuration is a duration used to calculate validUntil
	// attribute in the metadata endpoint
	MetadataValidDuration time.Duration

	// ForceAuthn allows you to force re-authentication of users even if the user
	// has a SSO session at the IdP.
	ForceAuthn *bool

	// AllowIdpInitiated
	AllowIDPInitiated bool

	// SignatureVerifier, if non-nil, allows you to implement an alternative way
	// to verify signatures.
	SignatureVerifier SignatureVerifier
}

// GetSSOBindingLocation returns URL for the IDP's Single Sign On Service binding
// of the specified type (HTTPRedirectBinding or HTTPPostBinding)
func (sp *DefaultServiceProvider) GetSSOBindingLocation(binding string) string {
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		for _, singleSignOnService := range idpSSODescriptor.SingleSignOnServices {
			if singleSignOnService.Binding == binding {
				return singleSignOnService.Location
			}
		}
	}
	return ""
}

// GetSLOBindingLocation returns URL for the IDP's Single Log Out Service binding
// of the specified type (HTTPRedirectBinding or HTTPPostBinding)
func (sp *DefaultServiceProvider) GetSLOBindingLocation(binding string) string {
	for _, idpSSODescriptor := range sp.IDPMetadata.IDPSSODescriptors {
		for _, singleLogoutService := range idpSSODescriptor.SingleLogoutServices {
			if singleLogoutService.Binding == binding {
				return singleLogoutService.Location
			}
		}
	}
	return ""
}

// GetNameIDFormat
func (sp *DefaultServiceProvider) GetNameIDFormat(context.Context) (string, error) {
	var nameIDFormat string
	switch sp.AuthnNameIDFormat {
	case "":
		// To maintain library back-compat, use "transient" if unset.
		nameIDFormat = string(TransientNameIDFormat)
	case UnspecifiedNameIDFormat:
		// Spec defines an empty value as "unspecified" so don't set one.
	default:
		nameIDFormat = string(sp.AuthnNameIDFormat)
	}
	return nameIDFormat, nil
}

// GetEntityID is optional - if not specified then MetadataURL will be used
func (sp *DefaultServiceProvider) GetEntityID(context.Context) (string, error) {
	return sp.EntityID, nil
}

// GetCertificatePair with its private key to sign requests
func (sp *DefaultServiceProvider) GetCertificatePair(context.Context) (CertificatePair, error) {
	return sp.CertificatePair, nil
}

// Metadata returns the service provider metadata
func (sp *DefaultServiceProvider) GetIDPMetadata(context.Context) (*EntityDescriptor, error) {
	return sp.IDPMetadata, nil
}

// GetMetadataURL is the full URL to the metadata endpoint on this host,
// i.e. https://example.com/saml/metadata
func (sp *DefaultServiceProvider) GetMetadataURL(context.Context) (url.URL, error) {
	return sp.MetadataURL, nil
}

// GetAcsURL is the full URL to the SAML Assertion Customer Service endpoint
// on this host, i.e. https://example.com/saml/acs
func (sp *DefaultServiceProvider) GetAcsURL(context.Context) (url.URL, error) {
	return sp.AcsURL, nil
}

// GetSloURL is the full URL to the SAML Single Logout endpoint on this host.
// i.e. https://example.com/saml/slo
func (sp *DefaultServiceProvider) GetSloURL(context.Context) (url.URL, error) {
	return sp.SloURL, nil
}

// GetMetadataValidDuration is a duration used to calculate validUntil
// attribute in the metadata endpoint
func (sp *DefaultServiceProvider) GetMetadataValidDuration(context.Context) (time.Duration, error) {
	return sp.MetadataValidDuration, nil
}

// GetForceAuthn
func (sp *DefaultServiceProvider) GetForceAuthn(context.Context) (*bool, error) {
	return sp.ForceAuthn, nil
}

// GetAllowIDPInitiated
func (sp *DefaultServiceProvider) GetAllowIDPInitiated(context.Context) (bool, error) {
	return sp.AllowIDPInitiated, nil
}

// GetSignatureVerifier, if non-nil, allows you to implement an alternative way
// to verify signatures.
func (sp *DefaultServiceProvider) GetSignatureVerifier(context.Context) (SignatureVerifier, error) {
	return sp.SignatureVerifier, nil
}

func firstSet(a, b string) string {
	if a == "" {
		return b
	}
	return a
}
