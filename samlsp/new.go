// Package samlsp provides helpers that can be used to protect web services using SAML.
package samlsp

import (
	"crypto"
	"crypto/x509"
	"github.com/echocat/go-saml"
	"net/url"
)

// Options represents the parameters for creating a new middleware
type Options struct {
	EntityID          string
	URL               url.URL
	ForceAuthn        bool
	Key               crypto.PrivateKey
	Certificate       *x509.Certificate
	Intermediates     []*x509.Certificate
	IDPMetadata       *saml.EntityDescriptor
	AllowIDPInitiated bool
}

func optionsToCertificatePair(opts Options) saml.CertificatePair {
	return saml.CertificatePair{
		Certificate:   opts.Certificate,
		Intermediates: opts.Intermediates,
		Key:           opts.Key,
	}
}
func optionsToJwtPatternProvider(opts Options) JWTPatternProvider {
	return JWTPatternProviderFor(JWTSessionPattern{
		SigningMethod:   defaultJWTSigningMethod,
		Audience:        opts.URL.String(),
		Issuer:          opts.URL.String(),
		MaxAge:          defaultSessionMaxAge,
		CertificatePair: optionsToCertificatePair(opts),
	})
}

// NewSessionCodec returns the default SessionCodec for the provided options,
// a JWTSessionCodec configured to issue signed tokens.
func NewSessionCodec(opts Options) (SessionCodec, error) {
	return &JWTSessionCodec{
		PatternProvider: optionsToJwtPatternProvider(opts),
	}, nil
}

// NewSessionProvider returns the default SessionProvider for the provided options,
// a CookieSessionProvider configured to store sessions in a cookie.
func NewSessionProvider(opts Options) (SessionProvider, error) {
	sessionCodec, err := NewSessionCodec(opts)
	if err != nil {
		return nil, err
	}
	return &CookieSessionProvider{
		NameProvider:    DefaultCookieSessionNameProvider(),
		PatternProvider: CookieSessionPatternProviderFor(defaultSessionMaxAge),
		Codec:           sessionCodec,
	}, nil
}

// NewTrackedRequestCodec returns a new TrackedRequestCodec for the provided
// options, a JWTTrackedRequestCodec that uses a JWT to encode TrackedRequests.
func NewTrackedRequestCodec(opts Options) (TrackedRequestCodec, error) {
	return &JWTTrackedRequestCodec{
		PatternProvider: optionsToJwtPatternProvider(opts),
	}, nil
}

// NewRequestTracker returns a new RequestTracker for the provided options,
// a CookieRequestTracker which uses cookies to track pending requests.
func NewRequestTracker(opts Options, serviceProvider saml.ServiceProvider) (RequestTracker, error) {
	trackedRequestCodec, err := NewTrackedRequestCodec(opts)
	if err != nil {
		return nil, err
	}
	return &CookieRequestTracker{
		ServiceProvider: serviceProvider,
		PatternProvider: CookieRequestPatternProviderFor(CookieRequestPattern{
			NamePrefix: "saml_",
			MaxAge:     saml.MaxIssueDelay,
		}),
		Codec: trackedRequestCodec,
	}, nil
}

// NewServiceProvider returns the default saml.DefaultServiceProvider for the provided
// options.
func NewServiceProvider(opts Options) (saml.ServiceProvider, error) {
	metadataURL := opts.URL.ResolveReference(&url.URL{Path: "saml/metadata"})
	acsURL := opts.URL.ResolveReference(&url.URL{Path: "saml/acs"})
	sloURL := opts.URL.ResolveReference(&url.URL{Path: "saml/slo"})

	var forceAuthn *bool
	if opts.ForceAuthn {
		forceAuthn = &opts.ForceAuthn
	}

	return &saml.DefaultServiceProvider{
		EntityID:          opts.EntityID,
		CertificatePair:   optionsToCertificatePair(opts),
		MetadataURL:       *metadataURL,
		AcsURL:            *acsURL,
		SloURL:            *sloURL,
		IDPMetadata:       opts.IDPMetadata,
		ForceAuthn:        forceAuthn,
		AllowIDPInitiated: opts.AllowIDPInitiated,
	}, nil
}

// New creates a new Middleware with the default providers for the
// given options.
//
// You can customize the behavior of the middleware in more detail by
// replacing and/or changing Session, RequestTracker, and NewServiceProvider
// in the returned Middleware.
func New(opts Options) (*Middleware, error) {
	serviceProvider, err := NewServiceProvider(opts)
	if err != nil {
		return nil, err
	}
	sessionProvider, err := NewSessionProvider(opts)
	if err != nil {
		return nil, err
	}
	requestTracker, err := NewRequestTracker(opts, serviceProvider)
	if err != nil {
		return nil, err
	}
	return &Middleware{
		ServiceProvider: serviceProvider,
		Binding:         "",
		OnError:         DefaultOnError,
		Session:         sessionProvider,
		RequestTracker:  requestTracker,
	}, nil
}
