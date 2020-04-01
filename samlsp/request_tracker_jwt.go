package samlsp

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"

	"github.com/echocat/go-saml"
)

var defaultJWTSigningMethod = jwt.SigningMethodRS256

// JWTTrackedRequestCodec encodes TrackedRequests as signed JWTs
type JWTTrackedRequestCodec struct {
	PatternProvider JWTPatternProvider
}

var _ TrackedRequestCodec = JWTTrackedRequestCodec{}

// JWTTrackedRequestClaims represents the JWT claims for a tracked request.
type JWTTrackedRequestClaims struct {
	jwt.StandardClaims
	TrackedRequest
	SAMLAuthnRequest bool `json:"saml-authn-request"`
}

// Encode returns an encoded string representing the TrackedRequest.
func (s JWTTrackedRequestCodec) Encode(ctx context.Context, value TrackedRequest) (string, error) {
	pattern, err := s.PatternProvider(ctx)
	if err != nil {
		return "", err
	}
	now := saml.TimeNow()
	claims := JWTTrackedRequestClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  pattern.Audience,
			ExpiresAt: now.Add(pattern.MaxAge).Unix(),
			IssuedAt:  now.Unix(),
			Issuer:    pattern.Issuer,
			NotBefore: now.Unix(), // TODO(ross): correct for clock skew
			Subject:   value.Index,
		},
		TrackedRequest:   value,
		SAMLAuthnRequest: true,
	}
	token := jwt.NewWithClaims(pattern.SigningMethod, claims)
	return token.SignedString(pattern.CertificatePair.Key)
}

// Decode returns a Tracked request from an encoded string.
func (s JWTTrackedRequestCodec) Decode(ctx context.Context, signed string) (*TrackedRequest, error) {
	pattern, err := s.PatternProvider(ctx)
	if err != nil {
		return nil, err
	}
	parser := jwt.Parser{
		ValidMethods: []string{pattern.SigningMethod.Alg()},
	}
	claims := JWTTrackedRequestClaims{}
	_, err = parser.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
		return pattern.CertificatePair.Certificate.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !claims.VerifyAudience(pattern.Audience, true) {
		return nil, fmt.Errorf("expected audience %q, got %q", pattern.Audience, claims.Audience)
	}
	if !claims.VerifyIssuer(pattern.Issuer, true) {
		return nil, fmt.Errorf("expected issuer %q, got %q", pattern.Issuer, claims.Issuer)
	}
	if claims.SAMLAuthnRequest != true {
		return nil, fmt.Errorf("expected saml-authn-request")
	}
	claims.TrackedRequest.Index = claims.Subject
	return &claims.TrackedRequest, nil
}
