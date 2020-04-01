package samlsp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/echocat/go-saml"
)

const defaultSessionMaxAge = time.Hour

// JWTSessionCodec implements SessionCoded to encode and decode Sessions from
// the corresponding JWT.
type JWTSessionCodec struct {
	PatternProvider JWTPatternProvider
}

// New creates a Session from the SAML assertion.
//
// The returned Session is a JWTSessionClaims.
func (c *JWTSessionCodec) New(ctx context.Context, assertion *saml.Assertion) (Session, error) {
	pattern, err := c.PatternProvider(ctx)
	if err != nil {
		return nil, err
	}
	now := saml.TimeNow()
	claims := JWTSessionClaims{}
	claims.SAMLSession = true
	claims.Audience = pattern.Audience
	claims.Issuer = pattern.Issuer
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(pattern.MaxAge).Unix()
	claims.NotBefore = now.Unix()
	if sub := assertion.Subject; sub != nil {
		if nameID := sub.NameID; nameID != nil {
			claims.Subject = nameID.Value
		}
	}
	for _, attributeStatement := range assertion.AttributeStatements {
		claims.Attributes = map[string][]string{}
		for _, attr := range attributeStatement.Attributes {
			claimName := attr.FriendlyName
			if claimName == "" {
				claimName = attr.Name
			}
			for _, value := range attr.Values {
				claims.Attributes[claimName] = append(claims.Attributes[claimName], value.Value)
			}
		}
	}

	return claims, nil
}

// Encode returns a serialized version of the Session.
//
// The provided session must be a JWTSessionClaims, otherwise this
// function will panic.
func (c *JWTSessionCodec) Encode(ctx context.Context, s Session) (string, error) {
	pattern, err := c.PatternProvider(ctx)
	if err != nil {
		return "", err
	}
	claims := s.(JWTSessionClaims) // this will panic if you pass the wrong kind of session

	token := jwt.NewWithClaims(pattern.SigningMethod, claims)
	signedString, err := token.SignedString(pattern.CertificatePair.Key)
	if err != nil {
		return "", err
	}

	return signedString, nil
}

// Decode parses the serialized session that may have been returned by Encode
// and returns a Session.
func (c *JWTSessionCodec) Decode(ctx context.Context, signed string) (Session, error) {
	pattern, err := c.PatternProvider(ctx)
	if err != nil {
		return "", err
	}
	parser := jwt.Parser{
		ValidMethods: []string{pattern.SigningMethod.Alg()},
	}
	claims := JWTSessionClaims{}
	_, err = parser.ParseWithClaims(signed, &claims, func(*jwt.Token) (interface{}, error) {
		return pattern.CertificatePair.Certificate.PublicKey, nil
	})
	// TODO(ross): check for errors due to bad time and return ErrNoSession
	if err != nil {
		return nil, err
	}
	if !claims.VerifyAudience(pattern.Audience, true) {
		return nil, fmt.Errorf("expected audience %q, got %q", pattern.Audience, claims.Audience)
	}
	if !claims.VerifyIssuer(pattern.Issuer, true) {
		return nil, fmt.Errorf("expected issuer %q, got %q", pattern.Issuer, claims.Issuer)
	}
	if claims.SAMLSession != true {
		return nil, errors.New("expected saml-session")
	}
	return claims, nil
}

// JWTSessionClaims represents the JWT claims in the encoded session
type JWTSessionClaims struct {
	jwt.StandardClaims
	Attributes  Attributes `json:"attr"`
	SAMLSession bool       `json:"saml-session"`
}

var _ Session = JWTSessionClaims{}

// GetAttributes implements SessionWithAttributes. It returns the SAMl attributes.
func (c JWTSessionClaims) GetAttributes() Attributes {
	return c.Attributes
}

// Attributes is a map of attributes provided in the SAML assertion
type Attributes map[string][]string

// Get returns the first attribute named `key` or an empty string if
// no such attributes is present.
func (a Attributes) Get(key string) string {
	if a == nil {
		return ""
	}
	v := a[key]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
