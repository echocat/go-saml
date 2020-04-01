package samlsp

import (
	"context"
	"github.com/dgrijalva/jwt-go"
	"github.com/echocat/go-saml"
	"time"
)

type JWTSessionPattern struct {
	SigningMethod   jwt.SigningMethod
	Audience        string
	Issuer          string
	MaxAge          time.Duration
	CertificatePair saml.CertificatePair
}

type JWTPatternProvider func(context.Context) (JWTSessionPattern, error)

func JWTPatternProviderFor(in JWTSessionPattern) JWTPatternProvider {
	return func(context.Context) (JWTSessionPattern, error) {
		return in, nil
	}
}
