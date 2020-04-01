package saml

import (
	"crypto"
	"crypto/x509"
)

type CertificatePair struct {
	// Key is the RSA private key we use to sign requests.
	Key crypto.PrivateKey

	// CertificatePair is the RSA public part of Key.
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate
}
