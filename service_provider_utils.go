package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/beevik/etree"
	"github.com/echocat/go-saml/xmlenc"
	"github.com/pkg/errors"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// Metadata returns the service provider metadata
func GetMetadata(ctx context.Context, sp ServiceProvider) (*EntityDescriptor, error) {
	validDuration := DefaultValidDuration
	if duration, err := sp.GetMetadataValidDuration(ctx); err != nil {
		return nil, err
	} else if duration > 0 {
		validDuration = duration
	}

	authnRequestsSigned := false
	wantAssertionsSigned := true
	validUntil := TimeNow().Add(validDuration)

	var keyDescriptors []KeyDescriptor
	if pair, err := sp.GetCertificatePair(ctx); err != nil {
		return nil, err
	} else if pair.Certificate != nil {
		certBytes := pair.Certificate.Raw
		for _, intermediate := range pair.Intermediates {
			certBytes = append(certBytes, intermediate.Raw...)
		}
		keyDescriptors = []KeyDescriptor{
			{
				Use: "signing",
				KeyInfo: KeyInfo{
					Certificate: base64.StdEncoding.EncodeToString(certBytes),
				},
			},
			{
				Use: "encryption",
				KeyInfo: KeyInfo{
					Certificate: base64.StdEncoding.EncodeToString(certBytes),
				},
				EncryptionMethods: []EncryptionMethod{
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
				},
			},
		}
	}

	entityID, err := sp.GetEntityID(ctx)
	if err != nil {
		return nil, err
	}
	metadataURL, err := sp.GetMetadataURL(ctx)
	if err != nil {
		return nil, err
	}
	sloURL, err := sp.GetSloURL(ctx)
	if err != nil {
		return nil, err
	}
	acsURL, err := sp.GetAcsURL(ctx)
	if err != nil {
		return nil, err
	}

	return &EntityDescriptor{
		EntityID:   firstSet(entityID, metadataURL.String()),
		ValidUntil: validUntil,

		SPSSODescriptors: []SPSSODescriptor{
			{
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors:             keyDescriptors,
						ValidUntil:                 &validUntil,
					},
					SingleLogoutServices: []Endpoint{
						{
							Binding:          HTTPPostBinding,
							Location:         sloURL.String(),
							ResponseLocation: sloURL.String(),
						},
					},
				},
				AuthnRequestsSigned:  &authnRequestsSigned,
				WantAssertionsSigned: &wantAssertionsSigned,

				AssertionConsumerServices: []IndexedEndpoint{
					{
						Binding:  HTTPPostBinding,
						Location: acsURL.String(),
						Index:    1,
					},
				},
			},
		},
	}, nil
}

// MakeAuthenticationRequest produces a new AuthnRequest object for idpURL.
func MakeAuthenticationRequest(ctx context.Context, sp ServiceProvider, idpURL string) (*AuthnRequest, error) {
	entityID, err := sp.GetEntityID(ctx)
	if err != nil {
		return nil, err
	}
	acsUrl, err := sp.GetAcsURL(ctx)
	if err != nil {
		return nil, err
	}
	metadataURL, err := sp.GetMetadataURL(ctx)
	if err != nil {
		return nil, err
	}
	forceAuthn, err := sp.GetForceAuthn(ctx)
	if err != nil {
		return nil, err
	}
	nameIDFormat, err := sp.GetNameIDFormat(ctx)
	if err != nil {
		return nil, err
	}

	allowCreate := true
	req := AuthnRequest{
		AssertionConsumerServiceURL: acsUrl.String(),
		Destination:                 idpURL,
		ProtocolBinding:             HTTPPostBinding, // default binding for the response
		ID:                          fmt.Sprintf("id-%x", randomBytes(20)),
		IssueInstant:                TimeNow(),
		Version:                     "2.0",
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  firstSet(entityID, metadataURL.String()),
		},
		NameIDPolicy: &NameIDPolicy{
			AllowCreate: &allowCreate,
			// TODO(ross): figure out exactly policy we need
			// urn:mace:shibboleth:1.0:nameIdentifier
			// urn:oasis:names:tc:SAML:2.0:nameid-format:transient
			Format: &nameIDFormat,
		},
		ForceAuthn: forceAuthn,
	}
	return &req, nil
}

// MakePostAuthenticationRequest creates a SAML authentication request using
// the HTTP-POST binding. It returns HTML text representing an HTML form that
// can be sent presented to a browser to initiate the login process.
func MakePostAuthenticationRequest(ctx context.Context, sp ServiceProvider, relayState string) ([]byte, error) {
	req, err := MakeAuthenticationRequest(ctx, sp, sp.GetSSOBindingLocation(HTTPPostBinding))
	if err != nil {
		return nil, err
	}
	return req.Post(relayState), nil
}

// MakeRedirectAuthenticationRequest creates a SAML authentication request using
// the HTTP-Redirect binding. It returns a URL that we will redirect the user to
// in order to start the auth process.
func MakeRedirectAuthenticationRequest(ctx context.Context, sp ServiceProvider, relayState string) (*url.URL, error) {
	req, err := MakeAuthenticationRequest(ctx, sp, sp.GetSSOBindingLocation(HTTPRedirectBinding))
	if err != nil {
		return nil, err
	}
	return req.Redirect(relayState), nil
}

// ParseResponse extracts the SAML IDP response received in req, validates
// it, and returns the verified assertion.
func ParseResponse(req *http.Request, sp ServiceProvider, possibleRequestIDs []string) (*Assertion, error) {
	now := TimeNow()
	retErr := &InvalidResponseError{
		Now:      now,
		Response: req.PostForm.Get("SAMLResponse"),
	}

	rawResponseBuf, err := base64.StdEncoding.DecodeString(req.PostForm.Get("SAMLResponse"))
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot parse base64: %s", err)
		return nil, retErr
	}
	retErr.Response = string(rawResponseBuf)
	assertion, err := ParseXMLResponse(req.Context(), sp, rawResponseBuf, possibleRequestIDs)
	if err != nil {
		return nil, err
	}

	return assertion, nil
}

// ParseXMLResponse validates the SAML IDP response and
// returns the verified assertion.
//
// This function handles decrypting the message, verifying the digital
// signature on the assertion, and verifying that the specified conditions
// and properties are met.
//
// If the function fails it will return an InvalidResponseError whose
// properties are useful in describing which part of the parsing process
// failed. However, to discourage inadvertent disclosure the diagnostic
// information, the Error() method returns a static string.
func ParseXMLResponse(ctx context.Context, sp ServiceProvider, decodedResponseXML []byte, possibleRequestIDs []string) (*Assertion, error) {
	now := TimeNow()
	var err error
	retErr := &InvalidResponseError{
		Now:      now,
		Response: string(decodedResponseXML),
	}

	// do some validation first before we decrypt
	resp := Response{}
	if err := xml.Unmarshal(decodedResponseXML, &resp); err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot unmarshal response: %s", err)
		return nil, retErr
	}

	if err := validateDestination(ctx, sp, decodedResponseXML, &resp); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	requestIDvalid := false

	if allowIdpInitiated, err := sp.GetAllowIDPInitiated(ctx); err != nil {
		return nil, err
	} else if allowIdpInitiated {
		requestIDvalid = true
	} else {
		for _, possibleRequestID := range possibleRequestIDs {
			if resp.InResponseTo == possibleRequestID {
				requestIDvalid = true
			}
		}
	}

	if !requestIDvalid {
		retErr.PrivateErr = fmt.Errorf("`InResponseTo` does not match any of the possible request IDs (expected %v)", possibleRequestIDs)
		return nil, retErr
	}

	if resp.IssueInstant.Add(MaxIssueDelay).Before(now) {
		retErr.PrivateErr = fmt.Errorf("response IssueInstant expired at %s", resp.IssueInstant.Add(MaxIssueDelay))
		return nil, retErr
	}
	if idpMetadata, err := sp.GetIDPMetadata(ctx); err != nil {
		return nil, err
	} else if resp.Issuer.Value != idpMetadata.EntityID {
		retErr.PrivateErr = fmt.Errorf("response Issuer does not match the IDP metadata (expected %q)", idpMetadata.EntityID)
		return nil, retErr
	}
	if resp.Status.StatusCode.Value != StatusSuccess {
		retErr.PrivateErr = ErrBadStatus{Status: resp.Status.StatusCode.Value}
		return nil, retErr
	}

	var assertion *Assertion
	if resp.EncryptedAssertion == nil {

		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(decodedResponseXML); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}

		// TODO(ross): verify that the namespace is urn:oasis:names:tc:SAML:2.0:protocol
		responseEl := doc.Root()
		if responseEl.Tag != "Response" {
			retErr.PrivateErr = fmt.Errorf("expected to find a response object, not %s", doc.Root().Tag)
			return nil, retErr
		}

		if err = validateSigned(ctx, sp, responseEl); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}

		assertion = resp.Assertion
	}

	// decrypt the response
	if resp.EncryptedAssertion != nil {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(decodedResponseXML); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}
		cp, err := sp.GetCertificatePair(ctx)
		if err != nil {
			return nil, err
		}
		key := cp.Key
		keyEl := doc.FindElement("//EncryptedAssertion/EncryptedKey")
		if keyEl != nil {
			key, err = xmlenc.Decrypt(cp.Key, keyEl)
			if err != nil {
				retErr.PrivateErr = fmt.Errorf("failed to decrypt key from response: %s", err)
				return nil, retErr
			}
		}

		el := doc.FindElement("//EncryptedAssertion/EncryptedData")
		plaintextAssertion, err := xmlenc.Decrypt(key, el)
		if err != nil {
			retErr.PrivateErr = fmt.Errorf("failed to decrypt response: %s", err)
			return nil, retErr
		}
		retErr.Response = string(plaintextAssertion)

		doc = etree.NewDocument()
		if err := doc.ReadFromBytes(plaintextAssertion); err != nil {
			retErr.PrivateErr = fmt.Errorf("cannot parse plaintext response %v", err)
			return nil, retErr
		}

		if err := validateSigned(ctx, sp, doc.Root()); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}

		assertion = &Assertion{}
		if err := xml.Unmarshal(plaintextAssertion, assertion); err != nil {
			retErr.PrivateErr = err
			return nil, retErr
		}
	}

	if err := validateAssertion(ctx, sp, assertion, possibleRequestIDs, now); err != nil {
		retErr.PrivateErr = fmt.Errorf("assertion invalid: %s", err)
		return nil, retErr
	}

	return assertion, nil
}

// MakeRedirectLogoutRequest creates a SAML authentication request using
// the HTTP-Redirect binding. It returns a URL that we will redirect the user to
// in order to start the auth process.
func MakeRedirectLogoutRequest(ctx context.Context, sp ServiceProvider, nameID, relayState string) (*url.URL, error) {
	req, err := MakeLogoutRequest(ctx, sp, sp.GetSLOBindingLocation(HTTPRedirectBinding), nameID)
	if err != nil {
		return nil, err
	}
	return req.Redirect(relayState), nil
}

// MakePostLogoutRequest creates a SAML authentication request using
// the HTTP-POST binding. It returns HTML text representing an HTML form that
// can be sent presented to a browser to initiate the logout process.
func MakePostLogoutRequest(ctx context.Context, sp ServiceProvider, nameID, relayState string) ([]byte, error) {
	req, err := MakeLogoutRequest(ctx, sp, sp.GetSLOBindingLocation(HTTPPostBinding), nameID)
	if err != nil {
		return nil, err
	}
	return req.Post(relayState), nil
}

// MakeLogoutRequest produces a new LogoutRequest object for idpURL.
func MakeLogoutRequest(ctx context.Context, sp ServiceProvider, idpURL, nameID string) (*LogoutRequest, error) {
	entityID, err := sp.GetEntityID(ctx)
	if err != nil {
		return nil, err
	}
	metadataURL, err := sp.GetMetadataURL(ctx)
	if err != nil {
		return nil, err
	}
	nameIDFormat, err := sp.GetNameIDFormat(ctx)
	if err != nil {
		return nil, err
	}

	idpMetadata, err := sp.GetIDPMetadata(ctx)
	if err != nil {
		return nil, err
	}
	metadata, err := GetMetadata(ctx, sp)
	if err != nil {
		return nil, err
	}

	req := LogoutRequest{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Destination:  idpURL,
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  firstSet(entityID, metadataURL.String()),
		},
		NameID: &NameID{
			Format:          nameIDFormat,
			Value:           nameID,
			NameQualifier:   idpMetadata.EntityID,
			SPNameQualifier: metadata.EntityID,
		},
	}
	return &req, nil
}

// ValidateLogoutResponseRequest validates the LogoutResponse content from the request
//noinspection GoUnusedExportedFunction
func ValidateLogoutResponseRequest(req *http.Request, sp ServiceProvider) error {
	if data := req.URL.Query().Get("SAMLResponse"); data != "" {
		return ValidateLogoutResponseRedirect(req.Context(), sp, data)
	}

	err := req.ParseForm()
	if err != nil {
		return fmt.Errorf("unable to parse form: %v", err)
	}

	return ValidateLogoutResponseForm(req.Context(), sp, req.PostForm.Get("SAMLResponse"))
}

// ValidatePostLogoutResponse returns a nil error if the logout response is valid.
func ValidateLogoutResponseForm(ctx context.Context, sp ServiceProvider, postFormData string) error {
	rawResponseBuf, err := base64.StdEncoding.DecodeString(postFormData)
	if err != nil {
		return fmt.Errorf("unable to parse base64: %s", err)
	}

	var resp LogoutResponse

	if err := xml.Unmarshal(rawResponseBuf, &resp); err != nil {
		return fmt.Errorf("cannot unmarshal response: %s", err)
	}

	if err := validateLogoutResponse(ctx, sp, &resp); err != nil {
		return err
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rawResponseBuf); err != nil {
		return err
	}

	responseEl := doc.Root()
	if err = validateSigned(ctx, sp, responseEl); err != nil {
		return err
	}

	return nil
}

// validateLogoutResponse validates the LogoutResponse fields. Returns a nil error if the LogoutResponse is valid.
func validateLogoutResponse(ctx context.Context, sp ServiceProvider, resp *LogoutResponse) error {

	if sloURL, err := sp.GetSloURL(ctx); err != nil {
		return err
	} else if resp.Destination != sloURL.String() {
		return fmt.Errorf("`Destination` does not match SloURL (expected %q)", sloURL.String())
	}

	now := time.Now()
	if resp.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return fmt.Errorf("issueInstant expired at %s", resp.IssueInstant.Add(MaxIssueDelay))
	}

	if idpMetadata, err := sp.GetIDPMetadata(ctx); err != nil {
		return err
	} else if resp.Issuer.Value != idpMetadata.EntityID {
		return fmt.Errorf("issuer does not match the IDP metadata (expected %q)", idpMetadata.EntityID)
	}
	if resp.Status.StatusCode.Value != StatusSuccess {
		return fmt.Errorf("status code was not %s", StatusSuccess)
	}

	return nil
}

// ValidateRedirectLogoutResponse returns a nil error if the logout response is valid.
// URL Binding appears to be gzip / flate encoded
// See https://www.oasis-open.org/committees/download.php/20645/sstc-saml-tech-overview-2%200-draft-10.pdf  6.6
func ValidateLogoutResponseRedirect(ctx context.Context, sp ServiceProvider, queryParameterData string) error {
	rawResponseBuf, err := base64.StdEncoding.DecodeString(queryParameterData)
	if err != nil {
		return fmt.Errorf("unable to parse base64: %s", err)
	}

	gr := flate.NewReader(bytes.NewBuffer(rawResponseBuf))

	decoder := xml.NewDecoder(gr)

	var resp LogoutResponse

	err = decoder.Decode(&resp)
	if err != nil {
		return fmt.Errorf("unable to flate decode: %s", err)
	}

	if err := validateLogoutResponse(ctx, sp, &resp); err != nil {
		return err
	}

	doc := etree.NewDocument()
	if _, err := doc.ReadFrom(gr); err != nil {
		return err
	}

	responseEl := doc.Root()
	if err = validateSigned(ctx, sp, responseEl); err != nil {
		return err
	}

	return nil
}

// validateSignature returns nill iff the Signature embedded in the element is valid
func validateSignature(ctx context.Context, sp ServiceProvider, el *etree.Element) error {
	certs, err := getIDPSigningCerts(ctx, sp)
	if err != nil {
		return err
	}

	certificateStore := dsig.MemoryX509CertificateStore{
		Roots: certs,
	}

	validationContext := dsig.NewDefaultValidationContext(&certificateStore)
	validationContext.IdAttribute = "ID"
	if Clock != nil {
		validationContext.Clock = Clock
	}

	// Some SAML responses contain a RSAKeyValue element. One of two things is happening here:
	//
	// (1) We're getting something signed by a key we already know about -- the public key
	//     of the signing cert provided in the metadata.
	// (2) We're getting something signed by a key we *don't* know about, and which we have
	//     no ability to verify.
	//
	// The best course of action is to just remove the KeyInfo so that dsig falls back to
	// verifying against the public key provided in the metadata.
	if el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate") == nil {
		if sigEl := el.FindElement("./Signature"); sigEl != nil {
			if keyInfo := sigEl.FindElement("KeyInfo"); keyInfo != nil {
				sigEl.RemoveChild(keyInfo)
			}
		}
	}

	nCtx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return err
	}
	nCtx, err = nCtx.SubContext(el)
	if err != nil {
		return err
	}
	el, err = etreeutils.NSDetatch(nCtx, el)
	if err != nil {
		return err
	}

	if v, err := sp.GetSignatureVerifier(ctx); err != nil {
		return err
	} else if v != nil {
		return v.VerifySignature(validationContext, el)
	}

	_, err = validationContext.Validate(el)
	return err
}

// getIDPSigningCerts returns the certificates which we can use to verify things
// signed by the IDP in PEM format, or nil if no such certificate is found.
func getIDPSigningCerts(ctx context.Context, sp ServiceProvider) ([]*x509.Certificate, error) {
	idpMetadata, err := sp.GetIDPMetadata(ctx)
	if err != nil {
		return nil, err
	}
	var certStrs []string
	for _, idpSSODescriptor := range idpMetadata.IDPSSODescriptors {
		for _, keyDescriptor := range idpSSODescriptor.KeyDescriptors {
			if keyDescriptor.Use == "signing" {
				certStrs = append(certStrs, keyDescriptor.KeyInfo.Certificate)
			}
		}
	}

	// If there are no explicitly signing certs, just return the first
	// non-empty cert we find.
	if len(certStrs) == 0 {
		for _, idpSSODescriptor := range idpMetadata.IDPSSODescriptors {
			for _, keyDescriptor := range idpSSODescriptor.KeyDescriptors {
				if keyDescriptor.Use == "" && keyDescriptor.KeyInfo.Certificate != "" {
					certStrs = append(certStrs, keyDescriptor.KeyInfo.Certificate)
					break
				}
			}
		}
	}

	if len(certStrs) == 0 {
		return nil, errors.New("cannot find any signing certificate in the IDP SSO descriptor")
	}

	var certs []*x509.Certificate

	// cleanup whitespace
	regex := regexp.MustCompile(`\s+`)
	for _, certStr := range certStrs {
		certStr = regex.ReplaceAllString(certStr, "")
		certBytes, err := base64.StdEncoding.DecodeString(certStr)
		if err != nil {
			return nil, fmt.Errorf("cannot parse certificate: %s", err)
		}

		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, parsedCert)
	}

	return certs, nil
}

// validateDestination validates the Destination attribute.
// If the response is signed, the Destination is required to be present.
func validateDestination(ctx context.Context, sp ServiceProvider, response []byte, responseDom *Response) error {
	responseXML := etree.NewDocument()
	err := responseXML.ReadFromBytes(response)
	if err != nil {
		return err
	}

	signed, err := responseIsSigned(responseXML)
	if err != nil {
		return err
	}

	// Compare if the response is signed OR the Destination is provided.
	// (Even if the response is not signed, if the Destination is set it must match.)
	if signed || responseDom.Destination != "" {
		if au, err := sp.GetAcsURL(ctx); err != nil {
			return err
		} else if responseDom.Destination != au.String() {
			return fmt.Errorf("`Destination` does not match AcsURL (expected %q, actual %q)", au.String(), responseDom.Destination)
		}
	}

	return nil
}

// validateAssertion checks that the conditions specified in assertion match
// the requirements to accept. If validation fails, it returns an error describing
// the failure. (The digital signature on the assertion is not checked -- this
// should be done before calling this function).
func validateAssertion(ctx context.Context, sp ServiceProvider, assertion *Assertion, possibleRequestIDs []string, now time.Time) error {
	if assertion.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return fmt.Errorf("expired on %s", assertion.IssueInstant.Add(MaxIssueDelay))
	}
	if idpMetadata, err := sp.GetIDPMetadata(ctx); err != nil {
		return err
	} else if assertion.Issuer.Value != idpMetadata.EntityID {
		return fmt.Errorf("issuer is not %q", idpMetadata.EntityID)
	}
	for _, subjectConfirmation := range assertion.Subject.SubjectConfirmations {
		requestIDvalid := false
		for _, possibleRequestID := range possibleRequestIDs {
			if subjectConfirmation.SubjectConfirmationData.InResponseTo == possibleRequestID {
				requestIDvalid = true
				break
			}
		}
		if !requestIDvalid {
			return fmt.Errorf("assertion SubjectConfirmation one of the possible request IDs (%v)", possibleRequestIDs)
		}
		if au, err := sp.GetAcsURL(ctx); err != nil {
			return err
		} else if subjectConfirmation.SubjectConfirmationData.Recipient != au.String() {
			return fmt.Errorf("assertion SubjectConfirmation Recipient is not %s", au.String())
		}
		if subjectConfirmation.SubjectConfirmationData.NotOnOrAfter.Add(MaxClockSkew).Before(now) {
			return fmt.Errorf("assertion SubjectConfirmationData is expired")
		}
	}
	if assertion.Conditions.NotBefore.Add(-MaxClockSkew).After(now) {
		return fmt.Errorf("assertion Conditions is not yet valid")
	}
	if assertion.Conditions.NotOnOrAfter.Add(MaxClockSkew).Before(now) {
		return fmt.Errorf("assertion Conditions is expired")
	}

	audienceRestrictionsValid := len(assertion.Conditions.AudienceRestrictions) == 0
	entityId, err := sp.GetEntityID(ctx)
	if err != nil {
		return err
	}
	metadataUrl, err := sp.GetMetadataURL(ctx)
	if err != nil {
		return err
	}
	audience := firstSet(entityId, metadataUrl.String())
	for _, audienceRestriction := range assertion.Conditions.AudienceRestrictions {
		if audienceRestriction.Audience.Value == audience {
			audienceRestrictionsValid = true
		}
	}
	if !audienceRestrictionsValid {
		return fmt.Errorf("assertion Conditions AudienceRestriction does not contain %q", audience)
	}
	return nil
}

// validateSigned returns a nil error iff each of the signatures on the Response and Assertion elements
// are valid and there is at least one signature.
func validateSigned(ctx context.Context, sp ServiceProvider, responseEl *etree.Element) error {
	haveSignature := false

	// Some SAML responses have the signature on the Response object, and some on the Assertion
	// object, and some on both. We will require that at least one signature be present and that
	// all signatures be valid
	sigEl, err := findChild(responseEl, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return err
	}
	if sigEl != nil {
		if err = validateSignature(ctx, sp, responseEl); err != nil {
			return fmt.Errorf("cannot validate signature on Response: %v", err)
		}
		haveSignature = true
	}

	assertionEl, err := findChild(responseEl, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
	if err != nil {
		return err
	}
	if assertionEl != nil {
		sigEl, err := findChild(assertionEl, "http://www.w3.org/2000/09/xmldsig#", "Signature")
		if err != nil {
			return err
		}
		if sigEl != nil {
			if err = validateSignature(ctx, sp, assertionEl); err != nil {
				return fmt.Errorf("cannot validate signature on Response: %v", err)
			}
			haveSignature = true
		}
	}

	if !haveSignature {
		return errors.New("either the Response or Assertion must be signed")
	}
	return nil
}

func responseIsSigned(response *etree.Document) (bool, error) {
	signatureElement, err := findChild(response.Root(), "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return false, err
	}
	return signatureElement != nil, nil
}

func findChild(parentEl *etree.Element, childNS string, childTag string) (*etree.Element, error) {
	for _, childEl := range parentEl.ChildElements() {
		if childEl.Tag != childTag {
			continue
		}

		ctx, err := etreeutils.NSBuildParentContext(childEl)
		if err != nil {
			return nil, err
		}
		ctx, err = ctx.SubContext(childEl)
		if err != nil {
			return nil, err
		}

		ns, err := ctx.LookupPrefix(childEl.Space)
		if err != nil {
			return nil, fmt.Errorf("[%s]:%s cannot find prefix %s: %v", childNS, childTag, childEl.Space, err)
		}
		if ns != childNS {
			continue
		}

		return childEl, nil
	}
	return nil, nil
}
