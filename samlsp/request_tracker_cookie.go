package samlsp

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/echocat/go-saml"
)

var _ RequestTracker = CookieRequestTracker{}

// CookieRequestTracker tracks requests by setting a uniquely named
// cookie for each request.
type CookieRequestTracker struct {
	ServiceProvider saml.ServiceProvider
	Codec           TrackedRequestCodec
	PatternProvider CookieRequestPatternProvider
}

type CookieRequestPattern struct {
	NamePrefix string
	MaxAge     time.Duration
}

type CookieRequestPatternProvider func(*http.Request) (CookieRequestPattern, error)

func CookieRequestPatternProviderFor(in CookieRequestPattern) CookieRequestPatternProvider {
	return func(*http.Request) (CookieRequestPattern, error) {
		return in, nil
	}
}

// TrackRequest starts tracking the SAML request with the given ID. It returns an
// `index` that should be used as the RelayState in the SAMl request flow.
func (t CookieRequestTracker) TrackRequest(w http.ResponseWriter, r *http.Request, samlRequestID string) (string, error) {
	trackedRequest := TrackedRequest{
		Index:         base64.RawURLEncoding.EncodeToString(randomBytes(42)),
		SAMLRequestID: samlRequestID,
		URI:           r.URL.String(),
	}
	signedTrackedRequest, err := t.Codec.Encode(r.Context(), trackedRequest)
	if err != nil {
		return "", err
	}
	acsUrl, err := t.ServiceProvider.GetAcsURL(r.Context())
	if err != nil {
		return "", err
	}

	pattern, err := t.PatternProvider(r)
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     pattern.NamePrefix + trackedRequest.Index,
		Value:    signedTrackedRequest,
		MaxAge:   int(pattern.MaxAge.Seconds()),
		HttpOnly: true,
		Secure:   acsUrl.Scheme == "https",
		Path:     acsUrl.Path,
	})

	return trackedRequest.Index, nil
}

// StopTrackingRequest stops tracking the SAML request given by index, which is a string
// previously returned from TrackRequest
func (t CookieRequestTracker) StopTrackingRequest(w http.ResponseWriter, r *http.Request, index string) error {
	pattern, err := t.PatternProvider(r)
	if err != nil {
		return err
	}

	cookie, err := r.Cookie(pattern.NamePrefix + index)
	if err != nil {
		return err
	}
	cookie.Value = ""
	cookie.Expires = time.Unix(1, 0) // past time as close to epoch as possible, but not zero time.Time{}
	http.SetCookie(w, cookie)
	return nil
}

// GetTrackedRequests returns all the pending tracked requests
func (t CookieRequestTracker) GetTrackedRequests(r *http.Request) ([]TrackedRequest, error) {
	pattern, err := t.PatternProvider(r)
	if err != nil {
		return nil, err
	}

	var rv []TrackedRequest
	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, pattern.NamePrefix) {
			continue
		}

		trackedRequest, err := t.Codec.Decode(r.Context(), cookie.Value)
		if err != nil {
			continue
		}
		index := strings.TrimPrefix(cookie.Name, pattern.NamePrefix)
		if index != trackedRequest.Index {
			continue
		}

		rv = append(rv, *trackedRequest)
	}
	return rv, nil
}

// GetTrackedRequest returns a pending tracked request.
func (t CookieRequestTracker) GetTrackedRequest(r *http.Request, index string) (*TrackedRequest, error) {
	pattern, err := t.PatternProvider(r)
	if err != nil {
		return nil, err
	}

	cookie, err := r.Cookie(pattern.NamePrefix + index)
	if err != nil {
		return nil, err
	}

	trackedRequest, err := t.Codec.Decode(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}
	if trackedRequest.Index != index {
		return nil, fmt.Errorf("expected index %q, got %q", index, trackedRequest.Index)
	}
	return trackedRequest, nil
}
