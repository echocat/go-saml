package samlsp

import (
	"net"
	"net/http"
	"time"

	"github.com/echocat/go-saml"
)

const defaultSessionCookieName = "token"

// CookieSessionProvider is an implementation of SessionProvider that stores
// session tokens in an HTTP cookie.
type CookieSessionProvider struct {
	NameProvider    CookeSessionNameProvider
	PatternProvider CookeSessionPatternProvider
	Codec           SessionCodec
}

type CookeSessionPattern struct {
	Domain   string
	HTTPOnly bool
	Secure   bool
	MaxAge   time.Duration
}

type CookeSessionNameProvider func(r *http.Request) (string, error)

func DefaultCookieSessionNameProvider() CookeSessionNameProvider {
	return func(*http.Request) (string, error) {
		return defaultSessionCookieName, nil
	}
}

type CookeSessionPatternProvider func(r *http.Request) (CookeSessionPattern, error)

func CookieSessionPatternProviderFor(sessionMaxAge time.Duration) CookeSessionPatternProvider {
	return func(r *http.Request) (CookeSessionPattern, error) {
		return CookeSessionPattern{
			Domain:   r.Host,
			HTTPOnly: true,
			Secure:   r.URL.Scheme == "https",
			MaxAge:   sessionMaxAge,
		}, nil
	}
}

// CreateSession is called when we have received a valid SAML assertion and
// should create a new session and modify the http response accordingly, e.g. by
// setting a cookie.
func (c *CookieSessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	name, err := c.NameProvider(r)
	if err != nil {
		return err
	}
	pattern, err := c.PatternProvider(r)
	if err != nil {
		return err
	}
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(pattern.Domain); err == nil {
		pattern.Domain = domain
	}

	session, err := c.Codec.New(r.Context(), assertion)
	if err != nil {
		return err
	}

	value, err := c.Codec.Encode(r.Context(), session)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Domain:   pattern.Domain,
		Value:    value,
		MaxAge:   int(pattern.MaxAge.Seconds()),
		HttpOnly: pattern.HTTPOnly,
		Secure:   pattern.Secure || r.URL.Scheme == "https",
		Path:     "/",
	})
	return nil
}

// DeleteSession is called to modify the response such that it removed the current
// session, e.g. by deleting a cookie.
func (c *CookieSessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	name, err := c.NameProvider(r)
	if err != nil {
		return err
	}
	cookie, err := r.Cookie(name)
	if err == http.ErrNoCookie {
		return nil
	}
	if err != nil {
		return err
	}

	cookie.Value = ""
	cookie.Expires = time.Unix(1, 0) // past time as close to epoch as possible, but not zero time.Time{}
	http.SetCookie(w, cookie)
	return nil
}

// GetSession returns the current Session associated with the request, or
// ErrNoSession if there is no valid session.
func (c *CookieSessionProvider) GetSession(r *http.Request) (Session, error) {
	name, err := c.NameProvider(r)
	if err != nil {
		return nil, err
	}
	cookie, err := r.Cookie(name)
	if err == http.ErrNoCookie {
		return nil, ErrNoSession
	} else if err != nil {
		return nil, err
	}

	session, err := c.Codec.Decode(r.Context(), cookie.Value)
	if err != nil {
		return nil, ErrNoSession
	}
	return session, nil
}
