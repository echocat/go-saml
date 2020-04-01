package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/echocat/go-saml/samlsp"
	"net/http"
	"net/url"
	"time"
)

func hello(w http.ResponseWriter, r *http.Request) {
	session := samlsp.SessionFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "   ")
	_ = encoder.Encode(session)
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		panic(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err)
	}

	idpMetadataURL, err := url.Parse("https://login.microsoftonline.com/e4a8eac5-60d4-40e6-8b6c-dcde6f9abfb3/federationmetadata/2007-06/federationmetadata.xml?appid=3f676dc5-506e-4fcf-a88b-07c3d507858b")
	if err != nil {
		panic(err)
	}

	rootURL, err := url.Parse("https://localhost:8000")
	if err != nil {
		panic(err)
	}

	idpMetadata, err := samlsp.FetchMetadata(context.TODO(), http.DefaultClient, *idpMetadataURL)
	if err != nil {
		panic(err)
	}

	opts := samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey,
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
	}
	samlSP, _ := samlsp.New(opts)

	samlSP.Session.(*samlsp.CookieSessionProvider).PatternProvider = samlsp.CookieSessionPatternProviderFor(time.Minute * 15)

	app := http.HandlerFunc(hello)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)
	if err := http.ListenAndServeTLS(":8000", "myservice.cert", "myservice.key", nil); err != nil {
		panic(err)
	}
}
