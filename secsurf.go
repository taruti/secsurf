/*
Package secsurf wraps https handlers setting various security related headers.

Please read the documentation carefully as the headers have long term security implications.

The following headers are set:
	X-XSS-Protection: 1; mode=block
	X-Frame-Options: deny
	X-Content-Type-Options: nosniff
	Strict-Transport-Security: max-age=31536000; includeSubDomains

X-XSS-Protection

Force XSS protection in some versions of IE.

X-Frame-Options

The pages cannot be used inside frames.

X-Content-Type-Options

Content type is not guessed by the browser.

Strict-Transport-Security

After the page has been succesfully loaded with a valid certificate chain the browser will REFUSE to load the page in the future without a valid https (tls) connection. Strict-Transport-Security is only set on https responses.

*/
package secsurf

import (
	"net/http"
)

// Wrap a HTTP handler.
func New(h http.Handler) http.Handler {
	return wrap{h}
}

type wrap struct {
	http.Handler
}

func (h wrap)ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hdrs := w.Header()
	hdrs.Set(`X-XSS-Protection`, `1; mode=block`)
	hdrs.Set(`X-Frame-Options`, `deny`)
	hdrs.Set(`X-Content-Type-Options`, `nosniff`)
	if r.TLS != nil {
		hdrs.Set(`Strict-Transport-Security`, `max-age=31536000; includeSubDomains`)
	}
	h.Handler.ServeHTTP(w, r)
}

// Wrap a HTTP handler, adds a STS header even on HTTP.
func NewAlwaysSTS(h http.Handler) http.Handler {
	return swrap{h}
}

type swrap struct {
	http.Handler
}

func (h swrap)ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hdrs := w.Header()
	hdrs.Set(`X-XSS-Protection`, `1; mode=block`)
	hdrs.Set(`X-Frame-Options`, `deny`)
	hdrs.Set(`X-Content-Type-Options`, `nosniff`)
	hdrs.Set(`Strict-Transport-Security`, `max-age=31536000; includeSubDomains`)
	h.Handler.ServeHTTP(w, r)
}
