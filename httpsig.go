package httpsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"io/ioutil"
	"net/http"
)

var defaultHeaders = []string{"content-type", "content-length", "host"} // also request path and digest

func sliceHas(haystack []string, needle string) bool {
	for _, n := range haystack {
		if n == needle {
			return true
		}
	}

	return false
}

// NewSignTransport returns a new client transport that wraps the provided transport with
// http message signing and body digest creation
func NewSignTransport(transport http.RoundTripper, opts ...signOption) http.RoundTripper {
	s := signer{}

	for _, o := range opts {
		o.configureSign(&s)
	}

	if len(s.headers) == 0 {
		s.headers = defaultHeaders[:]
	}

	// TODO: normalize headers? lowercase & de-dupe

	// request path first, for aesthetics
	if !sliceHas(s.headers, "@request-path") {
		s.headers = append([]string{"@request-path"}, s.headers...)
	}

	if !sliceHas(s.headers, "digest") {
		s.headers = append(s.headers, "digest")
	}

	return rt(func(r *http.Request) (*http.Response, error) {
		nr := r.Clone(r.Context())

		b := &bytes.Buffer{}
		if r.Body != nil {
			n, err := b.ReadFrom(r.Body)
			if err != nil {
				return nil, err
			}

			defer r.Body.Close()

			if n != 0 {
				r.Body = ioutil.NopCloser(bytes.NewReader(b.Bytes()))
			}
		}

		// Always set a digest (for now)
		// TODO: we could skip setting digest on an empty body if content-length is included in the sig
		r.Header.Set("Digest", calcDigest(b.Bytes()))

		msg := messageFromRequest(nr)
		hdr, err := s.Sign(msg)
		if err != nil {
			return nil, err
		}

		for k, v := range hdr {
			nr.Header[k] = v
		}

		return transport.RoundTrip(r)
	})
}

type rt func(*http.Request) (*http.Response, error)

func (r rt) RoundTrip(req *http.Request) (*http.Response, error) { return r(req) }

// NewVerifyMiddleware returns a configured http server middleware that can be used to wrap
// multiple handlers for http message signature and digest verification.
//
// TODO: form and multipart support
func NewVerifyMiddleware(opts ...verifyOption) func(http.Handler) http.Handler {

	v := verifier{}

	for _, o := range opts {
		o.configureVerify(&v)
	}

	serveErr := func(rw http.ResponseWriter) {
		// TODO: better error and custom error handler
		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusBadRequest)

		rw.Write([]byte("invalid required signature"))

		return
	}

	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {

			msg := messageFromRequest(r)
			err := v.Verify(msg)
			if err != nil {
				serveErr(rw)
				return
			}

			b := &bytes.Buffer{}
			if r.Body != nil {
				n, err := b.ReadFrom(r.Body)
				if err != nil {
					serveErr(rw)
					return
				}

				defer r.Body.Close()

				if n != 0 {
					r.Body = ioutil.NopCloser(bytes.NewReader(b.Bytes()))
				}
			}

			// Check the digest if set. We only support id-sha-256 for now.
			// TODO: option to require this?
			if dig := r.Header.Get("Digest"); dig != "" {
				if !verifyDigest(b.Bytes(), dig) {
					serveErr(rw)
				}
			}

			h.ServeHTTP(rw, r)
		})
	}
}

type signOption interface {
	configureSign(s *signer)
}

type verifyOption interface {
	configureVerify(v *verifier)
}

type signOrVerifyOption interface {
	signOption
	verifyOption
}

type optImpl struct {
	s func(s *signer)
	v func(v *verifier)
}

func (o *optImpl) configureSign(s *signer)     { o.s(s) }
func (o *optImpl) configureVerify(v *verifier) { o.v(v) }

// TODO: use this to implement required headers in verify?
func WithHeaders(hdr ...string) signOption {
	return &optImpl{
		s: func(s *signer) { s.headers = hdr },
	}
}

func WithSignRsaPssSha512(keyID string, pk *rsa.PrivateKey) signOption {
	return &optImpl{
		s: func(s *signer) { s.keys[keyID] = signRsaPssSha512(pk) },
	}
}
func WithVerifyRsaPssSha512(keyID string, pk *rsa.PublicKey) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.keys[keyID] = verifyRsaPssSha512(pk) },
	}
}

func WithSignEcdsaP256Sha256(keyID string, pk *ecdsa.PrivateKey) signOption {
	return &optImpl{
		s: func(s *signer) { s.keys[keyID] = signEccP256(pk) },
	}
}
func WithVerifyEcdsaP256Sha256(keyID string, pk *ecdsa.PublicKey) verifyOption {
	return &optImpl{
		v: func(v *verifier) { v.keys[keyID] = verifyEccP256(pk) },
	}
}

func WithHmacSha256(keyID string, secret []byte) signOrVerifyOption {
	return &optImpl{
		s: func(s *signer) { s.keys[keyID] = signHmacSha256(secret) },
		v: func(v *verifier) { v.keys[keyID] = verifyHmacSha256(secret) },
	}
}
