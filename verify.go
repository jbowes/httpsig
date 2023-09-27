// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"time"
)

type verImpl struct {
	w      io.Writer
	verify func([]byte) error
}

type verHolder struct {
	alg      string
	verifier func() verImpl
}

type verifier struct {
	keys map[string]verHolder

	// For testing
	nowFunc func() time.Time
}

// XXX: note about fail fast.
func (v *verifier) Verify(msg *message) error {
	sigHdr := msg.Header.Get("Signature")
	if sigHdr == "" {
		return errNotSigned
	}

	paramHdr := msg.Header.Get("Signature-Input")
	if paramHdr == "" {
		return errNotSigned
	}

	sigParts := strings.Split(sigHdr, ", ")
	paramParts := strings.Split(paramHdr, ", ")

	if len(sigParts) != len(paramParts) {
		return errMalformedSignature
	}

	// TODO: could be smarter about selecting the sig to verify, eg based
	// on algorithm
	var sigID string
	var params *signatureParams
	for _, p := range paramParts {
		pParts := strings.SplitN(p, "=", 2)
		if len(pParts) != 2 {
			return errMalformedSignature
		}

		candidate, err := parseSignatureInput(pParts[1])
		if err != nil {
			return errMalformedSignature
		}

		if _, ok := v.keys[candidate.keyID]; ok {
			sigID = pParts[0]
			params = candidate
			break
		}
	}

	if params == nil {
		return errUnknownKey
	}

	var signature string
	for _, s := range sigParts {
		sParts := strings.SplitN(s, "=", 2)
		if len(sParts) != 2 {
			return errMalformedSignature
		}

		if sParts[0] == sigID {
			// TODO: error if not surrounded by colons
			signature = strings.Trim(sParts[1], ":")
			break
		}
	}

	if signature == "" {
		return errMalformedSignature
	}

	ver := v.keys[params.keyID]
	if ver.alg != "" && params.alg != "" && ver.alg != params.alg {
		return errAlgMismatch
	}

	// verify signature. if invalid, error
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return errMalformedSignature
	}

	verifier := ver.verifier()

	//TODO: skip the buffer.

	var b bytes.Buffer

	// canonicalize headers
	// TODO: wrap the errors within
	for _, h := range params.items {

		// handle specialty components, section 2.3
		var err error
		switch h {
		case "@method":
			err = canonicalizeMethod(&b, msg.Method)
		case "@path":
			err = canonicalizePath(&b, msg.URL.Path)
		case "@query":
			err = canonicalizeQuery(&b, msg.URL.RawQuery)
		case "@authority":
			err = canonicalizeAuthority(&b, msg.Authority)
		default:
			// handle default (header) components
			err = canonicalizeHeader(&b, h, msg.Header)
		}

		if err != nil {
			return err
		}
	}

	if _, err := verifier.w.Write(b.Bytes()); err != nil {
		return err
	}

	if err = canonicalizeSignatureParams(verifier.w, params); err != nil {
		return err
	}

	err = verifier.verify(sig)
	if err != nil {
		return errInvalidSignature
	}

	// TODO: could put in some wiggle room
	if params.expires != nil && params.expires.After(time.Now()) {
		return errSignatureExpired
	}

	return nil
}

// XXX use vice here too.

var (
	errNotSigned          = errors.New("signature headers not found")
	errMalformedSignature = errors.New("unable to parse signature headers")
	errUnknownKey         = errors.New("unknown key id")
	errAlgMismatch        = errors.New("algorithm mismatch for key id")
	errSignatureExpired   = errors.New("signature expired")
	errInvalidSignature   = errors.New("invalid signature")
)

// These error checking funcs aren't needed yet, so don't export them

/*

func IsNotSignedError(err error) bool          { return errors.Is(err, notSignedError) }
func IsMalformedSignatureError(err error) bool { return errors.Is(err, malformedSignatureError) }
func IsUnknownKeyError(err error) bool         { return errors.Is(err, unknownKeyError) }
func IsAlgMismatchError(err error) bool        { return errors.Is(err, algMismatchError) }
func IsSignatureExpiredError(err error) bool   { return errors.Is(err, signatureExpiredError) }
func IsInvalidSignatureError(err error) bool   { return errors.Is(err, invalidSignatureError) }

*/

func verifyRsaPssSha512(pk *rsa.PublicKey) verHolder {
	return verHolder{
		alg: "rsa-pss-sha512",
		verifier: func() verImpl {
			h := sha512.New()

			return verImpl{
				w: h,
				verify: func(s []byte) error {
					b := h.Sum(nil)

					return rsa.VerifyPSS(pk, crypto.SHA512, b, s, nil)
				},
			}
		},
	}
}

func verifyEccP256(pk *ecdsa.PublicKey) verHolder {
	return verHolder{
		alg: "ecdsa-p256-sha256",
		verifier: func() verImpl {
			h := sha256.New()

			return verImpl{
				w: h,
				verify: func(s []byte) error {
					b := h.Sum(nil)

					if !ecdsa.VerifyASN1(pk, b, s) {
						return errInvalidSignature
					}

					return nil
				},
			}
		},
	}
}

func verifyEccEd25519(pk ed25519.PublicKey) verHolder {
	return verHolder{
		alg: "ed25519",
		verifier: func() verImpl {
			h := bytes.NewBuffer(nil)

			return verImpl{
				w: h,
				verify: func(s []byte) error {
					if !ed25519.Verify(pk, h.Bytes(), s) {
						return errInvalidSignature
					}
					return nil
				},
			}
		},
	}
}

func verifyHmacSha256(secret []byte) verHolder {
	// TODO: add alg
	return verHolder{
		alg: "hmac-sha256",
		verifier: func() verImpl {
			h := hmac.New(sha256.New, secret)

			return verImpl{
				w: h,
				verify: func(in []byte) error {
					if !hmac.Equal(in, h.Sum(nil)) {
						return errInvalidSignature
					}
					return nil
				},
			}
		},
	}
}
