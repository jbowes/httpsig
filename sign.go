// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type sigImpl struct {
	w    io.Writer
	sign func() []byte
}

type sigHolder struct {
	alg    string
	signer func() sigImpl
}

type signer struct {
	headers []string
	keys    map[string]sigHolder

	// For testing
	nowFunc func() time.Time
}

func (s *signer) Sign(msg *message) (http.Header, error) {
	var b bytes.Buffer

	var items []string

	// canonicalize headers
	for _, h := range s.headers {
		// optionally canonicalize request path via magic string
		if h == "@request-target" {
			err := canonicalizeRequestTarget(&b, msg.Method, msg.URL)
			if err != nil {
				return nil, err
			}

			items = append(items, h)
			continue
		}

		// Skip unset headers
		if len(msg.Header.Values(h)) == 0 {
			continue
		}

		err := canonicalizeHeader(&b, h, msg.Header)
		if err != nil {
			return nil, err
		}

		items = append(items, h)
	}

	now := s.nowFunc()

	sps := make(map[string]string)
	sigs := make(map[string]string)
	i := 1 // 1 indexed icky
	for k, si := range s.keys {
		sp := &signatureParams{
			items:   items,
			keyID:   k,
			created: now,
			alg:     si.alg,
		}
		sps[fmt.Sprintf("sig%d", i)] = sp.canonicalize()

		signer := si.signer()
		if _, err := signer.w.Write(b.Bytes()); err != nil {
			return nil, err
		}

		if err := canonicalizeSignatureParams(signer.w, sp); err != nil {
			return nil, err
		}

		sigs[fmt.Sprintf("sig%d", i)] = base64.StdEncoding.EncodeToString(signer.sign())

		i++
	}

	// for each configured key id,
	// canonicalize signing options appended to byte slice
	// create signature

	// add new headers with params for all key ids and signatures

	// TODO: make this stable
	var parts []string
	var sigparts []string
	for k, v := range sps {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		sigparts = append(sigparts, fmt.Sprintf("%s=:%s:", k, sigs[k]))
	}

	hdr := make(http.Header)
	hdr.Set("signature-input", strings.Join(parts, ", "))
	hdr.Set("signature", strings.Join(sigparts, ", "))

	return hdr, nil
}

func signRsaPssSha512(pk *rsa.PrivateKey) sigHolder {
	return sigHolder{
		alg: "rsa-pss-sha512",
		signer: func() sigImpl {
			h := sha256.New()

			return sigImpl{
				w: h,
				sign: func() []byte {
					b := h.Sum(nil)

					// TODO: might have to deal with this error :)
					sig, _ := rsa.SignPSS(rand.Reader, pk, crypto.SHA512, b, nil)
					return sig
				},
			}
		},
	}
}

func signEccP256(pk *ecdsa.PrivateKey) sigHolder {
	return sigHolder{
		alg: "ecdsa-p256-sha256",
		signer: func() sigImpl {
			h := sha256.New()

			return sigImpl{
				w: h,
				sign: func() []byte {
					b := h.Sum(nil)

					// TODO: might have to deal with this error :)
					sig, _ := ecdsa.SignASN1(rand.Reader, pk, b)
					return sig
				},
			}
		},
	}
}

func signHmacSha256(secret []byte) sigHolder {
	// TODO: add alg description
	return sigHolder{
		signer: func() sigImpl {
			h := hmac.New(sha256.New, secret)

			return sigImpl{
				w:    h,
				sign: func() []byte { return h.Sum(nil) },
			}
		},
	}
}
