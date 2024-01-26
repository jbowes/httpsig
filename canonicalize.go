// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	nurl "net/url"
	"strconv"
	"strings"
	"time"
)

// Message is a minimal representation of an HTTP request or response, containing the values
// needed to construct a signature.
type Message struct {
	Method    string
	Authority string
	URL       *nurl.URL
	Header    http.Header
}

func MessageFromRequest(r *http.Request) *Message {
	hdr := r.Header.Clone()
	hdr.Set("Host", r.Host)
	return &Message{
		Method:    r.Method,
		Authority: r.Host,
		URL:       r.URL,
		Header:    hdr,
	}
}

func canonicalizeHeader(out io.Writer, name string, hdr http.Header) error {
	// XXX: Structured headers are not considered, and they should be :)
	v := hdr.Values(name)
	if len(v) == 0 { // empty values are permitted, but no values are not
		return fmt.Errorf("'%s' header not found", name)
	}

	// Section 2.1 covers canonicalizing headers.
	// Section 2.4 step 2 covers using them as input.
	vc := make([]string, 0, len(v))
	for _, sv := range v {
		vc = append(vc, strings.TrimSpace(sv))
	}
	_, err := fmt.Fprintf(out, "\"%s\": %s\n", strings.ToLower(name), strings.Join(vc, ", "))
	return err
}

func canonicalizeMethod(out io.Writer, method string) error {
	// Section 2.3.2 covers canonicalization of the method.
	// Section 2.4 step 2 covers using it as input.
	_, err := fmt.Fprintf(out, "\"@method\": %s\n", strings.ToUpper(method)) // Method should always be caps.
	return err
}

func canonicalizeAuthority(out io.Writer, authority string) error {
	// Section 2.3.4 covers canonicalization of the authority.
	// Section 2.4 step 2 covers using it as input.
	_, err := fmt.Fprintf(out, "\"@authority\": %s\n", authority)
	return err
}

func canonicalizePath(out io.Writer, path string) error {
	// Section 2.3.7 covers canonicalization of the path.
	// Section 2.4 step 2 covers using it as input.
	_, err := fmt.Fprintf(out, "\"@path\": %s\n", path)
	return err
}

func canonicalizeRequestTarget(out io.Writer, requestTarget string) error {
	// Section 2.2.5 (v19) covers canonicalization of the path.
	// Section 2.4 step 2 covers using it as input.
	_, err := fmt.Fprintf(out, "\"@request-target\": %s\n", requestTarget)
	return err
}

func canonicalizeQuery(out io.Writer, rawQuery string) error {
	// Section 2.3.8 covers canonicalization of the query.
	// Section 2.4 step 2 covers using it as input.
	_, err := fmt.Fprintf(out, "\"@query\": ?%s\n", rawQuery) // TODO: decode percent encodings
	return err
}

func canonicalizeSignatureParams(out io.Writer, sp *signatureParams) error {
	// Section 2.3.1 covers canonicalization of the signature parameters

	// TODO: Deal with all the potential print errs. sigh.

	_, err := fmt.Fprintf(out, "\"@signature-params\": %s", sp.canonicalize())
	if err != nil {
		return err
	}

	return err
}

type signatureParams struct {
	items       []string
	paramsOrder []string
	keyID       string
	alg         string
	created     time.Time
	expires     *time.Time
	nonce       string
}

func (sp *signatureParams) canonicalize() string {
	li := make([]string, 0, len(sp.items))
	for _, i := range sp.items {
		li = append(li, fmt.Sprintf("\"%s\"", strings.ToLower(i)))
	}
	o := fmt.Sprintf("(%s)", strings.Join(li, " "))

	// Items comes first. The params afterwards can be in any order. The order chosen here
	// matches what's in the examples in the standard, aiding in testing.
	for _, param := range sp.paramsOrder {
		switch param {
		case "created":
			o += fmt.Sprintf(";created=%d", sp.created.Unix())
		case "expires":
			o += fmt.Sprintf(";expires=%d", sp.expires.Unix())
		case "keyid":
			o += fmt.Sprintf(";keyid=\"%s\"", sp.keyID)
		case "alg":
			o += fmt.Sprintf(";alg=\"%s\"", sp.alg)
		case "nonce":
			o += fmt.Sprintf(";nonce=\"%s\"", sp.nonce)
		}
	}

	return o
}

var errMalformedSignatureInput = errors.New("malformed signature-input header")

func parseSignatureInput(in string) (*signatureParams, error) {
	sp := &signatureParams{}

	parts := strings.Split(in, ";")
	if len(parts) < 1 {
		return nil, errMalformedSignatureInput
	}

	if parts[0][0] != '(' || parts[0][len(parts[0])-1] != ')' {
		return nil, errMalformedSignatureInput
	}

	if len(parts[0]) > 2 { // not empty
		// TODO: headers can't have spaces, but it should still be handled
		items := strings.Split(parts[0][1:len(parts[0])-1], " ")

		// TODO: error when not quoted
		for i := range items {
			items[i] = strings.Trim(items[i], `"`)
		}

		sp.items = items
	}

	for _, param := range parts[1:] {
		// keyid can be base64 encoded, so it can have = symbols at the end
		paramParts := strings.SplitN(param, "=", 2)

		sp.paramsOrder = append(sp.paramsOrder, paramParts[0])

		// TODO: error when not wrapped in quotes
		switch paramParts[0] {
		case "alg":
			sp.alg = strings.Trim(paramParts[1], `"`)
		case "keyid":
			sp.keyID = strings.Trim(paramParts[1], `"`)
		case "nonce":
			sp.nonce = strings.Trim(paramParts[1], `"`)
		case "created":
			i, err := strconv.ParseInt(paramParts[1], 10, 64)
			if err != nil {
				return nil, errMalformedSignatureInput
			}
			sp.created = time.Unix(i, 0)
		case "expires":
			i, err := strconv.ParseInt(paramParts[1], 10, 64)
			if err != nil {
				return nil, errMalformedSignatureInput
			}
			t := time.Unix(i, 0)
			sp.expires = &t
		default:
			// TODO: unknown params could be kept? hard to say.
			return nil, errMalformedSignatureInput
		}
	}

	return sp, nil
}
