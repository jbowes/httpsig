// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// HTTP digest headers support according to the draft standard
// https://datatracker.ietf.org/doc/draft-ietf-httpbis-digest-headers/

// TODO: support more algorithms, and maybe do its own package.

func calcDigest(in []byte) string {
	dig := sha256.Sum256(in)

	return fmt.Sprintf("id-sha256=%s", base64.StdEncoding.EncodeToString(dig[:]))
}

func verifyDigest(in []byte, dig string) bool {
	// TODO: case insensitity for incoming digest?
	calc := calcDigest(in)

	return subtle.ConstantTimeCompare([]byte(dig), []byte(calc)) == 0
}
