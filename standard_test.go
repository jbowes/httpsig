// Copyright (c) 2021 James Bowes. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpsig

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// These tests come from the sample data in the draft standard.
// Most of the signing tests aren't applicable, as the signatures contain some randomness.
// B_*_* map to sections in the standard.

func parse(in string) *url.URL {
	out, err := url.Parse(in)
	if err != nil {
		panic("couldn't parse static url for test!")
	}
	return out
}

func testReq() *message {
	return &message{
		Method: "POST",
		URL:    parse("https://example.com/foo?param=value&pet=dog"),
		Header: http.Header{
			"Host":           []string{"example.com"},
			"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
			"Content-Type":   []string{"application/json"},
			"Digest":         []string{"SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="},
			"Content-Length": []string{"18"},
		},
	}
}

func TestSign_B_2_5(t *testing.T) {
	k, err := base64.StdEncoding.DecodeString(testSharedSecret)
	if err != nil {
		panic("could not decode test shared secret")
	}

	s := &signer{
		headers: []string{"host", "date", "content-type"},
		keys: map[string]sigHolder{
			"test-shared-secret": signHmacSha256(k),
		},

		nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
	}

	hdr, err := s.Sign(testReq())
	if err != nil {
		t.Error("signing failed:", err)
	}

	if hdr.Get("Signature-Input") != `sig1=("host" "date" "content-type");created=1618884475;keyid="test-shared-secret"` {
		t.Error("signature input did not match. Got:", hdr.Get("Signature-Input"))
	}

	if hdr.Get("Signature") != `sig1=:x54VEvVOb0TMw8fUbsWdUHqqqOre+K7sB/LqHQvnfaQ=:` {
		t.Error("signature did not match. Got:", hdr.Get("Signature"))
	}
}

func TestVerify_B_2_1(t *testing.T) {
	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	if block == nil {
		panic("could not decode test public key pem")
	}

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("could not decode test public key: " + err.Error())
	}

	pk := pki.(*rsa.PublicKey)

	v := &verifier{
		keys: map[string]verHolder{
			"test-key-rsa-pss": verifyRsaPssSha512(pk),
		},

		nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
	}

	req := testReq()
	req.Header.Set("Signature-Input", `sig1=();created=1618884475;keyid="test-key-rsa-pss";alg="rsa-pss-sha512"`)
	req.Header.Set("Signature", `sig1=:VrfdC2KEFFLoGMYTbQz4PSlKat4hAxcr5XkVN7Mm/7OQQJG+uXgOez7kA6n/yTCaR1VL+FmJd2IVFCsUfcc/jO9siZK3siadoK1Dfgp2ieh9eO781tySS70OwvAkdORuQLWDnaDMRDlQhg5sNP6JaQghFLqD4qgFrM9HMPxLrznhAQugJ0FdRZLtSpnjECW6qsu2PVRoCYfnwe4gu8TfqH5GDx2SkpCF9BQ8CijuIWlOg7QP73tKtQNp65u14Si9VEVXHWGiLw4blyPLzWz/fqJbdLaq94Ep60Nq8WjYEAInYH6KyV7EAD60LXdspwF50R3dkWXJP/x+gkAHSMsxbg==:`)

	err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestVerify_B_2_2(t *testing.T) {
	// TODO: key parsing is duplicated
	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	if block == nil {
		panic("could not decode test public key pem")
	}

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("could not decode test public key: " + err.Error())
	}

	pk := pki.(*rsa.PublicKey)

	v := &verifier{
		keys: map[string]verHolder{
			"test-key-rsa-pss": verifyRsaPssSha512(pk),
		},

		nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
	}

	req := testReq()
	req.Header.Set("Signature-Input", `sig1=("host" "date" "content-type");created=1618884475;keyid="test-key-rsa-pss"`)
	req.Header.Set("Signature", `sig1=:Zu48JBrHlXN+hVj3T5fPQUjMNEEhABM5vNmiWuUUl7BWNid5RzOH1tEjVi+jObYkYT8p09lZ2hrNuU3xm+JUBT8WNIlopJtt0EzxFnjGlHvkhu3KbJfxNlvCJVlOEdR4AivDLMeK/ZgASpZ7py1UNHJqRyGCYkYpeedinXUertL/ySNp+VbK2O/qCoui2jFgff2kXQd6rjL1Up83Fpr+/KoZ6HQkv3qwBdMBDyHQykfZHhLn4AO1IG+vKhOLJQDfaLsJ/fYfzsgc1s46j3GpPPD/W2nEEtdhNwu7oXq81qVRsENChIu1XIFKR9q7WpyHDKEWTtaNZDS8TFvIQRU22w==:`)

	err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestVerify_B_2_3(t *testing.T) {
	// TODO: key parsing is duplicated
	block, _ := pem.Decode([]byte(testKeyRSAPSSPub))
	if block == nil {
		panic("could not decode test public key pem")
	}

	pki, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic("could not decode test public key: " + err.Error())
	}

	pk := pki.(*rsa.PublicKey)

	v := &verifier{
		keys: map[string]verHolder{
			"test-key-rsa-pss": verifyRsaPssSha512(pk),
		},

		nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
	}

	req := testReq()
	req.Header.Set("Signature-Input", `sig1=("@request-target" "host" "date" "content-type" "digest" "content-length");created=1618884475;keyid="test-key-rsa-pss"`)
	req.Header.Set("Signature", `sig1=:iD5NhkJoGSuuTpWMzS0BI47DfbWwsGmHHLTwOxT0n+0cQFSC+1c26B7IOfIRTYofqD0sfYYrnSwCvWJfA1zthAEv9J1CxS/CZXe7CQvFpuKuFJxMpkAzVYdE/TA6fELxNZy9RJEWZUPBU4+aJ26d8PC0XhPObXe6JkP6/C7XvG2QinsDde7rduMdhFN/Hj2MuX1Ipzvv4EgbHJdKwmWRNamfmKJZC4U5Tn0F58lzGF+WIpU73V67/6aSGvJGM57U9bRHrBB7ExuQhOX2J2dvJMYkE33pEJA70XBUp9ZvciTI+vjIUgUQ2oRww3huWMLmMMqEc95CliwIoL5aBdCnlQ==:`)
	err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestVerify_B_2_4(t *testing.T) {
	t.Skip("not working yet")
	/*
		block, _ := pem.Decode([]byte(testKeyECCP256Pub))
		if block == nil {
			panic("could not decode test public key pem")
		}

		pk, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			panic("could not decode test public key: " + err.Error())
		}

		v := &verifier{
			keys: map[string]verHolder{
				"test-key-ecc-p256": verifyEccP256(pk.(*ecdsa.PublicKey)),
			},

			nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
		}

		req := testReq()
		req.Header.Set("Signature-Input", `sig1=("date" "content-type" "digest" "content-length");created=1618884475;keyid="test-key-ecc-p256"`)
		req.Header.Set("Signature", `sig1=:3zmRDW6r50/RETqqhtx/N5sdd5eTh8xmHdsrYRK9wK4rCNEwLjCOBlcQxTL2oJTCWGRkuqE2r9KyqZFY9jd+NQ==:`)
		err = v.Verify(req)
		if err != nil {
			t.Error("verification failed:", err)
		}
	*/
}

func TestVerify_B_2_5(t *testing.T) {
	k, err := base64.StdEncoding.DecodeString(testSharedSecret)
	if err != nil {
		panic("could not decode test shared secret")
	}

	v := &verifier{
		keys: map[string]verHolder{
			"test-shared-secret": verifyHmacSha256(k),
		},

		nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
	}

	req := testReq()
	req.Header.Set("Signature-Input", `sig1=("host" "date" "content-type");created=1618884475;keyid="test-shared-secret"`)
	req.Header.Set("Signature", `sig1=:x54VEvVOb0TMw8fUbsWdUHqqqOre+K7sB/LqHQvnfaQ=:`)

	err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

// The following keypairs are taken from the Draft Standard, so we may recreate the examples in tests.
// If your robot scans this repo and says it's leaking keys I will be mildly amused.

/*

var testKeyRSA = `
-----BEGIN RSA PRIVATE KEY-----
MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
-----END RSA PRIVATE KEY-----
`

var testKeyRSAPSS = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
rOjr9w349JooGXhOxbu8nOxX
-----END PRIVATE KEY-----
`
*/

var testKeyRSAPSSPub = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----
   `

/*
var testKeyECCP256 = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----
`

var testKeyECCP256Pub = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----
`
*/

var testSharedSecret = `uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==`
