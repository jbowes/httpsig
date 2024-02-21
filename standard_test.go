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

func testReq() *Message {
	return &Message{
		Method:    "POST",
		Authority: "example.com",
		URL:       parse("https://example.com/foo?param=value&pet=dog"),
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

	s := &Signer{
		headers: []string{"@authority", "date", "content-type"},
		keys: map[string]SigHolder{
			"test-shared-secret": SignHmacSha256(k),
		},

		nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
	}

	hdr, err := s.Sign(testReq())
	if err != nil {
		t.Error("signing failed:", err)
	}

	if hdr.Get("Signature-Input") != `sig1=("@authority" "date" "content-type");created=1618884475;keyid="test-shared-secret"` {
		t.Error("signature input did not match. Got:", hdr.Get("Signature-Input"))
	}

	if hdr.Get("Signature") != `sig1=:fN3AMNGbx0V/cIEKkZOvLOoC3InI+lM2+gTv22x3ia8=:` {
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
	req.Header.Set("Signature", `sig1=:HWP69ZNiom9Obu1KIdqPPcu/C1a5ZUMBbqS/xwJECV8bhIQVmEAAAzz8LQPvtP1iFSxxluDO1KE9b8L+O64LEOvhwYdDctV5+E39Jy1eJiD7nYREBgxTpdUfzTO+Trath0vZdTylFlxK4H3l3s/cuFhnOCxmFYgEa+cw+StBRgY1JtafSFwNcZgLxVwialuH5VnqJS4JN8PHD91XLfkjMscTo4jmVMpFd3iLVe0hqVFl7MDt6TMkwIyVFnEZ7B/VIQofdShO+C/7MuupCSLVjQz5xA+Zs6Hw+W9ESD/6BuGs6LF1TcKLxW+5K+2zvDY/Cia34HNpRW5io7Iv9/b7iQ==:`)

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
	req.Header.Set("Signature-Input", `sig1=("@authority" content-type");created=1618884475;keyid="test-key-rsa-pss"`)
	req.Header.Set("Signature", `sig1=:ik+OtGmM/kFqENDf9Plm8AmPtqtC7C9a+zYSaxr58b/E6h81ghJS3PcH+m1asiMp8yvccnO/RfaexnqanVB3C72WRNZN7skPTJmUVmoIeqZncdP2mlfxlLP6UbkrgYsk91NS6nwkKC6RRgLhBFqzP42oq8D2336OiQPDAo/04SxZt4Wx9nDGuy2SfZJUhsJqZyEWRk4204x7YEB3VxDAAlVgGt8ewilWbIKKTOKp3ymUeQIwptqYwv0l8mN404PPzRBTpB7+HpClyK4CNp+SVv46+6sHMfJU4taz10s/NoYRmYCGXyadzYYDj0BYnFdERB6NblI/AOWFGl5Axhhmjg==:`)

	err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestVerify_B_2_3(t *testing.T) {
	t.Skip("not working as of draft 06 changes")
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
	req.Header.Set("Signature-Input", `sig1=("date" "@method" "@path" "@query" "@authority" "content-type" "digest" "content-length");created=1618884475;keyid="test-key-rsa-pss"`)
	req.Header.Set("Signature", `sig1=:JuJnJMFGD4HMysAGsfOY6N5ZTZUknsQUdClNG51VezDgPUOW03QMe74vbIdndKwW1BBrHOHR3NzKGYZJ7X3ur23FMCdANe4VmKb3Rc1Q/5YxOO8p7KoyfVa4uUcMk5jB9KAn1M1MbgBnqwZkRWsbv8ocCqrnD85Kavr73lx51k1/gU8w673WT/oBtxPtAn1eFjUyIKyA+XD7kYph82I+ahvm0pSgDPagu917SlqUjeaQaNnlZzO03Iy1RZ5XpgbNeDLCqSLuZFVID80EohC2CQ1cL5svjslrlCNstd2JCLmhjL7xV3NYXerLim4bqUQGRgDwNJRnqobpS6C1NBns/Q==:`)
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
		req.Header.Set("Signature-Input", `sig1=("content-type" "digest" "content-length");created=1618884475;keyid="test-key-ecc-p256"`)
		req.Header.Set("Signature", `sig1=:n8RKXkj0iseWDmC6PNSQ1GX2R9650v+lhbb6rTGoSrSSx18zmn6fPOtBx48/WffYLO0n1RHHf9scvNGAgGq52Q==:`)
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
	req.Header.Set("Signature-Input", `sig1=("@authority" "date" "content-type");created=1618884475;keyid="test-shared-secret"`)
	req.Header.Set("Signature", `sig1=:fN3AMNGbx0V/cIEKkZOvLOoC3InI+lM2+gTv22x3ia8=:`)

	err = v.Verify(req)
	if err != nil {
		t.Error("verification failed:", err)
	}
}

func TestVerify_AudioHook(t *testing.T) {
	k, err := base64.StdEncoding.DecodeString("TXlTdXBlclNlY3JldEtleVRlbGxOby0xITJAMyM0JDU=")
	if err != nil {
		panic("could not decode test shared secret")
	}

	v := &verifier{
		keys: map[string]verHolder{
			"SGVsbG8sIEkgYW0gdGhlIEFQSSBrZXkh": verifyHmacSha256(k),
		},

		nowFunc: func() time.Time { return time.Unix(1618884475, 0) },
	}

	req := testReq()
	req.URL = parse("/api/v1/voicebiometrics/ws")
	req.Authority = "audiohook.example.com"
	req.Header.Set("Host", "audiohook.example.com")
	req.Header.Set("Audiohook-Organization-Id", "d7934305-0972-4844-938e-9060eef73d05")
	req.Header.Set("Audiohook-Correlation-Id", "e160e428-53e2-487c-977d-96989bf5c99d")
	req.Header.Set("Audiohook-Session-Id", "30b0e395-84d3-4570-ac13-9a62d8f514c0")
	req.Header.Set("X-API-KEY", "SGVsbG8sIEkgYW0gdGhlIEFQSSBrZXkh")
	req.Header.Set("Signature-Input", `sig1=("@request-target" "@authority" "audiohook-organization-id" "audiohook-session-id" "audiohook-correlation-id" "x-api-key");keyid="SGVsbG8sIEkgYW0gdGhlIEFQSSBrZXkh";nonce="VGhpc0lzQVVuaXF1ZU5vbmNl";alg="hmac-sha256";created=1641013200;expires=3282026430`)
	req.Header.Set("Signature", `sig1=:NZBwyBHRRyRoeLqy1IzOa9VYBuI8TgMFt2GRDkDuJh4=:`)

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
