<!--
  Attractive html formatting for rendering in github. sorry text editor
  readers! Besides the header and section links, everything should be clean and
  readable.
-->
<h1 align="center">httpsig</h1>
<p align="center"><i>Standards-based HTTP request signing and verification for <a href="https://golang.org">Go</a></i></p>

<div align="center">
  <a href="https://godoc.org/github.com/jbowes/httpsig"><img src="https://godoc.org/github.com/jbowes/httpsig?status.svg" alt="GoDoc"></a>
  <img alt="Alpha Quality" src="https://img.shields.io/badge/status-ALPHA-orange.svg" >
  <a href="./LICENSE"><img alt="BSD license" src="https://img.shields.io/badge/license-BSD-blue.svg"></a>
  <a href="https://goreportcard.com/report/github.com/jbowes/httpsig"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/jbowes/httpsig"></a>
</div><br /><br />

## Introduction

`httpsig` provides support for signing and verifying HTTP requests according
to the [Signing HTTP Messages][msgsig] draft standard. This standard focuses
on signing headers and request paths, and you probably want to sign the
request body too, so body digest calculation according to
[Digest Headers][dighdr] is included.

Signed HTTP requests are ideal for scenarios like sending webhooks, allowing
recievers to securely verify the request came from your server, mitigate replay
attacks, etc.

Contrary to the commonly-used `x-hub-signature`, The standards implemented by
this package provide a signature of the entire request, including HTTP headers
and the request path.

## Usage

### Signing HTTP Requests in Clients

To sign HTTP requests from a client, wrap an `http.Client`'s transport with
`NewSignTransport`:

```go
client := http.Client{
	// Wrap the transport:
	Transport: httpsig.NewSignTransport(http.DefaultTransport,
		httpsig.WithSignEcdsaP256Sha256("key1", privKey)),
}

var buf bytes.Buffer

// construct body, etc
// ...

resp, err := client.Post("https://some-url.com", "application/json", &buf)
if err != nil {
	return
}
defer resp.Body.Close()

// ...
```

### Verifying HTTP Requests in Servers

To verify HTTP requests on the server, wrap the `http.Handler`s you wish to
protect with `NewVerifyMiddleware`. `NewVerifyMiddleware` returns the wrapping
func, so you can reuse configuration across multiple handlers.

```go
h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "Your request has an valid signature!")
})

middleware := httpsig.NewVerifyMiddleware(httpsig.WithVerifyEcdsaP256Sha256("key1", pubkey))
http.Handle("/", middleware(h))
```
## The Big Feature Matrix

This implementation is based on version `05` of [Signing HTTP Messages][msgsig]
(`draft-ietf-htttpbis-message-signatures-05`). Digest computation is based on
version `05` of [Digest Headers][dighdr] (`draft-ietf-httpbis-digest-headers-05`).

| Feature                         |   |   |
| ------------------------------- | - | - |
| sign requests                   | ✅ |   |
| verify requests                 | ✅ |   |
| sign responses                  |   | ❌ |
| verify responses                |   | ❌ |
| enforce `expires`               |   | ❌ |
| create multiple signatures      | ✅ |   |
| verify from multiple signatures | ✅ |   |
| `rsa-pss-sha512`                | ✅ |   |
| `rsa-v1_5-sha256`               |   | ❌ |
| `hmac-sha256`                   | ✅ |   |
| `ecdsa-p256-sha256`             | ✅ |   |
| custom signature formats        |   | ❌ |
| JSON Web Signatures             |   | ❌ |
| request digests                 | ✅ |   |
| response digests                |   | ❌ |
| multiple digests                |   | ❌ |
| digest: `sha-256`               |   | ❌ |
| digest: `sha-512`               |   | ❌ |
| digest: `md5`                   |   | ❌ |
| digest: `sha`                   |   | ❌ |
| digest: `unixsum`               |   | ❌ |
| digest: `unixcksum`             |   | ❌ |
| digest: `id-sha-512`            |   | ❌ |
| digest: `id-sha-256`            | ✅ |   |
| custom digest formats           |   | ❌ |

## Contributing

I would love your help!

`httpsig` is still a work in progress. You can help by:

- Opening a pull request to resolve an [open issue][issues].
- Adding a feature or enhancement of your own! If it might be big, please
  [open an issue][enhancement] first so we can discuss it.
- Improving this `README` or adding other documentation to `httpsig`.
- Letting [me] know if you're using `httpsig`.


<!-- Other links -->
[go]: https://golang.org
[msgsig]: https://datatracker.ietf.org/doc/draft-ietf-httpbis-message-signatures/
[dighdr]: https://datatracker.ietf.org/doc/draft-ietf-httpbis-digest-headers/

[issues]: ./issues
[bug]: ./issues/new?labels=bug
[enhancement]: ./issues/new?labels=enhancement

[me]: https://twitter.com/jrbowes