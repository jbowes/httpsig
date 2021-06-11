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

## The Big Feature Matrix

This implementation is based on version `05` of "Signing HTTP Messages" 
(`draft-ietf-htttpbis-message-signatures-05`). Digest computation is based on
version `05` of "Digest Headers" (`draft-ietf-httpbis-digest-headers-05`).

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