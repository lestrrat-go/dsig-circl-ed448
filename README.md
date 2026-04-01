# github.com/lestrrat-go/jwx-circl-ed448 [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx-circl-ed448.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx-circl-ed448)

Ed448 signing/verification and JWK support for [github.com/lestrrat-go/jwx/v3](https://github.com/lestrrat-go/jwx), powered by [cloudflare/circl](https://github.com/cloudflare/circl).

# Why a separate module?

Go's standard library does not include Ed448 support. The only viable implementation comes from `github.com/cloudflare/circl`, which is a large dependency. Rather than forcing every `jwx` user to pull in `circl`, Ed448 support is provided as an opt-in companion module.

# Synopsis

Import this package for its side effects to register Ed448 with `jwx`:

<!-- INCLUDE(example_test.go) -->
```go
```
<!-- END INCLUDE -->

# Installation

```
go get github.com/lestrrat-go/jwx-circl-ed448
```
