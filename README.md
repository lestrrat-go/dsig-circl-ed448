# github.com/lestrrat-go/jwx-circl-ed448 [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx-circl-ed448.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx-circl-ed448)

Ed448 signing/verification and JWK support for [github.com/lestrrat-go/jwx/v3](https://github.com/lestrrat-go/jwx), powered by [cloudflare/circl](https://github.com/cloudflare/circl).

# Why a separate module?

Go's standard library does not include Ed448 support. The only viable implementation comes from `github.com/cloudflare/circl`, which is a large dependency. Rather than forcing every `jwx` user to pull in `circl`, Ed448 support is provided as an opt-in companion module.

# Synopsis

Import this package for its side effects to register Ed448 with `jwx`:

<!-- INCLUDE(example_test.go) -->
```go
package ed448_test

import (
  "encoding/json"
  "fmt"

  "github.com/cloudflare/circl/sign/ed448"
  "github.com/lestrrat-go/jwx/v3/jwa"
  "github.com/lestrrat-go/jwx/v3/jwk"
  "github.com/lestrrat-go/jwx/v3/jws"

  _ "github.com/lestrrat-go/jwx-circl-ed448"
)

func Example() {
  // Generate an Ed448 key pair
  pub, priv, err := ed448.GenerateKey(nil)
  if err != nil {
    fmt.Printf("failed to generate key: %s\n", err)
    return
  }

  payload := []byte("Hello, Ed448!")

  // Sign and verify with raw keys
  signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd448(), priv))
  if err != nil {
    fmt.Printf("failed to sign: %s\n", err)
    return
  }

  verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd448(), pub))
  if err != nil {
    fmt.Printf("failed to verify: %s\n", err)
    return
  }
  fmt.Printf("%s\n", verified)

  // Import raw keys into JWK
  jwkPriv, err := jwk.Import(priv)
  if err != nil {
    fmt.Printf("failed to import private key: %s\n", err)
    return
  }

  jwkPub, err := jwk.Import(pub)
  if err != nil {
    fmt.Printf("failed to import public key: %s\n", err)
    return
  }

  // Sign and verify with JWK keys
  signed, err = jws.Sign(payload, jws.WithKey(jwa.EdDSAEd448(), jwkPriv))
  if err != nil {
    fmt.Printf("failed to sign with JWK key: %s\n", err)
    return
  }

  verified, err = jws.Verify(signed, jws.WithKey(jwa.EdDSAEd448(), jwkPub))
  if err != nil {
    fmt.Printf("failed to verify with JWK key: %s\n", err)
    return
  }
  fmt.Printf("%s\n", verified)

  // JWK JSON round-trip
  buf, err := json.MarshalIndent(jwkPriv, "", "  ")
  if err != nil {
    fmt.Printf("failed to marshal JWK: %s\n", err)
    return
  }

  parsed, err := jwk.ParseKey(buf)
  if err != nil {
    fmt.Printf("failed to parse JWK: %s\n", err)
    return
  }
  _ = parsed

  // Output:
  // Hello, Ed448!
  // Hello, Ed448!
}
```
source: [example_test.go](https://github.com/lestrrat-go/jwx-circl-ed448/blob/main/example_test.go)
<!-- END INCLUDE -->

# Installation

```
go get github.com/lestrrat-go/jwx-circl-ed448
```
