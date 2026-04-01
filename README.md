# github.com/lestrrat-go/jwx-circl-ed448 [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/jwx-circl-ed448.svg)](https://pkg.go.dev/github.com/lestrrat-go/jwx-circl-ed448)

Ed448 signing/verification and JWK support for [github.com/lestrrat-go/jwx/v3](https://github.com/lestrrat-go/jwx), powered by [cloudflare/circl](https://github.com/cloudflare/circl).

# Why a separate module?

Go's standard library does not include Ed448 support. The only viable implementation comes from `github.com/cloudflare/circl`, which is a large dependency. Rather than forcing every `jwx` user to pull in `circl`, Ed448 support is provided as an opt-in companion module.

# Synopsis

Import this package for its side effects to register Ed448 with `jwx`:

```go
package main

import (
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	_ "github.com/lestrrat-go/jwx-circl-ed448" // register Ed448
)

func main() {
	pub, priv, err := ed448.GenerateKey(nil)
	if err != nil {
		fmt.Printf("failed to generate key: %s\n", err)
		return
	}

	// Sign and verify with raw keys
	signed, err := jws.Sign([]byte("hello"), jws.WithKey(jwa.EdDSAEd448(), priv))
	if err != nil {
		fmt.Printf("failed to sign: %s\n", err)
		return
	}

	payload, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd448(), pub))
	if err != nil {
		fmt.Printf("failed to verify: %s\n", err)
		return
	}
	fmt.Printf("%s\n", payload)

	// Import into JWK
	jwkKey, err := jwk.Import(priv)
	if err != nil {
		fmt.Printf("failed to import key: %s\n", err)
		return
	}
	_ = jwkKey
}
```

# What gets registered

The blank import (`_ "github.com/lestrrat-go/jwx-circl-ed448"`) registers the following in the `jwx` ecosystem via its `init()` function:

* **JWS sign/verify** -- `jwa.EdDSAEd448()` can be used with `jws.Sign` and `jws.Verify`
* **JWK import/export** -- `ed448.PublicKey` and `ed448.PrivateKey` can be used with `jwk.Import` and `jwk.Export`
* **JWK OKP curve builders** -- JWK JSON round-tripping works for `"crv": "Ed448"` keys
* **Algorithm-key mapping** -- `jwa.EdDSAEd448()` is associated with `jwa.OKP()` key type

# Installation

```
go get github.com/lestrrat-go/jwx-circl-ed448
```
