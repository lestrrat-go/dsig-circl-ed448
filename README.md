# github.com/lestrrat-go/dsig-circl-ed448 [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/dsig-circl-ed448.svg)](https://pkg.go.dev/github.com/lestrrat-go/dsig-circl-ed448)

Ed448 signing/verification support for [github.com/lestrrat-go/dsig](https://github.com/lestrrat-go/dsig), powered by [cloudflare/circl](https://github.com/cloudflare/circl).

# Why a separate module?

Go's standard library does not include Ed448 support. The only viable implementation comes from `github.com/cloudflare/circl`, which is a large dependency. Rather than forcing every `dsig` user to pull in `circl`, Ed448 support is provided as an opt-in companion module.

# Synopsis

Import this package for its side effects to register Ed448 with `dsig`:

<!-- INCLUDE(example_test.go) -->
```go
package ed448_test

import (
  "fmt"

  "github.com/cloudflare/circl/sign/ed448"
  "github.com/lestrrat-go/dsig"

  _ "github.com/lestrrat-go/dsig-circl-ed448"
)

func Example() {
  // Generate an Ed448 key pair
  pub, priv, err := ed448.GenerateKey(nil)
  if err != nil {
    fmt.Printf("failed to generate key: %s\n", err)
    return
  }

  payload := []byte("Hello, Ed448!")

  // Sign with Ed448 private key
  signature, err := dsig.Sign(priv, "Ed448", payload, nil)
  if err != nil {
    fmt.Printf("failed to sign: %s\n", err)
    return
  }

  // Verify with Ed448 public key
  if err := dsig.Verify(pub, "Ed448", payload, signature); err != nil {
    fmt.Printf("failed to verify: %s\n", err)
    return
  }
  fmt.Println("signature verified")

  // Output:
  // signature verified
}
```
source: [example_test.go](https://github.com/lestrrat-go/dsig-circl-ed448/blob/main/example_test.go)
<!-- END INCLUDE -->

# Installation

```
go get github.com/lestrrat-go/dsig-circl-ed448
```
