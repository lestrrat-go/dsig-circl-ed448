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
