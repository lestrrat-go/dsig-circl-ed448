// Package ed448 provides Ed448 signing and verification support for the dsig library.
//
// Ed448 is not included in the main dsig module because Go's standard library
// does not support Ed448, requiring the external github.com/cloudflare/circl
// module. To avoid adding this dependency for all users, Ed448 support is
// provided as a separate module.
//
// To enable Ed448 support, import this package for its side effects:
//
//	import _ "github.com/lestrrat-go/dsig-circl-ed448"
//
// This registers an "Ed448" algorithm with dsig. After importing, dsig.Sign
// and dsig.Verify can be used with the "Ed448" algorithm name.
package ed448

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/dsig"
)

type ed448Algorithm struct{}

func init() {
	if err := dsig.RegisterAlgorithm("Ed448", dsig.AlgorithmInfo{
		Family: dsig.Custom,
		Meta:   &ed448Algorithm{},
	}); err != nil {
		panic(fmt.Sprintf("dsig-circl-ed448: failed to register Ed448: %s", err))
	}
}

func (a *ed448Algorithm) Sign(key any, payload []byte, _ io.Reader) ([]byte, error) {
	var privkey ed448.PrivateKey
	if err := ed448PrivateKey(&privkey, key); err != nil {
		return nil, fmt.Errorf(`ed448.Sign: invalid key type %T: %w`, key, err)
	}
	return ed448.Sign(privkey, payload, ""), nil
}

func (a *ed448Algorithm) Verify(key any, payload, signature []byte) error {
	var pubkey ed448.PublicKey
	if err := ed448PublicKey(&pubkey, key); err != nil {
		return fmt.Errorf(`ed448.Verify: invalid key type %T: %w`, key, err)
	}
	if !ed448.Verify(pubkey, payload, signature, "") {
		return fmt.Errorf(`ed448.Verify: invalid Ed448 signature`)
	}
	return nil
}

func ed448PrivateKey(dst *ed448.PrivateKey, src any) error {
	switch src := src.(type) {
	case ed448.PrivateKey:
		*dst = src
	case *ed448.PrivateKey:
		*dst = *src
	default:
		return fmt.Errorf(`expected ed448.PrivateKey, got %T`, src)
	}
	return nil
}

func ed448PublicKey(dst *ed448.PublicKey, src any) error {
	switch key := src.(type) {
	case ed448.PrivateKey:
		src = key.Public()
	case *ed448.PrivateKey:
		src = key.Public()
	}

	switch src := src.(type) {
	case ed448.PublicKey:
		*dst = src
	case *ed448.PublicKey:
		*dst = *src
	default:
		return fmt.Errorf(`expected ed448.PublicKey, got %T`, src)
	}
	return nil
}
