package ed448_test

import (
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/dsig"
	"github.com/stretchr/testify/require"

	_ "github.com/lestrrat-go/dsig-circl-ed448"
)

func TestEd448SignVerifyRoundtrip(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed448.GenerateKey(nil)
	require.NoError(t, err, "Ed448 key generation should succeed")

	payload := []byte("Ed448 roundtrip test")

	signed, err := dsig.Sign(priv, "Ed448", payload, nil)
	require.NoError(t, err, "signing should succeed")

	err = dsig.Verify(pub, "Ed448", payload, signed)
	require.NoError(t, err, "verifying should succeed")
}

func TestEd448VerifyWrongKey(t *testing.T) {
	t.Parallel()

	_, priv, err := ed448.GenerateKey(nil)
	require.NoError(t, err)

	otherPub, _, err := ed448.GenerateKey(nil)
	require.NoError(t, err)

	payload := []byte("wrong key test")

	signed, err := dsig.Sign(priv, "Ed448", payload, nil)
	require.NoError(t, err)

	err = dsig.Verify(otherPub, "Ed448", payload, signed)
	require.Error(t, err, "verifying with wrong key should fail")
}

func TestEd448InvalidKeyType(t *testing.T) {
	t.Parallel()

	payload := []byte("invalid key test")

	_, err := dsig.Sign("not a key", "Ed448", payload, nil)
	require.Error(t, err, "signing with invalid key type should fail")

	err = dsig.Verify("not a key", "Ed448", payload, []byte("fake sig"))
	require.Error(t, err, "verifying with invalid key type should fail")
}
