package ed448_test

import (
	"encoding/json"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/stretchr/testify/require"

	_ "github.com/lestrrat-go/jwx-circl-ed448"
)

func TestEd448SignVerifyRoundtrip(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed448.GenerateKey(nil)
	require.NoError(t, err, "Ed448 key generation should succeed")

	payload := []byte("Ed448 roundtrip test")

	t.Run("raw keys", func(t *testing.T) {
		t.Parallel()
		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd448(), priv))
		require.NoError(t, err, "signing should succeed")

		verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd448(), pub))
		require.NoError(t, err, "verifying should succeed")
		require.Equal(t, payload, verified)
	})

	t.Run("JWK keys", func(t *testing.T) {
		t.Parallel()
		jwkPriv, err := jwk.Import(priv)
		require.NoError(t, err, "importing Ed448 private key should succeed")

		jwkPub, err := jwk.Import(pub)
		require.NoError(t, err, "importing Ed448 public key should succeed")

		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd448(), jwkPriv))
		require.NoError(t, err, "signing with JWK key should succeed")

		verified, err := jws.Verify(signed, jws.WithKey(jwa.EdDSAEd448(), jwkPub))
		require.NoError(t, err, "verifying with JWK key should succeed")
		require.Equal(t, payload, verified)
	})

	t.Run("alg header is Ed448", func(t *testing.T) {
		t.Parallel()
		signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSAEd448(), priv))
		require.NoError(t, err)

		msg, err := jws.Parse(signed)
		require.NoError(t, err)
		sigs := msg.Signatures()
		require.Len(t, sigs, 1)
		alg, ok := sigs[0].ProtectedHeaders().Algorithm()
		require.True(t, ok)
		require.Equal(t, jwa.EdDSAEd448(), alg)
	})
}

func TestEd448JWKRoundtrip(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed448.GenerateKey(nil)
	require.NoError(t, err)

	t.Run("public key import/export", func(t *testing.T) {
		t.Parallel()
		jwkKey, err := jwk.Import(pub)
		require.NoError(t, err)

		crv, ok := jwkKey.(jwk.OKPPublicKey).Crv()
		require.True(t, ok)
		require.Equal(t, jwa.Ed448(), crv)

		var exported ed448.PublicKey
		require.NoError(t, jwk.Export(jwkKey, &exported))
		require.Equal(t, pub, exported)
	})

	t.Run("private key import/export", func(t *testing.T) {
		t.Parallel()
		jwkKey, err := jwk.Import(priv)
		require.NoError(t, err)

		crv, ok := jwkKey.(jwk.OKPPrivateKey).Crv()
		require.True(t, ok)
		require.Equal(t, jwa.Ed448(), crv)

		var exported ed448.PrivateKey
		require.NoError(t, jwk.Export(jwkKey, &exported))
		require.Equal(t, priv.Seed(), exported.Seed())
	})

	t.Run("JSON roundtrip", func(t *testing.T) {
		t.Parallel()
		jwkKey, err := jwk.Import(priv)
		require.NoError(t, err)

		buf, err := json.Marshal(jwkKey)
		require.NoError(t, err)

		parsedKey, err := jwk.ParseKey(buf)
		require.NoError(t, err)

		var exported ed448.PrivateKey
		require.NoError(t, jwk.Export(parsedKey, &exported))
		require.Equal(t, priv.Seed(), exported.Seed())
	})
}
