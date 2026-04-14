package testtoken_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"
)

// TestPrintNewKeyPair generates a fresh ECDSA P-256 key pair and prints
// the base64-encoded PKCS8 private key and PKIX public key. Use this to
// regenerate the default keys in keys.go if needed.
func TestPrintNewKeyPair(t *testing.T) {
	t.Skip("run manually with -run TestPrintNewKeyPair to generate keys")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Private (PKCS8 base64): %s\n", base64.StdEncoding.EncodeToString(privDER))
	fmt.Printf("Public  (PKIX base64):  %s\n", base64.StdEncoding.EncodeToString(pubDER))
}
