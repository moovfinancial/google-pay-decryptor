// Copyright (c) 2022 Rakhat

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package decrypt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/google/tink/go/hybrid/subtle"
	"github.com/stretchr/testify/assert"
	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt"
)

func TestLoadEphemeralPublicKey(t *testing.T) {
	curve, err := subtle.GetCurve(decrypt.GooglePayECCType)
	if err != nil {
		t.Error(err)
	}
	privKey, err := subtle.GenerateECDHKeyPair(curve)
	if err != nil {
		t.Error(err)
	}

	encoded, err := subtle.PointEncode(curve, decrypt.GooglePayUncompressedFormat, privKey.PublicKey.Point)
	if err != nil {
		t.Error(err)
	}

	encodedBase64 := base64.StdEncoding.EncodeToString(encoded)
	var pk decrypt.PublicKey
	ephemeralPK, err := pk.LoadEphemeralPublicKey(encodedBase64)
	if err != nil {
		t.Error(err)
	}

	if !assert.Equal(t, &privKey.PublicKey.Point, ephemeralPK) {
		t.Errorf("loaded key is incorrect or does not match")
	}
}

func TestLoadPublicKey(t *testing.T) {
	curve, _ := subtle.GetCurve(decrypt.GooglePayECCType)
	generated, _ := subtle.GenerateECDHKeyPair(curve)
	converted := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     generated.PublicKey.Point.X,
		Y:     generated.PublicKey.Point.Y,
	}
	encoded, err := x509.MarshalPKIXPublicKey(converted)
	if err != nil {
		t.Logf("error occured while marshaling to pkix: %s", err)
	}

	encodedBase64 := base64.StdEncoding.EncodeToString(encoded)
	var pk *decrypt.PublicKey
	publicKey, err := pk.LoadPublicKey(encodedBase64)
	if err != nil {
		t.Fatalf("error loading key: %s", err)
	}

	if !assert.Equal(t, converted, publicKey) {
		t.Errorf("loaded key is incorrect or does not match")
	}
}

func TestLoadPublicKey_InvalidKeyType(t *testing.T) {
	// Create an RSA public key instead of ECDSA
	rsaKey := &rsa.PublicKey{
		N: big.NewInt(123),
		E: 65537,
	}

	encoded, err := x509.MarshalPKIXPublicKey(rsaKey)
	if err != nil {
		t.Fatalf("error marshaling RSA key: %s", err)
	}

	encodedBase64 := base64.StdEncoding.EncodeToString(encoded)
	var pk decrypt.PublicKey
	_, err = pk.LoadPublicKey(encodedBase64)

	if err == nil {
		t.Fatal("expected error when loading non-ECDSA key")
	}
	if err != decrypt.ErrPublicKey {
		t.Errorf("expected ErrPublicKey, got %v", err)
	}
}

func TestLoadEphemeralPublicKey_InvalidCurve(t *testing.T) {
	// Create a valid base64 string with the correct point format and coordinates
	data := make([]byte, 65)
	data[0] = 0x04 // Uncompressed point format
	for i := 1; i < 65; i++ {
		data[i] = byte(i) // Fill with some valid-looking data
	}
	validBase64 := base64.StdEncoding.EncodeToString(data)

	// Create a new PublicKey instance
	pk := &decrypt.PublicKey{}

	// Call LoadEphemeralPublicKey which internally uses GetCurve
	_, err := pk.LoadEphemeralPublicKey(validBase64)

	// Verify that the error is propagated
	if err == nil {
		t.Fatal("expected error to be propagated")
	}
}
