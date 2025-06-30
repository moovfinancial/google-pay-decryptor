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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/google/tink/go/hybrid/subtle"
	"github.com/stretchr/testify/assert"
	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt"
)

func TestLoadKey(t *testing.T) {
	curve, _ := subtle.GetCurve(decrypt.GooglePayECCType)
	generated, _ := subtle.GenerateECDHKeyPair(curve)
	converted := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     generated.PublicKey.Point.X,
			Y:     generated.PublicKey.Point.Y,
		},
		D: generated.D,
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(converted)
	if err != nil {
		t.Logf("error occured while marshaling to pkcs8: %s", err)
	}

	encodedBase64 := base64.StdEncoding.EncodeToString(encoded)
	var privK decrypt.PrivateKey
	privateKey, err := privK.LoadKey(encodedBase64)
	if err != nil {
		t.Fatalf("error loading key: %s", err)
	}

	if !assert.Equal(t, generated, privateKey) {
		t.Errorf("loaded key is incorrect or does not match")
	}
}

func TestBadKey(t *testing.T) {
	var privK decrypt.PrivateKey
	_, err := privK.LoadKey("badkey")
	if err == nil {
		t.Fatalf("expected error loading key")
	}
}

func TestLoadKeyInvalidBase64(t *testing.T) {
	var privK decrypt.PrivateKey
	_, err := privK.LoadKey("not-a-valid-base64-string")
	if err == nil {
		t.Fatalf("expected error for invalid base64 string")
	}
}

func TestLoadKeyInvalidPKCS8(t *testing.T) {
	// Create a valid base64 string that isn't a valid PKCS8 private key
	invalidKey := base64.StdEncoding.EncodeToString([]byte("not-a-valid-pkcs8-key"))

	var privK decrypt.PrivateKey
	_, err := privK.LoadKey(invalidKey)
	if err == nil {
		t.Fatalf("expected error for invalid PKCS8 key")
	}
}

func TestLoadKeyNonECDSAKey(t *testing.T) {
	// Generate an RSA private key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Marshal it to PKCS8 format
	encoded, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA key: %v", err)
	}

	// Encode to base64
	encodedBase64 := base64.StdEncoding.EncodeToString(encoded)

	var privK decrypt.PrivateKey
	_, err = privK.LoadKey(encodedBase64)
	if err == nil {
		t.Fatalf("expected error for non-ECDSA key")
	}
	if err != decrypt.ErrPrivateKey {
		t.Fatalf("expected ErrPrivateKey, got %v", err)
	}
}
