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
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/google/tink/go/hybrid/subtle"
	"github.com/m1crogravity/google-pay-decryptor/decrypt"
	"github.com/m1crogravity/google-pay-decryptor/decrypt/types"
	"github.com/stretchr/testify/assert"
)

func TestLoadEphemeralPublicKey(t *testing.T) {
	curve, err := subtle.GetCurve(types.CURVE)
	if err != nil {
		t.Error(err)
	}
	privKey, err := subtle.GenerateECDHKeyPair(curve)
	if err != nil {
		t.Error(err)
	}

	encoded, err := subtle.PointEncode(curve, types.FORMAT, privKey.PublicKey.Point)
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
	curve, _ := subtle.GetCurve(types.CURVE)
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
