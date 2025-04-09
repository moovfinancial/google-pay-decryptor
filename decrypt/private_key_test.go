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
	"github.com/moovfinancial/google-pay-decryptor/decrypt"
	"github.com/moovfinancial/google-pay-decryptor/decrypt/types"
	"github.com/stretchr/testify/assert"
)

func TestLoadKey(t *testing.T) {
	curve, _ := subtle.GetCurve(types.CURVE)
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
