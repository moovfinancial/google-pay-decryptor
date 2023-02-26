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

package decrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"

	"github.com/google/tink/go/hybrid/subtle"
	"github.com/zethuman/google-pay-decryptor/decrypt/types"
)

type PrivateKey struct{}

func (p *PrivateKey) LoadKey(privateKey string) (*subtle.ECPrivateKey, error) {
	privateKeyBase64Decoded, err := Base64Decode(privateKey)
	if err != nil {
		return &subtle.ECPrivateKey{}, err
	}
	priv, err := x509.ParsePKCS8PrivateKey(privateKeyBase64Decoded)
	if err != nil {
		return &subtle.ECPrivateKey{}, err
	}
	privKey, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return &subtle.ECPrivateKey{}, types.ErrPrivateKey
	}
	ecpoints := subtle.ECPoint{X: privKey.PublicKey.X, Y: privKey.PublicKey.Y}
	publicKey := subtle.ECPublicKey{Curve: elliptic.P256(), Point: ecpoints}
	ecpointpk := subtle.ECPrivateKey{PublicKey: publicKey, D: privKey.D}
	return &ecpointpk, nil
}
