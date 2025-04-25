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
	"crypto/x509"

	"github.com/google/tink/go/hybrid/subtle"
)

type PublicKey struct{}

func (pk *PublicKey) LoadEphemeralPublicKey(base64PublicKey string) (*subtle.ECPoint, error) {
	decoded, err := Base64Decode(base64PublicKey)
	if err != nil {
		return nil, err
	}

	curve, err := subtle.GetCurve(GooglePayECCType)
	if err != nil {
		return nil, err
	}

	pubKey, err := subtle.PointDecode(curve, GooglePayUncompressedFormat, decoded)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

func (pk *PublicKey) LoadPublicKey(base64PublicKey string) (*ecdsa.PublicKey, error) {
	publicKeyBase64Decoded, _ := Base64Decode(base64PublicKey)
	pub, err := x509.ParsePKIXPublicKey(publicKeyBase64Decoded)
	if err != nil {
		return nil, err
	}
	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrPublicKey
	}
	return publicKey, nil
}
