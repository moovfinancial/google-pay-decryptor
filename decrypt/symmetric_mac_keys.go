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
	"github.com/google/tink/go/hybrid/subtle"
	hkdf "github.com/google/tink/go/subtle"
	"github.com/moovfinancial/google-pay-decryptor/decrypt/types"
)

func DeriveKeys(token types.Token, privateKeyEncoded string) ([]byte, []byte, error) {
	var privK PrivateKey
	privateKey, err := privK.LoadKey(privateKeyEncoded)
	if err != nil {
		return nil, nil, err
	}

	signedMessage, _ := token.UnmarshalSignedMessage(token.SignedMessage)
	var pk PublicKey
	ephemeralPK, err := pk.LoadEphemeralPublicKey(signedMessage.EphemeralPublicKey)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret, err := subtle.ComputeSharedSecret(ephemeralPK, privateKey)
	if err != nil {
		return nil, nil, err
	}
	decodedEphemeralKey, _ := Base64Decode(signedMessage.EphemeralPublicKey)
	combined := append(decodedEphemeralKey, sharedSecret...)
	derivedKeyHKDF, err := hkdf.ComputeHKDF(GooglePaySHA256HashAlgorithm, combined, make([]byte, 32), []byte(GooglePaySenderID), 64)
	if err != nil {
		return nil, nil, err
	}

	mac, encryptionKey, err := GenerateMacKeyAndEncryptionKey(derivedKeyHKDF)
	if err != nil {
		return nil, nil, err
	}
	return mac, encryptionKey, nil
}
