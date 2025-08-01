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
	"encoding/json"
	"fmt"

	"github.com/google/tink/go/hybrid/subtle"
	hkdf "github.com/google/tink/go/subtle"
	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt/types"
)

// DecryptECv1 decrypts an ECv1 token
// ECv1 is simpler than ECv2 - it doesn't have intermediate signing key verification
func (g *GooglePayDecryptor) DecryptECv1(token types.Token) (types.Decrypted, error) {
	// Try each active key in sequence
	var lastErr error
	for _, keyEntry := range g.privateKeys {
		if !keyEntry.IsActive {
			continue
		}

		// Parse the signed message
		signedMessage, err := token.UnmarshalSignedMessage(token.SignedMessage)
		if err != nil {
			lastErr = err
			continue
		}

		// derive mac and encryption keys using the same process as ECv2
		mac, encryptionKey, err := DeriveKeysECv1(signedMessage, keyEntry.Key)
		if err != nil {
			lastErr = err
			continue
		}

		// verify mac
		if err := VerifyMessageHmac(mac, signedMessage.Tag, signedMessage.EncryptedMessage); err != nil {
			lastErr = err
			continue
		}

		// Decode message with encryptionKey
		decodedMessage, err := Decode(encryptionKey, signedMessage.EncryptedMessage)
		if err != nil {
			lastErr = err
			continue
		}

		var decrypted types.Decrypted
		err = json.Unmarshal(decodedMessage, &decrypted)
		if err != nil {
			lastErr = fmt.Errorf("failed to unmarshal decrypted message: %w", err)
			continue
		}

		// check message expiration
		if !CheckTime(decrypted.MessageExpiration) {
			return types.Decrypted{}, fmt.Errorf("message expired: %w", ErrValidateTimeMessage)
		}

		// If we get here, the message has been successfully decrypted and validated
		return decrypted, nil
	}

	// If we get here, none of the keys worked
	if lastErr != nil {
		return types.Decrypted{}, fmt.Errorf("failed to decrypt with any key: %w", lastErr)
	}
	return types.Decrypted{}, fmt.Errorf("no active keys available for decryption")
}

// DeriveKeysECv1 derives MAC and encryption keys for ECv1 tokens
// This is similar to DeriveKeys but takes a SignedMessage directly instead of a Token
func DeriveKeysECv1(signedMessage types.SignedMessage, privateKeyEncoded string) ([]byte, []byte, error) {
	var privK PrivateKey
	privateKey, err := privK.LoadKey(privateKeyEncoded)
	if err != nil {
		return nil, nil, err
	}

	var pk PublicKey
	ephemeralPK, err := pk.LoadEphemeralPublicKey(signedMessage.EphemeralPublicKey)
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err := subtle.ComputeSharedSecret(ephemeralPK, privateKey)
	if err != nil {
		return nil, nil, err
	}

	decodedEphemeralKey, err := Base64Decode(signedMessage.EphemeralPublicKey)
	if err != nil {
		return nil, nil, err
	}

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
