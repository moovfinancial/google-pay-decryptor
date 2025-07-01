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
	"encoding/base64"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/assert"
	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt"
)

func TestBase64Decode(t *testing.T) {
	randomBytes := random.GetRandomBytes(64)
	encoded := base64.StdEncoding.EncodeToString(randomBytes)

	decoded, err := decrypt.Base64Decode(encoded)
	if err != nil {
		t.Error(err)
	}

	if !assert.Equal(t, randomBytes, decoded) {
		t.Errorf("encoded value does not match decoded one")
	}
}

func TestGenerateMacKeyAndEncryptionKey(t *testing.T) {
	table := []struct {
		name                            string
		sharedSecret, mac, symmetricKey []byte
	}{
		{
			name:         "Normal case",
			sharedSecret: RandomBytes,
			mac:          RandomBytes[32:],
			symmetricKey: RandomBytes[:32],
		},
		{
			name:         "Invalid length",
			sharedSecret: RandomBytes[:63], // One byte short of required length
			mac:          nil,
			symmetricKey: nil,
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			derivedMac, derivedSymmetric, err := decrypt.GenerateMacKeyAndEncryptionKey(tb.sharedSecret)
			if err != nil {
				if tb.name == "Invalid length" {
					assert.ErrorIs(t, err, decrypt.ErrLengthDoesnotMatch)
					return
				}
				t.Error(err)
			}

			if !assert.Equal(t, tb.mac, derivedMac) {
				t.Errorf("derived mac does not match initial mac")
			}

			if !assert.Equal(t, tb.symmetricKey, derivedSymmetric) {
				t.Errorf("derived symmetric key does not match initial symmetric key")
			}
		})
	}
}

func TestCheckTime(t *testing.T) {
	table := []struct {
		name       string
		expiration string
		isTrue     bool
	}{
		{
			name:       "Normal case",
			expiration: KeyExp,
			isTrue:     true,
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			checked := decrypt.CheckTime(tb.expiration)

			if !assert.Equal(t, tb.isTrue, checked) {
				t.Errorf("derived mac does not match initial mac")
			}
		})
	}
}

func TestConstructSignature(t *testing.T) {
	table := []struct {
		name      string
		params    []string
		signature []byte
	}{
		{
			name:      "Normal case",
			params:    []string{"Google", "merchant:123456789", "ECv2", `{"tag":"jpGz1F1Bcoi/fCNxI9n7Qrsw7i7KHrGtTf3NrRclt+U\u003d","ephemeralPublicKey":"BJatyFvFPPD21l8/uLP46Ta1hsKHndf8Z+tAgk+DEPQgYTkhHy19cF3h/bXs0tWTmZtnNm+vlVrKbRU9K8+7cZs\u003d","encryptedMessage":"mKOoXwi8OavZ"}`},
			signature: []byte{6, 0, 0, 0, 71, 111, 111, 103, 108, 101, 18, 0, 0, 0, 109, 101, 114, 99, 104, 97, 110, 116, 58, 49, 50, 51, 52, 53, 54, 55, 56, 57, 4, 0, 0, 0, 69, 67, 118, 50, 210, 0, 0, 0, 123, 34, 116, 97, 103, 34, 58, 34, 106, 112, 71, 122, 49, 70, 49, 66, 99, 111, 105, 47, 102, 67, 78, 120, 73, 57, 110, 55, 81, 114, 115, 119, 55, 105, 55, 75, 72, 114, 71, 116, 84, 102, 51, 78, 114, 82, 99, 108, 116, 43, 85, 92, 117, 48, 48, 51, 100, 34, 44, 34, 101, 112, 104, 101, 109, 101, 114, 97, 108, 80, 117, 98, 108, 105, 99, 75, 101, 121, 34, 58, 34, 66, 74, 97, 116, 121, 70, 118, 70, 80, 80, 68, 50, 49, 108, 56, 47, 117, 76, 80, 52, 54, 84, 97, 49, 104, 115, 75, 72, 110, 100, 102, 56, 90, 43, 116, 65, 103, 107, 43, 68, 69, 80, 81, 103, 89, 84, 107, 104, 72, 121, 49, 57, 99, 70, 51, 104, 47, 98, 88, 115, 48, 116, 87, 84, 109, 90, 116, 110, 78, 109, 43, 118, 108, 86, 114, 75, 98, 82, 85, 57, 75, 56, 43, 55, 99, 90, 115, 92, 117, 48, 48, 51, 100, 34, 44, 34, 101, 110, 99, 114, 121, 112, 116, 101, 100, 77, 101, 115, 115, 97, 103, 101, 34, 58, 34, 109, 75, 79, 111, 88, 119, 105, 56, 79, 97, 118, 90, 34, 125},
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			signature := decrypt.ConstructSignature(tb.params...)

			if !assert.Equal(t, tb.signature, signature) {
				t.Errorf("derived signature does not match initial signature")
			}
		})
	}
}
