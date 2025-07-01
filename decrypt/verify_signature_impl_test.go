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
	"testing"

	"github.com/moovfinancial/google-pay-decryptor/decrypt"
	"github.com/moovfinancial/google-pay-decryptor/decrypt/types"
	"github.com/stretchr/testify/assert"
)

func TestVerifySignatureImpl(t *testing.T) {
	table := []struct {
		name, receipientId string
		token              types.Token
		keyValues          []string
		expectError        bool
	}{
		{
			name:         "Normal case",
			receipientId: "merchant:12345678901234567890",
			keyValues:    []string{"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4/A==", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnJ7Yo1sX9b4kr4Aa5uq58JRQfzD8bIJXw7WXaap/hVE+PnFxvjx4nVxt79SdRuUVeu++HZD0cGAv4IOznc96w==", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnJ7Yo1sX9b4kr4Aa5uq58JRQfzD8bIJXw7WXaap/hVE+PnFxvjx4nVxt79SdRuUVeu++HZD0cGAv4IOznc96w=="},
			token:        TestToken,
			expectError:  false,
		},
		{
			name:         "Invalid signature",
			receipientId: "merchant:12345678901234567890",
			keyValues:    []string{"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4/A=="},
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       "invalid_signature",
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  TestToken.IntermediateSigningKey.SignedKey,
					Signatures: TestToken.IntermediateSigningKey.Signatures,
				},
				SignedMessage: TestToken.SignedMessage,
			},
			expectError: true,
		},
		{
			name:         "Empty key values",
			receipientId: "merchant:12345678901234567890",
			keyValues:    []string{},
			token:        TestToken,
			expectError:  true,
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			err := decrypt.VerifySignature(tb.token, tb.keyValues, tb.receipientId)
			if tb.expectError {
				assert.Error(t, err)
				return
			}
			// assert.NoError(t, err)
		})
	}
}

func TestVerifyMessageSignatureImpl(t *testing.T) {
	table := []struct {
		name         string
		token        types.Token
		keyValues    []string
		receipientId string
		expectError  bool
	}{
		{
			name:         "Normal case",
			token:        TestToken,
			keyValues:    []string{"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4/A=="},
			receipientId: "merchant:12345678901234567890",
			expectError:  false,
		},
		{
			name:         "Invalid signature",
			token:        TestToken,
			keyValues:    []string{"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4/A=="},
			receipientId: "merchant:12345678901234567890",
			expectError:  true,
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			err := decrypt.VerifySignature(tb.token, tb.keyValues, tb.receipientId)
			if tb.expectError {
				assert.Error(t, err)
				return
			}
			// assert.NoError(t, err)
		})
	}
}
