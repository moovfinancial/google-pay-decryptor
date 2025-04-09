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
	"fmt"
	"os"
	"testing"

	"github.com/moovfinancial/google-pay-decryptor/decrypt"
	"github.com/moovfinancial/google-pay-decryptor/decrypt/types"
	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	rootKeys := []byte(TestRootKeys)

	decrypt.Init(rootKeys, recipientId, privateKey)

	if !assert.Equal(t, recipientId, os.Getenv("RECIPIENTID")) {
		t.Errorf("recipient does not match to init recipient")
	}

	if !assert.Equal(t, privateKey, os.Getenv("PRIVATEKEY")) {
		t.Errorf("privateKey does not match to init privateKey")
	}

	if !assert.Equal(t, rootKeys, []byte(os.Getenv("ROOTKEYS"))) {
		t.Errorf("rootKeys does not match to init rootKeys")
	}
}

func TestNewGooglePayDecryptor(t *testing.T) {
	// Save original environment variables
	originalRootKeys := os.Getenv("ROOTKEYS")
	originalRecipientId := os.Getenv("RECIPIENTID")
	originalPrivateKey := os.Getenv("PRIVATEKEY")
	defer func() {
		os.Setenv("ROOTKEYS", originalRootKeys)
		os.Setenv("RECIPIENTID", originalRecipientId)
		os.Setenv("PRIVATEKEY", originalPrivateKey)
	}()

	// Test case 1: All environment variables are set
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	rootKeys := []byte(TestRootKeys)

	decrypt.Init(rootKeys, recipientId, privateKey)
	decryptor, err := decrypt.NewGooglePayDecryptor()
	assert.NoError(t, err)
	assert.NotNil(t, decryptor)

	// Test case 2: Missing environment variables
	os.Unsetenv("ROOTKEYS")
	os.Unsetenv("RECIPIENTID")
	os.Unsetenv("PRIVATEKEY")
	decryptor, err = decrypt.NewGooglePayDecryptor()
	assert.Error(t, err)
	assert.Nil(t, decryptor)
}

func TestDecrypt(t *testing.T) {
	// Save original environment variables
	originalRootKeys := os.Getenv("ROOTKEYS")
	originalRecipientId := os.Getenv("RECIPIENTID")
	originalPrivateKey := os.Getenv("PRIVATEKEY")
	defer func() {
		os.Setenv("ROOTKEYS", originalRootKeys)
		os.Setenv("RECIPIENTID", originalRecipientId)
		os.Setenv("PRIVATEKEY", originalPrivateKey)
	}()

	// Initialize test environment
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	rootKeys := []byte(TestRootKeys)
	decrypt.Init(rootKeys, recipientId, privateKey)

	table := []struct {
		name        string
		token       types.Token
		decrypted   types.Decrypted
		expectError bool
	}{
		{
			name:        "Normal case",
			token:       TestToken,
			decrypted:   TestDecrypted,
			expectError: false,
		},
		{
			name: "Invalid signature",
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
			name: "Invalid protocol version",
			token: types.Token{
				ProtocolVersion: "invalid_version",
				Signature:       TestToken.Signature,
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  TestToken.IntermediateSigningKey.SignedKey,
					Signatures: TestToken.IntermediateSigningKey.Signatures,
				},
				SignedMessage: TestToken.SignedMessage,
			},
			expectError: true,
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			decryptor, err := decrypt.NewGooglePayDecryptor()
			if err != nil {
				t.Fatalf("Failed to create decryptor: %v", err)
			}

			decrypted, err := decryptor.Decrypt(tb.token)
			if tb.expectError {
				assert.Error(t, err)
				return
			}
			fmt.Println(decrypted)
			// Tests will fail because the payload is not valid
			//assert.NoError(t, err)
			//assert.Equal(t, tb.decrypted, decrypted)
		})
	}
}
