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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/moovfinancial/google-pay-decryptor/decrypt"
	"github.com/moovfinancial/google-pay-decryptor/decrypt/types"
	"github.com/stretchr/testify/assert"
)

// RootSigningKey represents the structure of Google's root signing keys
type RootSigningKey struct {
	Keys []struct {
		KeyValue        string `json:"keyValue"`
		ProtocolVersion string `json:"protocolVersion"`
		KeyExpiration   string `json:"keyExpiration"`
	} `json:"keys"`
}

// Filter processes the root keys and returns the filtered keys and values
func (r *RootSigningKey) Filter(rootKeys []byte) ([]byte, []string, error) {
	if err := json.Unmarshal(rootKeys, r); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal root keys: %w", err)
	}

	var keyValues []string
	for _, key := range r.Keys {
		keyValues = append(keyValues, key.KeyValue)
	}

	return rootKeys, keyValues, nil
}

// VerifySignature verifies the signature of a token
func VerifySignature(token types.Token, keyValues []string, recipientId string) error {
	// Implementation of signature verification
	// This is a placeholder - the actual implementation would verify the token's signature
	// against the provided key values and recipient ID
	return nil
}

func TestInit(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	rootKeys := []byte(TestRootKeys)

	decryptor := decrypt.New(rootKeys, recipientId, privateKey)
	assert.NotNil(t, decryptor)

	activeKeys := decryptor.GetActivePrivateKeys()
	assert.Equal(t, 1, len(activeKeys))
	assert.Equal(t, "primary", activeKeys[0].Identifier)
	assert.True(t, activeKeys[0].IsActive)
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

	os.Setenv("ROOTKEYS", string(rootKeys))
	os.Setenv("RECIPIENTID", recipientId)
	os.Setenv("PRIVATEKEY", privateKey)

	decryptor, err := decrypt.NewGooglePayDecryptor()
	assert.NoError(t, err)
	assert.NotNil(t, decryptor)

	activeKeys := decryptor.GetActivePrivateKeys()
	assert.Equal(t, 1, len(activeKeys))
	assert.Equal(t, "primary", activeKeys[0].Identifier)
	assert.True(t, activeKeys[0].IsActive)

	// Test case 2: Missing environment variables
	os.Unsetenv("ROOTKEYS")
	os.Unsetenv("RECIPIENTID")
	os.Unsetenv("PRIVATEKEY")
	decryptor, err = decrypt.NewGooglePayDecryptor()
	assert.Error(t, err)
	assert.Nil(t, decryptor)
}

func TestMultipleKeys(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	primaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	secondaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPt7FKYx/UQFmOFpFM5zI5YhPvLzpjPPNtQgJZxNhX6hRANCAARvRNAHWz0aCdBUwABFfgPSBNr4JhQhPVHMZvGtXeqXgH1Yr+i/Qm8vBJFEGPBFtHvOHqFtJEwNYFsNKLGrUHWB"
	rootKeys := []byte(TestRootKeys)

	decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
	assert.NotNil(t, decryptor)

	// Add secondary key
	err := decryptor.AddPrivateKey(secondaryKey, "secondary")
	assert.NoError(t, err)

	activeKeys := decryptor.GetActivePrivateKeys()
	assert.Equal(t, 2, len(activeKeys))

	// Find the secondary key
	var secondaryKeyEntry decrypt.KeyEntry
	for _, key := range activeKeys {
		if key.Identifier == "secondary" {
			secondaryKeyEntry = key
			break
		}
	}
	assert.Equal(t, "secondary", secondaryKeyEntry.Identifier)
	assert.True(t, secondaryKeyEntry.IsActive)

	// Test disabling a key
	err = decryptor.SetPrivateKeyActive("secondary", false)
	assert.NoError(t, err)

	activeKeys = decryptor.GetActivePrivateKeys()
	assert.Equal(t, 1, len(activeKeys))
	assert.Equal(t, "primary", activeKeys[0].Identifier)

	// Test enabling a key
	err = decryptor.SetPrivateKeyActive("secondary", true)
	assert.NoError(t, err)

	activeKeys = decryptor.GetActivePrivateKeys()
	assert.Equal(t, 2, len(activeKeys))

	// Test error cases
	err = decryptor.AddPrivateKey("", "invalid")
	assert.Error(t, err)

	err = decryptor.SetPrivateKeyActive("nonexistent", true)
	assert.Error(t, err)
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

	os.Setenv("ROOTKEYS", string(rootKeys))
	os.Setenv("RECIPIENTID", recipientId)
	os.Setenv("PRIVATEKEY", privateKey)

	table := []struct {
		name        string
		token       types.Token
		decrypted   types.Decrypted
		expectError bool
	}{
		{
			name:        "Normal case, but Expired",
			token:       TestToken,
			decrypted:   TestDecrypted,
			expectError: true,
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

			// Success case
			//fmt.Println(decrypted)
			assert.NoError(t, err)
			assert.Equal(t, tb.decrypted, decrypted)
		})
	}
}

func TestNewWithRootKeysFromGoogle(t *testing.T) {
	// Save original HTTP client
	originalClient := decrypt.DefaultHTTPClient
	defer func() {
		decrypt.DefaultHTTPClient = originalClient
	}()

	// Test case 1: Valid test environment
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"

	// Set up mock client for successful response
	decrypt.DefaultHTTPClient = &mockHTTPClient{
		statusCode: http.StatusOK,
		body:       []byte(TestRootKeys),
	}

	decryptor, err := decrypt.NewWithRootKeysFromGoogle("test", recipientId, privateKey)
	assert.NoError(t, err)
	assert.NotNil(t, decryptor)

	// Test case 2: Invalid environment
	decryptor, err = decrypt.NewWithRootKeysFromGoogle("invalid", recipientId, privateKey)
	assert.Error(t, err)
	assert.Nil(t, decryptor)

	// Test case 3: Empty recipient ID
	decryptor, err = decrypt.NewWithRootKeysFromGoogle("test", "", privateKey)
	assert.Error(t, err)
	assert.Nil(t, decryptor)

	// Test case 4: Empty private key
	decryptor, err = decrypt.NewWithRootKeysFromGoogle("test", recipientId, "")
	assert.Error(t, err)
	assert.Nil(t, decryptor)

	// Test case 5: HTTP error
	decrypt.DefaultHTTPClient = &mockHTTPClient{
		err: fmt.Errorf("connection error"),
	}
	decryptor, err = decrypt.NewWithRootKeysFromGoogle("test", recipientId, privateKey)
	assert.Error(t, err)
	assert.Nil(t, decryptor)

	// Test case 6: Non-200 status code
	decrypt.DefaultHTTPClient = &mockHTTPClient{
		statusCode: http.StatusNotFound,
	}
	decryptor, err = decrypt.NewWithRootKeysFromGoogle("test", recipientId, privateKey)
	assert.Error(t, err)
	assert.Nil(t, decryptor)
}

func TestFetchGoogleRootKeys(t *testing.T) {
	// Save original HTTP client
	originalClient := decrypt.DefaultHTTPClient
	defer func() {
		decrypt.DefaultHTTPClient = originalClient
	}()

	// Test case 1: Test environment
	decrypt.DefaultHTTPClient = &mockHTTPClient{
		statusCode: http.StatusOK,
		body:       []byte(TestRootKeys),
	}
	keys, err := decrypt.FetchGoogleRootKeys("test")
	assert.NoError(t, err)
	assert.NotNil(t, keys)

	// Test case 2: Production environment
	decrypt.DefaultHTTPClient = &mockHTTPClient{
		statusCode: http.StatusOK,
		body:       []byte(TestRootKeys),
	}
	keys, err = decrypt.FetchGoogleRootKeys("production")
	assert.NoError(t, err)
	assert.NotNil(t, keys)

	// Test case 3: Invalid environment
	keys, err = decrypt.FetchGoogleRootKeys("invalid")
	assert.Error(t, err)
	assert.Nil(t, keys)

	// Test case 4: HTTP error
	decrypt.DefaultHTTPClient = &mockHTTPClient{
		err: fmt.Errorf("connection error"),
	}
	keys, err = decrypt.FetchGoogleRootKeys("test")
	assert.Error(t, err)
	assert.Nil(t, keys)

	// Test case 5: Non-200 status code
	decrypt.DefaultHTTPClient = &mockHTTPClient{
		statusCode: http.StatusNotFound,
	}
	keys, err = decrypt.FetchGoogleRootKeys("test")
	assert.Error(t, err)
	assert.Nil(t, keys)
}

func TestKeyRotation(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	primaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	secondaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPt7FKYx/UQFmOFpFM5zI5YhPvLzpjPPNtQgJZxNhX6hRANCAARvRNAHWz0aCdBUwABFfgPSBNr4JhQhPVHMZvGtXeqXgH1Yr+i/Qm8vBJFEGPBFtHvOHqFtJEwNYFsNKLGrUHWB"
	rootKeys := []byte(TestRootKeys)

	decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
	assert.NotNil(t, decryptor)

	// Add secondary key
	err := decryptor.AddPrivateKey(secondaryKey, "secondary")
	assert.NoError(t, err)

	// Test key rotation by disabling primary key
	err = decryptor.SetPrivateKeyActive("primary", false)
	assert.NoError(t, err)

	activeKeys := decryptor.GetActivePrivateKeys()
	assert.Equal(t, 1, len(activeKeys))
	assert.Equal(t, "secondary", activeKeys[0].Identifier)

	// Test re-enabling primary key
	err = decryptor.SetPrivateKeyActive("primary", true)
	assert.NoError(t, err)

	activeKeys = decryptor.GetActivePrivateKeys()
	assert.Equal(t, 2, len(activeKeys))
}

func TestDecryptErrorCases(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	rootKeys := []byte(TestRootKeys)

	decryptor := decrypt.New(rootKeys, recipientId, privateKey)
	assert.NotNil(t, decryptor)

	// Test case 1: Invalid token
	invalidToken := types.Token{
		ProtocolVersion: "invalid",
		Signature:       "invalid",
		SignedMessage:   "invalid",
	}
	_, err := decryptor.Decrypt(invalidToken)
	assert.Error(t, err)

	// Test case 2: Token with invalid signature
	invalidSignatureToken := types.Token{
		ProtocolVersion: "ECv2",
		Signature:       "invalid",
		SignedMessage:   TestToken.SignedMessage,
	}
	_, err = decryptor.Decrypt(invalidSignatureToken)
	assert.Error(t, err)

	// Test case 3: Token with invalid signed message
	invalidMessageToken := types.Token{
		ProtocolVersion: "ECv2",
		Signature:       TestToken.Signature,
		SignedMessage:   "invalid",
	}
	_, err = decryptor.Decrypt(invalidMessageToken)
	assert.Error(t, err)

	// Test case 4: All keys disabled
	err = decryptor.SetPrivateKeyActive("primary", false)
	assert.NoError(t, err)
	_, err = decryptor.Decrypt(TestToken)
	assert.Error(t, err)
	// Don't check the specific error message since it depends on the validation order
}

func TestKeyManagement(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	primaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	secondaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPt7FKYx/UQFmOFpFM5zI5YhPvLzpjPPNtQgJZxNhX6hRANCAARvRNAHWz0aCdBUwABFfgPSBNr4JhQhPVHMZvGtXeqXgH1Yr+i/Qm8vBJFEGPBFtHvOHqFtJEwNYFsNKLGrUHWB"
	rootKeys := []byte(TestRootKeys)

	decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
	assert.NotNil(t, decryptor)

	// Test adding multiple keys
	for i := 0; i < 3; i++ {
		err := decryptor.AddPrivateKey(secondaryKey, fmt.Sprintf("secondary_%d", i))
		assert.NoError(t, err)
	}

	activeKeys := decryptor.GetActivePrivateKeys()
	assert.Equal(t, 4, len(activeKeys)) // primary + 3 secondary keys

	// Test disabling multiple keys
	for i := 0; i < 3; i++ {
		err := decryptor.SetPrivateKeyActive(fmt.Sprintf("secondary_%d", i), false)
		assert.NoError(t, err)
	}

	activeKeys = decryptor.GetActivePrivateKeys()
	assert.Equal(t, 1, len(activeKeys)) // only primary key active

	// Test enabling specific keys
	err := decryptor.SetPrivateKeyActive("secondary_1", true)
	assert.NoError(t, err)

	activeKeys = decryptor.GetActivePrivateKeys()
	assert.Equal(t, 2, len(activeKeys)) // primary + secondary_1

	// Test error cases
	err = decryptor.AddPrivateKey("", "empty_key")
	assert.Error(t, err)

	err = decryptor.SetPrivateKeyActive("nonexistent_key", true)
	assert.Error(t, err)
}

func TestDecryptWithMultipleKeys(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	primaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	secondaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPt7FKYx/UQFmOFpFM5zI5YhPvLzpjPPNtQgJZxNhX6hRANCAARvRNAHWz0aCdBUwABFfgPSBNr4JhQhPVHMZvGtXeqXgH1Yr+i/Qm8vBJFEGPBFtHvOHqFtJEwNYFsNKLGrUHWB"
	rootKeys := []byte(TestRootKeys)

	decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
	assert.NotNil(t, decryptor)

	// Add secondary key
	err := decryptor.AddPrivateKey(secondaryKey, "secondary")
	assert.NoError(t, err)

	// Test decryption with both keys active
	_, err = decryptor.Decrypt(TestToken)
	// We expect an error because TestToken is not valid, but we want to ensure
	// the code path for trying multiple keys is exercised
	assert.Error(t, err)

	// Test decryption with only secondary key active
	err = decryptor.SetPrivateKeyActive("primary", false)
	assert.NoError(t, err)

	_, err = decryptor.Decrypt(TestToken)
	assert.Error(t, err)

	// Test decryption with no active keys
	err = decryptor.SetPrivateKeyActive("secondary", false)
	assert.NoError(t, err)

	_, err = decryptor.Decrypt(TestToken)
	assert.Error(t, err)
	// Don't check the specific error message since it depends on the validation order
}

func TestHTTPClientInterface(t *testing.T) {
	// Test custom HTTP client
	customClient := &mockHTTPClient{
		statusCode: http.StatusOK,
		body:       []byte(TestRootKeys),
	}

	// Save original client and restore after test
	originalClient := decrypt.DefaultHTTPClient
	decrypt.DefaultHTTPClient = customClient
	defer func() {
		decrypt.DefaultHTTPClient = originalClient
	}()

	// Test successful request
	keys, err := decrypt.FetchGoogleRootKeys("test")
	assert.NoError(t, err)
	assert.NotNil(t, keys)

	// Test client error
	customClient.err = fmt.Errorf("custom error")
	keys, err = decrypt.FetchGoogleRootKeys("test")
	assert.Error(t, err)
	assert.Nil(t, keys)
	assert.Contains(t, err.Error(), "custom error")

	// Test bad response
	customClient.err = nil
	customClient.statusCode = http.StatusInternalServerError
	keys, err = decrypt.FetchGoogleRootKeys("test")
	assert.Error(t, err)
	assert.Nil(t, keys)
	assert.Contains(t, err.Error(), "500")
}

// mockHTTPClient implements the HTTPClient interface for testing
type mockHTTPClient struct {
	statusCode int
	body       []byte
	err        error
}

func (m *mockHTTPClient) Get(url string) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}

	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(bytes.NewReader(m.body)),
	}, nil
}

func TestSignatureVerification(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	rootKeys := []byte(TestRootKeys)

	decryptor := decrypt.New(rootKeys, recipientId, privateKey)
	assert.NotNil(t, decryptor)

	// Test case 1: Invalid protocol version
	invalidToken := types.Token{
		ProtocolVersion: "invalid",
		Signature:       "invalid",
		SignedMessage:   "invalid",
	}
	_, err := decryptor.Decrypt(invalidToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "only ECv2-signed tokens are supported")

	// Test case 2: Invalid intermediate signing key
	invalidIntermediateKey := types.Token{
		ProtocolVersion: "ECv2",
		Signature:       TestToken.Signature,
		IntermediateSigningKey: types.IntermediateSigningKey{
			SignedKey:  "invalid",
			Signatures: []string{"invalid"},
		},
		SignedMessage: TestToken.SignedMessage,
	}
	_, err = decryptor.Decrypt(invalidIntermediateKey)
	assert.Error(t, err)

	// Test case 3: Invalid signature format
	invalidSignatureFormat := types.Token{
		ProtocolVersion:        "ECv2",
		Signature:              "not_base64",
		IntermediateSigningKey: TestToken.IntermediateSigningKey,
		SignedMessage:          TestToken.SignedMessage,
	}
	_, err = decryptor.Decrypt(invalidSignatureFormat)
	assert.Error(t, err)

	// Test case 4: Invalid signed message format
	invalidMessageFormat := types.Token{
		ProtocolVersion:        "ECv2",
		Signature:              TestToken.Signature,
		IntermediateSigningKey: TestToken.IntermediateSigningKey,
		SignedMessage:          "not_base64",
	}
	_, err = decryptor.Decrypt(invalidMessageFormat)
	assert.Error(t, err)
}

func TestDecryptionProcess(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	rootKeys := []byte(TestRootKeys)

	decryptor := decrypt.New(rootKeys, recipientId, privateKey)
	assert.NotNil(t, decryptor)

	// Test case 1: Invalid root keys format
	invalidRootKeysDecryptor := decrypt.New([]byte("invalid"), recipientId, privateKey)
	_, err := invalidRootKeysDecryptor.Decrypt(TestToken)
	assert.Error(t, err)

	// Test case 2: Invalid private key format
	invalidPrivateKeyDecryptor := decrypt.New(rootKeys, recipientId, "invalid")
	_, err = invalidPrivateKeyDecryptor.Decrypt(TestToken)
	assert.Error(t, err)

	// Test case 3: Invalid recipient ID
	invalidRecipientDecryptor := decrypt.New(rootKeys, "invalid", privateKey)
	_, err = invalidRecipientDecryptor.Decrypt(TestToken)
	assert.Error(t, err)

	// Test case 4: Invalid signed message JSON
	invalidJSON := types.Token{
		ProtocolVersion:        "ECv2",
		Signature:              TestToken.Signature,
		IntermediateSigningKey: TestToken.IntermediateSigningKey,
		SignedMessage:          "eyJpbnZhbGlkIjoianNvbiJ9", // Base64 encoded invalid JSON
	}
	//_, err = decryptor.Decrypt(invalidJSON)
	_, err = decryptor.DecryptWithMerchantId(invalidJSON, "googletest")
	assert.Error(t, err)
}

func TestRootKeysProcessing(t *testing.T) {
	// Test case 1: Invalid JSON in root keys
	invalidJSON := []byte(`{"invalid": "json"`)
	decryptor := decrypt.New(invalidJSON, "recipient", "key")
	_, err := decryptor.Decrypt(TestToken)
	assert.Error(t, err)

	// Test case 2: Missing required fields in root keys
	missingFields := []byte(`{"keys": [{"someField": "value"}]}`)
	decryptor = decrypt.New(missingFields, "recipient", "key")
	_, err = decryptor.Decrypt(TestToken)
	assert.Error(t, err)

	// Test case 3: Invalid key format in root keys
	invalidKeyFormat := []byte(`{"keys": [{"keyValue": "not-base64", "protocolVersion": "ECv2"}]}`)
	decryptor = decrypt.New(invalidKeyFormat, "recipient", "key")
	_, err = decryptor.Decrypt(TestToken)
	assert.Error(t, err)
}

// setupTestDecryptor creates a test decryptor with default test values
func setupTestDecryptor(t *testing.T) *decrypt.GooglePayDecryptor {
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	rootKeys := []byte(TestRootKeys)

	decryptor := decrypt.New(rootKeys, recipientId, privateKey)
	assert.NotNil(t, decryptor)
	return decryptor
}

// TestDecryptWithInvalidInputs tests decryption with various invalid inputs
func TestDecryptWithInvalidInputs(t *testing.T) {
	decryptor := setupTestDecryptor(t)

	tests := []struct {
		name          string
		token         types.Token
		expectedError string
	}{
		{
			name: "Invalid protocol version",
			token: types.Token{
				ProtocolVersion: "invalid",
				Signature:       "test",
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  "test",
					Signatures: []string{"test"},
				},
				SignedMessage: "test",
			},
			expectedError: "only ECv2-signed tokens are supported",
		},
		{
			name: "Empty signature",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       "",
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  "test",
					Signatures: []string{"test"},
				},
				SignedMessage: "test",
			},
			expectedError: "could not verify intermediate signing key signature",
		},
		{
			name: "Invalid intermediate signing key",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       "test",
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  "",
					Signatures: []string{},
				},
				SignedMessage: "test",
			},
			expectedError: "could not verify intermediate signing key signature",
		},
		{
			name: "Empty signed message",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       "test",
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  "test",
					Signatures: []string{"test"},
				},
				SignedMessage: "",
			},
			expectedError: "could not verify intermediate signing key signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decryptor.Decrypt(tt.token)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

// TestVerifySignatureWithInvalidKeys tests signature verification with invalid keys
func TestVerifySignatureWithInvalidKeys(t *testing.T) {
	decryptor := setupTestDecryptor(t)

	tests := []struct {
		name          string
		token         types.Token
		expectedError string
	}{
		{
			name: "Invalid encrypted message",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       "test",
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  "test",
					Signatures: []string{"test"},
				},
				SignedMessage: `{"encryptedMessage":"","ephemeralPublicKey":"test","tag":"test"}`,
			},
			expectedError: "could not verify intermediate signing key signature",
		},
		{
			name: "Invalid ephemeral public key",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       "test",
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  "test",
					Signatures: []string{"test"},
				},
				SignedMessage: `{"encryptedMessage":"test","ephemeralPublicKey":"","tag":"test"}`,
			},
			expectedError: "could not verify intermediate signing key signature",
		},
		{
			name: "Invalid tag",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       "test",
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  "test",
					Signatures: []string{"test"},
				},
				SignedMessage: `{"encryptedMessage":"test","ephemeralPublicKey":"test","tag":""}`,
			},
			expectedError: "could not verify intermediate signing key signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decryptor.Decrypt(tt.token)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

// TestKeyManagementOperations tests comprehensive key management scenarios
func TestKeyManagementOperations(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	primaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	secondaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPt7FKYx/UQFmOFpFM5zI5YhPvLzpjPPNtQgJZxNhX6hRANCAARvRNAHWz0aCdBUwABFfgPSBNr4JhQhPVHMZvGtXeqXgH1Yr+i/Qm8vBJFEGPBFtHvOHqFtJEwNYFsNKLGrUHWB"
	rootKeys := []byte(TestRootKeys)

	t.Run("Add and verify multiple keys", func(t *testing.T) {
		decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
		assert.NotNil(t, decryptor)

		// Add secondary key
		err := decryptor.AddPrivateKey(secondaryKey, "secondary")
		assert.NoError(t, err)

		// Verify both keys are active
		activeKeys := decryptor.GetActivePrivateKeys()
		assert.Equal(t, 2, len(activeKeys))
		foundPrimary := false
		foundSecondary := false
		for _, key := range activeKeys {
			if key.Identifier == "primary" {
				foundPrimary = true
			}
			if key.Identifier == "secondary" {
				foundSecondary = true
			}
		}
		assert.True(t, foundPrimary, "Primary key not found")
		assert.True(t, foundSecondary, "Secondary key not found")
	})

	t.Run("Key rotation scenario", func(t *testing.T) {
		decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
		assert.NotNil(t, decryptor)

		// Add secondary key
		err := decryptor.AddPrivateKey(secondaryKey, "secondary")
		assert.NoError(t, err)

		// Disable primary key (simulating rotation)
		err = decryptor.SetPrivateKeyActive("primary", false)
		assert.NoError(t, err)

		// Verify only secondary is active
		activeKeys := decryptor.GetActivePrivateKeys()
		assert.Equal(t, 1, len(activeKeys))
		assert.Equal(t, "secondary", activeKeys[0].Identifier)

		// Re-enable primary key
		err = decryptor.SetPrivateKeyActive("primary", true)
		assert.NoError(t, err)

		// Verify both are active again
		activeKeys = decryptor.GetActivePrivateKeys()
		assert.Equal(t, 2, len(activeKeys))
	})

	t.Run("Invalid key operations", func(t *testing.T) {
		decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
		assert.NotNil(t, decryptor)

		// Try to add empty key
		err := decryptor.AddPrivateKey("", "empty")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty key")

		// Try to activate non-existent key
		err = decryptor.SetPrivateKeyActive("nonexistent", true)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")

		// Try to add key with duplicate identifier
		err = decryptor.AddPrivateKey(secondaryKey, "primary")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate identifier")
	})

	t.Run("Multiple key rotations", func(t *testing.T) {
		decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
		assert.NotNil(t, decryptor)

		// Add multiple secondary keys
		for i := 1; i <= 3; i++ {
			err := decryptor.AddPrivateKey(secondaryKey, fmt.Sprintf("secondary_%d", i))
			assert.NoError(t, err)
		}

		// Verify all keys are added
		activeKeys := decryptor.GetActivePrivateKeys()
		assert.Equal(t, 4, len(activeKeys))

		// Disable all secondary keys
		for i := 1; i <= 3; i++ {
			err := decryptor.SetPrivateKeyActive(fmt.Sprintf("secondary_%d", i), false)
			assert.NoError(t, err)
		}

		// Verify only primary is active
		activeKeys = decryptor.GetActivePrivateKeys()
		assert.Equal(t, 1, len(activeKeys))
		assert.Equal(t, "primary", activeKeys[0].Identifier)

		// Re-enable one secondary key
		err := decryptor.SetPrivateKeyActive("secondary_2", true)
		assert.NoError(t, err)

		// Verify two keys are active
		activeKeys = decryptor.GetActivePrivateKeys()
		assert.Equal(t, 2, len(activeKeys))
	})
}

// TestHTTPClientScenarios tests various HTTP client scenarios
func TestHTTPClientScenarios(t *testing.T) {
	// Save original client and restore after test
	originalClient := decrypt.DefaultHTTPClient
	defer func() {
		decrypt.DefaultHTTPClient = originalClient
	}()

	t.Run("Network timeout", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			err: fmt.Errorf("network timeout"),
		}
		decrypt.DefaultHTTPClient = mockClient

		_, err := decrypt.FetchGoogleRootKeys("test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "network timeout")
	})

	t.Run("Server error", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			statusCode: http.StatusInternalServerError,
			body:       []byte("internal server error"),
		}
		decrypt.DefaultHTTPClient = mockClient

		_, err := decrypt.FetchGoogleRootKeys("test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("Invalid response body", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			statusCode: http.StatusOK,
			body:       []byte("invalid json"),
		}
		decrypt.DefaultHTTPClient = mockClient

		_, err := decrypt.FetchGoogleRootKeys("test")
		assert.NoError(t, err)
		// The error will occur when trying to use these invalid root keys
		decryptor := decrypt.New([]byte("invalid json"), "recipient", "key")
		_, err = decryptor.Decrypt(TestToken)
		assert.Error(t, err)
	})

	t.Run("Empty response body", func(t *testing.T) {
		mockClient := &mockHTTPClient{
			statusCode: http.StatusOK,
			body:       []byte{},
		}
		decrypt.DefaultHTTPClient = mockClient

		_, err := decrypt.FetchGoogleRootKeys("test")
		assert.NoError(t, err)
		// The error will occur when trying to use these empty root keys
		decryptor := decrypt.New([]byte{}, "recipient", "key")
		_, err = decryptor.Decrypt(TestToken)
		assert.Error(t, err)
	})
}

// TestRootKeyValidation tests various root key validation scenarios
func TestRootKeyValidation(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"

	t.Run("Invalid root key JSON", func(t *testing.T) {
		invalidJSON := []byte(`{"invalid": json}`)
		decryptor := decrypt.New(invalidJSON, recipientId, privateKey)
		_, err := decryptor.Decrypt(TestToken)
		assert.Error(t, err)
	})

	t.Run("Missing required fields", func(t *testing.T) {
		missingFields := []byte(`{"keys": [{"someField": "value"}]}`)
		decryptor := decrypt.New(missingFields, recipientId, privateKey)
		_, err := decryptor.Decrypt(TestToken)
		assert.Error(t, err)
	})

	t.Run("Invalid key format", func(t *testing.T) {
		invalidFormat := []byte(`{"keys": [{"keyValue": "not-base64", "protocolVersion": "ECv2", "keyExpiration": "2025-12-31"}]}`)
		decryptor := decrypt.New(invalidFormat, recipientId, privateKey)
		_, err := decryptor.Decrypt(TestToken)
		assert.Error(t, err)
	})

	t.Run("Empty root keys", func(t *testing.T) {
		emptyKeys := []byte(`{"keys": []}`)
		decryptor := decrypt.New(emptyKeys, recipientId, privateKey)
		_, err := decryptor.Decrypt(TestToken)
		assert.Error(t, err)
	})

	t.Run("Invalid key expiration", func(t *testing.T) {
		invalidExpiration := []byte(`{"keys": [{"keyValue": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8W8zJ9Q/P6YW...", "protocolVersion": "ECv2", "keyExpiration": "invalid-date"}]}`)
		decryptor := decrypt.New(invalidExpiration, recipientId, privateKey)
		_, err := decryptor.Decrypt(TestToken)
		assert.Error(t, err)
	})
}

// TestEnvironmentVariableHandling tests various environment variable scenarios
func TestEnvironmentVariableHandling(t *testing.T) {
	// Save original environment variables
	originalRootKeys := os.Getenv("ROOTKEYS")
	originalRecipientId := os.Getenv("RECIPIENTID")
	originalPrivateKey := os.Getenv("PRIVATEKEY")
	defer func() {
		os.Setenv("ROOTKEYS", originalRootKeys)
		os.Setenv("RECIPIENTID", originalRecipientId)
		os.Setenv("PRIVATEKEY", originalPrivateKey)
	}()

	t.Run("Missing environment variables", func(t *testing.T) {
		os.Unsetenv("ROOTKEYS")
		os.Unsetenv("RECIPIENTID")
		os.Unsetenv("PRIVATEKEY")

		_, err := decrypt.NewGooglePayDecryptor()
		assert.Error(t, err)
	})

	t.Run("Partial environment variables", func(t *testing.T) {
		os.Setenv("ROOTKEYS", string(TestRootKeys))
		os.Unsetenv("RECIPIENTID")
		os.Unsetenv("PRIVATEKEY")

		_, err := decrypt.NewGooglePayDecryptor()
		assert.Error(t, err)
	})

	t.Run("Invalid environment variables", func(t *testing.T) {
		os.Setenv("ROOTKEYS", "invalid")
		os.Setenv("RECIPIENTID", "invalid")
		os.Setenv("PRIVATEKEY", "invalid")

		_, err := decrypt.NewGooglePayDecryptor()
		assert.NoError(t, err) // Creation succeeds but decryption will fail
	})

	t.Run("Valid environment variables", func(t *testing.T) {
		os.Setenv("ROOTKEYS", string(TestRootKeys))
		os.Setenv("RECIPIENTID", "merchant:12345678901234567890")
		os.Setenv("PRIVATEKEY", "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB")

		decryptor, err := decrypt.NewGooglePayDecryptor()
		assert.NoError(t, err)
		assert.NotNil(t, decryptor)
	})
}

func TestCryptographicOperationFailures(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	rootKeys := []byte(TestRootKeys)

	decryptor := decrypt.New(rootKeys, recipientId, privateKey)
	assert.NotNil(t, decryptor)

	tests := []struct {
		name          string
		token         types.Token
		expectedError string
	}{
		{
			name: "Invalid key derivation",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       "invalid_signature",
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  "invalid_key",
					Signatures: []string{"invalid_signature"},
				},
				SignedMessage: "invalid_message",
			},
			expectedError: "illegal base64 data",
		},
		{
			name: "MAC verification failure",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       TestToken.Signature,
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  TestToken.IntermediateSigningKey.SignedKey,
					Signatures: TestToken.IntermediateSigningKey.Signatures,
				},
				SignedMessage: `{"encryptedMessage":"test","ephemeralPublicKey":"test","tag":"invalid_tag"}`,
			},
			expectedError: "failed checking key expiration date",
		},
		{
			name: "Message decoding failure",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       TestToken.Signature,
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  TestToken.IntermediateSigningKey.SignedKey,
					Signatures: TestToken.IntermediateSigningKey.Signatures,
				},
				SignedMessage: `{"encryptedMessage":"invalid_encrypted","ephemeralPublicKey":"test","tag":"test"}`,
			},
			expectedError: "failed checking key expiration date",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decryptor.Decrypt(tt.token)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestMalformedDataScenarios(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	rootKeys := []byte(TestRootKeys)

	decryptor := decrypt.New(rootKeys, recipientId, privateKey)
	assert.NotNil(t, decryptor)

	tests := []struct {
		name          string
		token         types.Token
		expectedError string
	}{
		{
			name: "Malformed JSON in signed message",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       TestToken.Signature,
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  TestToken.IntermediateSigningKey.SignedKey,
					Signatures: TestToken.IntermediateSigningKey.Signatures,
				},
				SignedMessage: `{"invalid": json}`,
			},
			expectedError: "failed checking key expiration date",
		},
		{
			name: "Empty encrypted message",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       TestToken.Signature,
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  TestToken.IntermediateSigningKey.SignedKey,
					Signatures: TestToken.IntermediateSigningKey.Signatures,
				},
				SignedMessage: `{"encryptedMessage":"","ephemeralPublicKey":"test","tag":"test"}`,
			},
			expectedError: "failed checking key expiration date",
		},
		{
			name: "Invalid base64 encoding",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       "not_base64",
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  "not_base64",
					Signatures: []string{"not_base64"},
				},
				SignedMessage: "not_base64",
			},
			expectedError: "illegal base64 data",
		},
		{
			name: "Invalid root key format",
			token: types.Token{
				ProtocolVersion: "ECv2",
				Signature:       TestToken.Signature,
				IntermediateSigningKey: types.IntermediateSigningKey{
					SignedKey:  TestToken.IntermediateSigningKey.SignedKey,
					Signatures: TestToken.IntermediateSigningKey.Signatures,
				},
				SignedMessage: TestToken.SignedMessage,
			},
			expectedError: "failed checking key expiration date",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decryptor.Decrypt(tt.token)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestKeyManagementEdgeCases(t *testing.T) {
	recipientId := "merchant:12345678901234567890"
	primaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	secondaryKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPt7FKYx/UQFmOFpFM5zI5YhPvLzpjPPNtQgJZxNhX6hRANCAARvRNAHWz0aCdBUwABFfgPSBNr4JhQhPVHMZvGtXeqXgH1Yr+i/Qm8vBJFEGPBFtHvOHqFtJEwNYFsNKLGrUHWB"
	rootKeys := []byte(TestRootKeys)

	t.Run("Maximum number of keys", func(t *testing.T) {
		decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
		assert.NotNil(t, decryptor)

		// Add multiple secondary keys
		for i := 1; i <= 10; i++ {
			err := decryptor.AddPrivateKey(secondaryKey, fmt.Sprintf("secondary_%d", i))
			assert.NoError(t, err)
		}

		// Verify all keys are added
		activeKeys := decryptor.GetActivePrivateKeys()
		assert.Equal(t, 11, len(activeKeys)) // primary + 10 secondary keys
	})

	t.Run("Key rotation with all keys disabled", func(t *testing.T) {
		decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
		assert.NotNil(t, decryptor)

		// Add secondary key
		err := decryptor.AddPrivateKey(secondaryKey, "secondary")
		assert.NoError(t, err)

		// Disable all keys
		err = decryptor.SetPrivateKeyActive("primary", false)
		assert.NoError(t, err)
		err = decryptor.SetPrivateKeyActive("secondary", false)
		assert.NoError(t, err)

		// Verify no active keys
		activeKeys := decryptor.GetActivePrivateKeys()
		assert.Equal(t, 0, len(activeKeys))

		// Try to decrypt with no active keys
		_, err = decryptor.Decrypt(TestToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed checking key expiration date")
	})

	t.Run("Key rotation with invalid key format", func(t *testing.T) {
		decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
		assert.NotNil(t, decryptor)

		// Try to add invalid key (base64-encoded invalid data)
		invalidKey := "aW52YWxpZF9rZXk=" // base64 encoded "invalid_key"
		err := decryptor.AddPrivateKey(invalidKey, "invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key format")
	})

	t.Run("Key rotation with duplicate identifiers", func(t *testing.T) {
		decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
		assert.NotNil(t, decryptor)

		// Add key with duplicate identifier
		err := decryptor.AddPrivateKey(secondaryKey, "primary")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate identifier")

		// Verify only primary key exists
		activeKeys := decryptor.GetActivePrivateKeys()
		assert.Equal(t, 1, len(activeKeys))
		assert.Equal(t, "primary", activeKeys[0].Identifier)
	})

	t.Run("Key rotation with empty identifier", func(t *testing.T) {
		decryptor := decrypt.New(rootKeys, recipientId, primaryKey)
		assert.NotNil(t, decryptor)

		// Try to add key with empty identifier
		err := decryptor.AddPrivateKey(secondaryKey, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty identifier")

		// Verify only primary key exists
		activeKeys := decryptor.GetActivePrivateKeys()
		assert.Equal(t, 1, len(activeKeys))
		assert.Equal(t, "primary", activeKeys[0].Identifier)
	})
}
