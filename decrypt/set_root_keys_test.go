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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moov-io/google-pay-decryptor/decrypt"
	"github.com/moov-io/google-pay-decryptor/testtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Shared test fixtures for set_root_keys_test.go. Pulled to file scope so the
// per-test setup blocks don't drift out of sync.
const (
	setRootKeysTestRecipientId = "merchant:12345678901234567890"
	setRootKeysTestPrivateKey  = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
)

// alternateValidRootKeys is a different but structurally valid set of ECv2 root keys
// (different keyValue and a far-future expiration). It is JSON-valid and parseable by
// loadRootSigningKeys, so SetRootKeys should accept it.
const alternateValidRootKeys = `{"keys":[{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHuVqzL+RlS7yIzllOQy/Ev1bfDOLk5LybGmL5RlMfFHAh//WPwQYrgYxV7K4u+ipxr6vfDi3HhExZ7sTzxr5lA==","protocolVersion":"ECv2","keyExpiration":"2154841200000"}]}`

func TestSetRootKeys_validJSONUpdatesStoredKeys(t *testing.T) {
	// Setup
	decryptor := decrypt.New([]byte(TestRootKeys), setRootKeysTestRecipientId, setRootKeysTestPrivateKey)
	require.NotNil(t, decryptor)

	// Execute
	err := decryptor.SetRootKeys([]byte(alternateValidRootKeys))

	// Verify
	require.NoError(t, err)
	got := decryptor.RootKeys()
	assert.Equal(t, []byte(alternateValidRootKeys), got)
}

func TestSetRootKeys_malformedJSONReturnsErrorAndLeavesPriorKeysIntact(t *testing.T) {
	// Setup
	decryptor := decrypt.New([]byte(TestRootKeys), setRootKeysTestRecipientId, setRootKeysTestPrivateKey)
	require.NotNil(t, decryptor)
	originalKeys := decryptor.RootKeys()
	require.Equal(t, []byte(TestRootKeys), originalKeys)

	tests := []struct {
		name     string
		rootKeys []byte
	}{
		{
			name:     "malformed JSON",
			rootKeys: []byte(`{"keys":`),
		},
		{
			name:     "no ECv2 keys",
			rootKeys: []byte(`{"keys":[{"keyValue":"abc","protocolVersion":"ECv1"}]}`),
		},
		{
			name:     "empty bytes",
			rootKeys: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			err := decryptor.SetRootKeys(tt.rootKeys)

			// Verify
			require.Error(t, err)
			// Prior keys are still intact.
			assert.Equal(t, originalKeys, decryptor.RootKeys())
			// Decrypt still proceeds with original keys (it will fail on token expiration,
			// but the error path proves the original ECv2 root keys were loaded).
			_, derr := decryptor.Decrypt(TestToken)
			require.Error(t, derr)
			assert.NotContains(t, derr.Error(), "failed to load root signing keys")
		})
	}
}

func TestSetRootKeys_concurrentDecryptAndSetRootKeysIsRaceFree(t *testing.T) {
	// Setup
	decryptor := decrypt.New([]byte(TestRootKeys), setRootKeysTestRecipientId, setRootKeysTestPrivateKey)
	require.NotNil(t, decryptor)

	const decryptorWorkers = 8
	var (
		stop      atomic.Bool
		wg        sync.WaitGroup
		panicSeen atomic.Bool
	)

	// Execute: fire decrypt goroutines.
	for i := 0; i < decryptorWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicSeen.Store(true)
				}
			}()
			for !stop.Load() {
				// Errors are expected — we're racing against state changes —
				// but Decrypt must never panic.
				_, _ = decryptor.Decrypt(TestToken)
			}
		}()
	}

	// Repeatedly swap root keys.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				panicSeen.Store(true)
			}
		}()
		toggle := false
		for !stop.Load() {
			var keys []byte
			if toggle {
				keys = []byte(alternateValidRootKeys)
			} else {
				keys = []byte(TestRootKeys)
			}
			toggle = !toggle
			_ = decryptor.SetRootKeys(keys)
		}
	}()

	// Let them race for a brief window.
	time.Sleep(100 * time.Millisecond)
	stop.Store(true)
	wg.Wait()

	// Verify
	assert.False(t, panicSeen.Load(), "no goroutine should panic during concurrent Decrypt + SetRootKeys")
}

// TestSetRootKeys_decryptPicksUpNewKeysAfterSwap exercises the full SetRootKeys
// contract: a token signed with a known root must verify when the decryptor is
// configured with the matching root, and must be rejected (with a signature
// error) once SetRootKeys has swapped to a non-matching root. The reverse
// direction — starting from a mismatched root, then swapping to the matching
// one — must flip a previously failing decryption to success.
func TestSetRootKeys_decryptPicksUpNewKeysAfterSwap(t *testing.T) {
	// Setup: use the round-trip-capable test config from the testtoken package
	// so we control which root keys actually sign the generated token.
	cfg := testtoken.DefaultConfig()
	gen, err := testtoken.NewGenerator(cfg)
	require.NoError(t, err)

	token, err := gen.Generate(testtoken.PaymentData{
		PAN:             "4111111111111111",
		ExpirationMonth: 12,
		ExpirationYear:  2030,
		AuthMethod:      "PAN_ONLY",
		CardNetwork:     "VISA",
	})
	require.NoError(t, err)

	t.Run("matching root then swap to non-matching root", func(t *testing.T) {
		// Decryptor starts on the matching root: decryption must succeed.
		decryptor := decrypt.New([]byte(cfg.RootKeysJSON), cfg.RecipientID, cfg.RecipientPrivateKey)
		require.NotNil(t, decryptor)

		decrypted, err := decryptor.Decrypt(token)
		require.NoError(t, err, "token signed with the configured root must verify and decrypt")
		require.Equal(t, "4111111111111111", decrypted.PaymentMethodDetails.Pan)

		// Execute: swap to a structurally valid but non-matching root.
		require.NoError(t, decryptor.SetRootKeys([]byte(alternateValidRootKeys)))
		assert.Equal(t, []byte(alternateValidRootKeys), decryptor.RootKeys())

		// Verify: the same token, previously valid, is now rejected at signature
		// verification (the intermediate signing key was signed by the original
		// root and can't be verified by alternateValidRootKeys).
		_, err = decryptor.Decrypt(token)
		require.Error(t, err, "after swap to non-matching root, previously valid token must be rejected")
		assert.Contains(t, err.Error(), "failed to verify signature",
			"rejection reason should be signature verification failure, got: %v", err)
		assert.NotContains(t, err.Error(), "all root signing keys are expired")
	})

	t.Run("non-matching root then swap to matching root", func(t *testing.T) {
		// Decryptor starts on a mismatched root: decryption must fail with a
		// signature verification error.
		decryptor := decrypt.New([]byte(alternateValidRootKeys), cfg.RecipientID, cfg.RecipientPrivateKey)
		require.NotNil(t, decryptor)

		_, err := decryptor.Decrypt(token)
		require.Error(t, err, "token must be rejected when decryptor's root doesn't match the signing root")
		assert.Contains(t, err.Error(), "failed to verify signature",
			"rejection reason should be signature verification failure, got: %v", err)

		// Execute: swap to the matching root.
		require.NoError(t, decryptor.SetRootKeys([]byte(cfg.RootKeysJSON)))
		assert.Equal(t, []byte(cfg.RootKeysJSON), decryptor.RootKeys())

		// Verify: the previously failing token now decrypts successfully —
		// proves Decrypt actually picks up the swapped-in keys.
		decrypted, err := decryptor.Decrypt(token)
		require.NoError(t, err, "after swap to matching root, token must verify and decrypt")
		assert.Equal(t, "4111111111111111", decrypted.PaymentMethodDetails.Pan)
	})
}

func TestRootKeys_returnsDefensiveCopy(t *testing.T) {
	// Setup
	decryptor := decrypt.New([]byte(TestRootKeys), setRootKeysTestRecipientId, setRootKeysTestPrivateKey)

	// Execute
	got := decryptor.RootKeys()
	require.NotEmpty(t, got)
	got[0] = 'X' // mutate the returned slice

	// Verify: subsequent reads see unmutated bytes.
	again := decryptor.RootKeys()
	assert.Equal(t, []byte(TestRootKeys), again)
}
