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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// alternateValidRootKeys is a different but structurally valid set of ECv2 root keys
// (different keyValue and a far-future expiration). It is JSON-valid and parseable by
// loadRootSigningKeys, so SetRootKeys should accept it.
const alternateValidRootKeys = `{"keys":[{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHuVqzL+RlS7yIzllOQy/Ev1bfDOLk5LybGmL5RlMfFHAh//WPwQYrgYxV7K4u+ipxr6vfDi3HhExZ7sTzxr5lA==","protocolVersion":"ECv2","keyExpiration":"2154841200000"}]}`

func TestSetRootKeys_validJSONUpdatesStoredKeys(t *testing.T) {
	// Setup
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	decryptor := decrypt.New([]byte(TestRootKeys), recipientId, privateKey)
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
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	decryptor := decrypt.New([]byte(TestRootKeys), recipientId, privateKey)
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
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	decryptor := decrypt.New([]byte(TestRootKeys), recipientId, privateKey)
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

func TestSetRootKeys_decryptPicksUpNewKeysAfterSwap(t *testing.T) {
	// Setup
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"

	// Start with root keys whose only ECv2 entry is already expired. Decrypt must
	// fail with "all root signing keys are expired".
	expiredRootKeys := []byte(`{"keys":[{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnJ7Yo1sX9b4kr4Aa5uq58JRQfzD8bIJXw7WXaap/hVE+PnFxvjx4nVxt79SdRuUVeu++HZD0cGAv4IOznc96w==","protocolVersion":"ECv2","keyExpiration":"1000000000000"}]}`)
	decryptor := decrypt.New(expiredRootKeys, recipientId, privateKey)
	require.NotNil(t, decryptor)

	_, err := decryptor.Decrypt(TestToken)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all root signing keys are expired")

	// Execute: swap to non-expired root keys.
	require.NoError(t, decryptor.SetRootKeys([]byte(TestRootKeys)))

	// Verify: getter reflects the swap and Decrypt now advances past the expiration
	// gate (it will fail downstream because the test token itself is unsigned for
	// these keys, but the "all root signing keys are expired" error must be gone).
	assert.Equal(t, []byte(TestRootKeys), decryptor.RootKeys())
	_, err = decryptor.Decrypt(TestToken)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "all root signing keys are expired")
}

func TestRootKeys_returnsDefensiveCopy(t *testing.T) {
	// Setup
	recipientId := "merchant:12345678901234567890"
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB"
	decryptor := decrypt.New([]byte(TestRootKeys), recipientId, privateKey)

	// Execute
	got := decryptor.RootKeys()
	require.NotEmpty(t, got)
	got[0] = 'X' // mutate the returned slice

	// Verify: subsequent reads see unmutated bytes.
	again := decryptor.RootKeys()
	assert.Equal(t, []byte(TestRootKeys), again)
}
