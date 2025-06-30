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

	"github.com/stretchr/testify/assert"
	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt"
	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt/types"
)

func TestDeriveKeys(t *testing.T) {
	table := []struct {
		name, prviateKeyEncoded string
		token                   types.Token
		mac, encryptionKey      []byte
		expectError             bool
	}{
		{
			name:              "Normal case",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             TestToken,
			mac:               []byte{254, 126, 190, 74, 145, 45, 85, 141, 82, 231, 171, 227, 17, 124, 132, 162, 207, 84, 15, 123, 218, 193, 153, 156, 36, 94, 103, 61, 124, 4, 15, 138},
			encryptionKey:     []byte{50, 44, 36, 45, 28, 38, 113, 31, 125, 246, 105, 125, 109, 13, 180, 130, 65, 191, 130, 161, 251, 90, 150, 198, 177, 87, 175, 180, 124, 118, 14, 184},
			expectError:       false,
		},
		{
			name:              "Invalid Input",
			prviateKeyEncoded: "badkey",
			token:             TestToken,
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Empty Private Key",
			prviateKeyEncoded: "",
			token:             TestToken,
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Empty Token",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid Token Protocol Version",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{ProtocolVersion: "InvalidVersion"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid Ephemeral Public Key",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "invalid_signed_message"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid Base64 in SignedMessage",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"!@#$%^&*\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid ECDSA Key",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"AQID\"}"}, // Valid base64 but invalid ECDSA key
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid Private Key",
			prviateKeyEncoded: "invalid_key",
			token:             TestToken,
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid Signed Message",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "invalid_json"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid Ephemeral Public Key Format",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"invalid_format\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid Shared Secret Computation",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWHE6JlhsOFbQff7hBwZT8IaE6XoOoY3/UCQqVNu+vr7+ekqRLVWNUuer4xF8hKLPVA972sGZnCReZz18BA+KAw==\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid Base64 Decode",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"!@#$%^&*()_+\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid HKDF Computation",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"AAAA\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid MAC Key Generation",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"AQIDBAU=\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid HKDF Output",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid HKDF Output Length",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid MAC Key Length",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid HKDF Input Empty",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid HKDF Input Single Byte",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"AA==\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid HKDF Input Invalid Base64",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"!@#$\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Invalid MAC Key Generation Empty Input",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}"},
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Protocol Version Case Sensitivity",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{ProtocolVersion: "EcV2"}, // Different casing
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "Protocol Version With Special Characters",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{ProtocolVersion: "ECv2!"}, // With special character
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "SignedMessage Missing Required Fields",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{}"}, // Missing ephemeralPublicKey
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "SignedMessage With Extra Fields",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"AAAA\",\"extraField\":\"value\"}"}, // Extra unexpected field
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "SignedMessage With Nested JSON",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":{\"key\":\"AAAA\"}}"}, // Nested object where string expected
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "SignedMessage With Array Value",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":[\"AAAA\"]}"}, // Array where string expected
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
		{
			name:              "ECDSA Key With Invalid Size",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             types.Token{SignedMessage: "{\"ephemeralPublicKey\":\"A\"}"}, // Too short for valid key
			mac:               []byte{0, 0},
			encryptionKey:     []byte{0, 0, 0},
			expectError:       true,
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			mac, encryptionKey, err := decrypt.DeriveKeys(tb.token, tb.prviateKeyEncoded)
			if err != nil && !tb.expectError {
				t.Errorf("expected no error, got %v", err)
			}

			if err == nil && tb.expectError {
				t.Errorf("expected error, got nil")
			}

			if !tb.expectError {
				if !assert.Equal(t, tb.mac, mac) {
					t.Errorf("actual mac does not match expected mac")
				}

				if !assert.Equal(t, tb.encryptionKey, encryptionKey) {
					t.Errorf("actual encryption key does not match expected encryption key")
				}
			}
		})
	}
}
