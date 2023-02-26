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

	"github.com/m1crogravity/google-pay-decryptor/decrypt"
	"github.com/m1crogravity/google-pay-decryptor/decrypt/types"
	"github.com/stretchr/testify/assert"
)

func TestDeriveKeys(t *testing.T) {
	table := []struct {
		name, prviateKeyEncoded string
		token                   types.Token
		mac, encryptionKey      []byte
	}{
		{
			name:              "Normal case",
			prviateKeyEncoded: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVXmgr0TkF+YKxR9Hqk1oN/YrBHoHIY+fvPEnrdS1fb+hRANCAATLt+0tx4HUcMrQkq/D45PNREgAS9+zUP8iUbCl9dt4sQhaZyGmt47TcyJaFLwSUwcSxrYQ9MW7BiU9z1e2NkCB",
			token:             TestToken,
			mac:               []byte{254, 126, 190, 74, 145, 45, 85, 141, 82, 231, 171, 227, 17, 124, 132, 162, 207, 84, 15, 123, 218, 193, 153, 156, 36, 94, 103, 61, 124, 4, 15, 138},
			encryptionKey:     []byte{50, 44, 36, 45, 28, 38, 113, 31, 125, 246, 105, 125, 109, 13, 180, 130, 65, 191, 130, 161, 251, 90, 150, 198, 177, 87, 175, 180, 124, 118, 14, 184},
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			mac, encryptionKey, err := decrypt.DeriveKeys(tb.token, tb.prviateKeyEncoded)
			if err != nil {
				t.Log(err)
			}

			if !assert.Equal(t, tb.mac, mac) {
				t.Errorf("actual mac does not match expected mac")
			}

			if !assert.Equal(t, tb.encryptionKey, encryptionKey) {
				t.Errorf("actual encryption key does not match expected encryption key")
			}
		})
	}
}
