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

func TestFilter(t *testing.T) {
	table := []struct {
		name            string
		rootKeys        []byte
		rootSigningKeys types.RootKeys
		keyValues       []string
	}{
		{
			name:     "Loading development root signing keys",
			rootKeys: []byte(TestRootKeys),
			rootSigningKeys: types.RootKeys{
				KeyValue:        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnJ7Yo1sX9b4kr4Aa5uq58JRQfzD8bIJXw7WXaap/hVE+PnFxvjx4nVxt79SdRuUVeu++HZD0cGAv4IOznc96w==",
				ProtocolVersion: "ECv2",
				KeyExpiration:   "2154841200000",
			},
			keyValues: []string{
				"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4/A==",
				"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnJ7Yo1sX9b4kr4Aa5uq58JRQfzD8bIJXw7WXaap/hVE+PnFxvjx4nVxt79SdRuUVeu++HZD0cGAv4IOznc96w==",
				"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnJ7Yo1sX9b4kr4Aa5uq58JRQfzD8bIJXw7WXaap/hVE+PnFxvjx4nVxt79SdRuUVeu++HZD0cGAv4IOznc96w==",
			},
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			var rootKeys decrypt.RootSigningKey
			rootSigningKeys, keyValues, err := rootKeys.Filter(tb.rootKeys)
			if err != nil {
				t.Error(err)
			}

			if !assert.Equal(t, rootSigningKeys, tb.rootSigningKeys) {
				t.Errorf("loaded keys are incorrect or does not match expected one")
			}

			if !assert.Equal(t, tb.keyValues, keyValues) {
				t.Errorf("actual keyvalues are incorrect or does not match expected one")
			}
		})
	}
}
