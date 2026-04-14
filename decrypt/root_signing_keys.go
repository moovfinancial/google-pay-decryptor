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

	"github.com/moovfinancial/google-pay-decryptor/decrypt/types"
)

type RootSigningKey struct{}

func (r *RootSigningKey) Filter(rootKeys []byte) ([]types.RootKeys, []string, error) {
	return loadRootSigningKeys(rootKeys)
}

func loadRootSigningKeys(rootKeys []byte) ([]types.RootKeys, []string, error) {
	var keys types.RootSigningKey
	if err := json.Unmarshal(rootKeys, &keys); err != nil {
		return nil, nil, fmt.Errorf("failed to parse root keys JSON: %w", err)
	}
	var ecv2Keys []types.RootKeys
	var keyValues []string
	for _, key := range keys.RootKeys {
		if key.ProtocolVersion == "ECv2" {
			ecv2Keys = append(ecv2Keys, key)
			keyValues = append(keyValues, key.KeyValue)
		}
	}
	if len(ecv2Keys) == 0 {
		return nil, nil, ErrParseJson
	}
	return ecv2Keys, keyValues, nil
}
