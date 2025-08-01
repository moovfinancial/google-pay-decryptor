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

package types

import (
	"encoding/json"
)

type Token struct {
	ProtocolVersion        string                 `json:"protocolVersion"`
	Signature              string                 `json:"signature"`
	IntermediateSigningKey IntermediateSigningKey `json:"intermediateSigningKey,omitempty"`
	SignedMessage          string                 `json:"signedMessage"`
}

type IntermediateSigningKey struct {
	SignedKey  string   `json:"signedKey"`
	Signatures []string `json:"signatures"`
}

type SignedKey struct {
	KeyValue      string `json:"keyValue"`
	KeyExpiration string `json:"keyExpiration"`
}

type SignedMessage struct {
	EncryptedMessage   string `json:"encryptedMessage"`
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Tag                string `json:"tag"`
}

func (t *Token) UnmarshalSignedMessage(s string) (result SignedMessage, err error) {
	err = json.Unmarshal([]byte(s), &result)
	if err != nil {
		return SignedMessage{}, err
	}
	return result, nil
}

func (t *IntermediateSigningKey) UnmarshalSignedKey(s string) (result SignedKey, err error) {
	err = json.Unmarshal([]byte(s), &result)
	if err != nil {
		return SignedKey{}, err
	}
	return result, nil
}
