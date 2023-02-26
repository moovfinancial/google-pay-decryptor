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
	ProtocolVersion        string                 `json:"protocolVersion" binding:"required"`
	Signature              string                 `json:"signature" binding:"required"`
	IntermediateSigningKey IntermediateSigningKey `json:"intermediateSigningKey" binding:"required"`
	SignedMessage          string                 `json:"signedMessage" binding:"required"`
}

type IntermediateSigningKey struct {
	SignedKey  string   `json:"signedKey" binding:"required"`
	Signatures []string `json:"signatures" binding:"required"`
}

type SignedKey struct {
	KeyValue      string `json:"keyValue" binding:"required"`
	KeyExpiration string `json:"keyExpiration" binding:"required"`
}

type SignedMessage struct {
	EncryptedMessage   string `json:"encryptedMessage" binding:"required"`
	EphemeralPublicKey string `json:"ephemeralPublicKey" binding:"required"`
	Tag                string `json:"tag" binding:"required"`
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
