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
	"errors"
	"fmt"
	"os"

	"github.com/m1crogravity/google-pay-decryptor/decrypt/types"
)

type GooglePayDecryptor struct {
	rootKeys    []byte
	recipientId string
	privateKey  string
}

func New(rootKeys []byte, recipientId string, privateKey string) *GooglePayDecryptor {
	return &GooglePayDecryptor{
		rootKeys:    rootKeys,
		recipientId: recipientId,
		privateKey:  privateKey,
	}
}

func Init(rootKeys []byte, recipientId string, privateKey string) {
	os.Setenv("ROOTKEYS", string(rootKeys))
	os.Setenv("RECIPIENTID", recipientId)
	os.Setenv("PRIVATEKEY", privateKey)
}

func NewGooglePayDecryptor() (*GooglePayDecryptor, error) {
	rootkeys := []byte(os.Getenv("ROOTKEYS"))
	recipientId := os.Getenv("RECIPIENTID")
	privateKey := os.Getenv("PRIVATEKEY")
	if rootkeys == nil && recipientId == "" && privateKey == "" {
		return nil, types.ErrLoadingKeys
	}
	return New(rootkeys, recipientId, privateKey), nil
}

func (g *GooglePayDecryptor) Decrypt(token types.Token) (types.Decrypted, error) {
	// Load root singning keys
	var rootKeys RootSigningKey
	rootSigningKeys, keyValues, err := rootKeys.Filter(g.rootKeys)
	if err != nil {
		return types.Decrypted{}, err
	}

	if err := VerifySignature(token, keyValues, g.recipientId); err != nil {
		return types.Decrypted{}, err
	}

	// check time and verify signature
	if !CheckTime(rootSigningKeys.KeyExpiration) {
		return types.Decrypted{}, types.ErrValidateTime
	}

	// derive mac and encryption keys
	mac, encryptionKey, err := DeriveKeys(token, g.privateKey)
	if err != nil {
		return types.Decrypted{}, err
	}

	signedMessage, _ := token.UnmarshalSignedMessage(token.SignedMessage)
	// verify mac
	if err := VerifyMessageHmac(mac, signedMessage.Tag, signedMessage.EncryptedMessage); err != nil {
		return types.Decrypted{}, err
	}

	// Decode message with encryptionKey
	decodedMessage, err := Decode(encryptionKey, signedMessage.EncryptedMessage)
	if err != nil {
		return types.Decrypted{}, err
	}

	var decrypted types.Decrypted
	err = json.Unmarshal(decodedMessage, &decrypted)
	if err != nil {
		var newError string
		if e, ok := err.(*json.SyntaxError); ok {
			newError = fmt.Sprintf("syntax error at byte offset %d", e.Offset)
		}
		return types.Decrypted{}, errors.New(newError)
	}

	return decrypted, nil
}
