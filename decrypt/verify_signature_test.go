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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt"
	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt/types"
)

// ecdsaSignature represents the ASN.1 structure of an ECDSA signature
type ecdsaSignature struct {
	R, S *big.Int
}

func TestVerifySignature(t *testing.T) {
	table := []struct {
		name, receipientId string
		token              types.Token
		keyValues          []string
		expectError        bool
	}{
		{
			name:         "Invalid signature",
			receipientId: "merchant:12345678901234567890",
			keyValues:    []string{"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4/A=="},
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
			name:         "Empty key values",
			receipientId: "merchant:12345678901234567890",
			keyValues:    []string{},
			token:        TestToken,
			expectError:  true,
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			err := decrypt.VerifySignature(tb.token, tb.keyValues, tb.receipientId)
			if tb.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestVerifyMessageSignature(t *testing.T) {
	// Generate a test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Convert public key to PKIX format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	testKey := base64.StdEncoding.EncodeToString(publicKeyBytes)

	// Test parameters
	testMessage := "test_message"
	protocolVersion := "ECv2"
	senderID := "Google"
	recipientID := "merchant:12345678901234567890"

	// Create signed data in the same format as verifyMessageSignature
	signedData := decrypt.ConstructSignature(senderID, recipientID, protocolVersion, testMessage)

	// Hash the signed data before signing
	hash := sha256.Sum256(signedData)

	// Sign the hash of the constructed data
	signatureR, signatureS, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Encode signature in ASN.1 DER format
	sig := ecdsaSignature{R: signatureR, S: signatureS}
	signature, err := asn1.Marshal(sig)
	if err != nil {
		t.Fatalf("Failed to marshal signature: %v", err)
	}
	testSignature := base64.StdEncoding.EncodeToString(signature)

	table := []struct {
		name         string
		keyValue     string
		token        types.Token
		receipientId string
		expectError  bool
	}{
		{
			name:     "Valid signature",
			keyValue: testKey,
			token: types.Token{
				ProtocolVersion: protocolVersion,
				Signature:       testSignature,
				SignedMessage:   testMessage,
			},
			receipientId: recipientID,
			expectError:  false,
		},
		{
			name:     "Invalid public key",
			keyValue: "invalid_key",
			token: types.Token{
				ProtocolVersion: protocolVersion,
				Signature:       testSignature,
				SignedMessage:   testMessage,
			},
			receipientId: recipientID,
			expectError:  true,
		},
		{
			name:     "Invalid signature format",
			keyValue: testKey,
			token: types.Token{
				ProtocolVersion: protocolVersion,
				Signature:       "invalid_signature",
				SignedMessage:   testMessage,
			},
			receipientId: recipientID,
			expectError:  true,
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			err := decrypt.VerifyMessageSignature(tb.keyValue, tb.token, tb.receipientId)
			if tb.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Error(err)
			}
		})
	}
}
