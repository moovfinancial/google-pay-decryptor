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
	"io"
	"net/http"
	"os"
	"time"

	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt/types"
)

// https://developers.google.com/pay/api/processors/guides/implementation/validate-decryption-google
const (
	TestRootKeysUrl              = "https://payments.developers.google.com/paymentmethodtoken/test/keys.json"
	ProductionRootKeysUrl        = "https://payments.developers.google.com/paymentmethodtoken/keys.json"
	GooglePaySenderID            = "Google"
	GooglePayECCType             = "NIST_P256"
	GooglePayUncompressedFormat  = "UNCOMPRESSED"
	GooglePaySHA256HashAlgorithm = "SHA256"
	GooglePayDEREncoding         = "DER"
)

type Environment string

const (
	EnvironmentTest       Environment = "test"
	EnvironmentProduction Environment = "production"
)

// HTTPClient is an interface for making HTTP requests
type HTTPClient interface {
	Get(url string) (*http.Response, error)
}

// DefaultHTTPClient is the default HTTP client used for making requests
var DefaultHTTPClient HTTPClient = &http.Client{}

// KeyEntry represents a private key with metadata
type KeyEntry struct {
	Key        string    // The actual private key in PKCS8 format
	CreatedAt  time.Time // When the key was created
	IsActive   bool      // Whether this key is currently active
	Identifier string    // Optional identifier for the key
}

type GooglePayDecryptor struct {
	rootKeys    []byte
	recipientId string
	privateKeys []KeyEntry // Slice of private keys, ordered by priority
}

func New(rootKeys []byte, recipientId string, privateKey string) *GooglePayDecryptor {
	keys := []KeyEntry{
		{
			Key:        privateKey,
			CreatedAt:  time.Now(),
			IsActive:   true,
			Identifier: "primary",
		},
	}
	return &GooglePayDecryptor{
		rootKeys:    rootKeys,
		recipientId: recipientId,
		privateKeys: keys,
	}
}

func NewGooglePayDecryptor() (*GooglePayDecryptor, error) {
	rootkeys := []byte(os.Getenv("ROOTKEYS"))
	recipientId := os.Getenv("RECIPIENTID")
	privateKey := os.Getenv("PRIVATEKEY")
	if rootkeys == nil || recipientId == "" || privateKey == "" {
		return nil, ErrLoadingKeys
	}
	return New(rootkeys, recipientId, privateKey), nil
}

func NewWithRootKeysFromGoogle(environment Environment, recipientId string, privateKey string) (*GooglePayDecryptor, error) {
	rootkeys, err := FetchGoogleRootKeys(environment)
	if err != nil {
		return nil, err
	}

	if rootkeys == nil || recipientId == "" || privateKey == "" {
		return nil, ErrLoadingKeys
	}
	return New(rootkeys, recipientId, privateKey), nil
}

// AddPrivateKey adds a new private key to the decryptor
func (g *GooglePayDecryptor) AddPrivateKey(key string, identifier string) error {
	if key == "" {
		return errors.New("empty key")
	}

	if identifier == "" {
		return errors.New("empty identifier")
	}

	// Check for duplicate identifier
	for _, existingKey := range g.privateKeys {
		if existingKey.Identifier == identifier {
			return fmt.Errorf("duplicate identifier: %s", identifier)
		}
	}

	// Validate key format
	var privK PrivateKey
	_, err := privK.LoadKey(key)
	if err != nil {
		return fmt.Errorf("invalid key format: %w", err)
	}

	newKey := KeyEntry{
		Key:        key,
		CreatedAt:  time.Now(),
		IsActive:   true,
		Identifier: identifier,
	}

	g.privateKeys = append(g.privateKeys, newKey)
	return nil
}

// SetPrivateKeyActive sets the active state of a key by its identifier
func (g *GooglePayDecryptor) SetPrivateKeyActive(identifier string, active bool) error {
	for i := range g.privateKeys {
		if g.privateKeys[i].Identifier == identifier {
			g.privateKeys[i].IsActive = active
			return nil
		}
	}
	return fmt.Errorf("key with identifier %s not found", identifier)
}

// GetActivePrivateKeys returns all active private keys
func (g *GooglePayDecryptor) GetActivePrivateKeys() []KeyEntry {
	var activeKeys []KeyEntry
	for _, key := range g.privateKeys {
		if key.IsActive {
			activeKeys = append(activeKeys, key)
		}
	}
	return activeKeys
}

// FetchGoogleRootKeys retrieves the root keys from Google's servers for the specified environment.
func FetchGoogleRootKeys(environment Environment) ([]byte, error) {
	var resp *http.Response
	var err error

	switch environment {
	case EnvironmentTest:
		resp, err = DefaultHTTPClient.Get(TestRootKeysUrl)
	case EnvironmentProduction:
		resp, err = DefaultHTTPClient.Get(ProductionRootKeysUrl)
	default:
		return nil, fmt.Errorf("invalid environment: %s", environment)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to fetch root keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch root keys, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

func (g *GooglePayDecryptor) DecryptWithMerchantId(token types.Token, merchantId string) (types.Decrypted, error) {
	// Decrypt the test payload
	decryptedToken, err := g.Decrypt(token) // input is payload as []byte
	if err != nil {
		return types.Decrypted{}, err
	}

	// Check the Merchant ID
	if decryptedToken.GatewayMerchantId != merchantId {
		return types.Decrypted{}, fmt.Errorf("merchant ID mismatch: %s != %s", decryptedToken.GatewayMerchantId, merchantId)
	}

	return decryptedToken, nil
}

// Decrypt automatically detects the token format and routes to the appropriate decryption method
func (g *GooglePayDecryptor) Decrypt(token types.Token) (types.Decrypted, error) {
	switch token.ProtocolVersion {
	case "ECv1":
		return g.DecryptECv1(token)
	case "ECv2":
		return g.DecryptECv2(token)
	default:
		return types.Decrypted{}, fmt.Errorf("unable to determine token format")
	}
}

// DecryptECv2 decrypts an ECv2 token
func (g *GooglePayDecryptor) DecryptECv2(token types.Token) (types.Decrypted, error) {
	// Load root singning keys
	var rootKeys RootSigningKey
	rootSigningKeys, keyValues, err := rootKeys.Filter(g.rootKeys)
	if err != nil {
		return types.Decrypted{}, fmt.Errorf("could not verify intermediate signing key signature: %w", err)
	}

	if err := VerifySignature(token, keyValues, g.recipientId); err != nil {
		return types.Decrypted{}, fmt.Errorf("could not verify intermediate signing key signature: %w", err)
	}

	// check key expiration and verify signature
	if !CheckTime(rootSigningKeys.KeyExpiration) {
		return types.Decrypted{}, fmt.Errorf("could not verify intermediate signing key signature: %w", ErrValidateTimeKey)
	}

	// Try each active key in sequence
	var lastErr error
	for _, keyEntry := range g.privateKeys {
		if !keyEntry.IsActive {
			continue
		}

		// derive mac and encryption keys
		mac, encryptionKey, err := DeriveKeys(token, keyEntry.Key)
		if err != nil {
			lastErr = err
			continue
		}

		signedMessage, _ := token.UnmarshalSignedMessage(token.SignedMessage)
		// verify mac
		if err := VerifyMessageHmac(mac, signedMessage.Tag, signedMessage.EncryptedMessage); err != nil {
			lastErr = err
			continue
		}

		// Decode message with encryptionKey
		decodedMessage, err := Decode(encryptionKey, signedMessage.EncryptedMessage)
		if err != nil {
			lastErr = err
			continue
		}

		var decrypted types.Decrypted
		err = json.Unmarshal(decodedMessage, &decrypted)
		if err != nil {
			var newError string
			if e, ok := err.(*json.SyntaxError); ok {
				newError = fmt.Sprintf("syntax error at byte offset %d", e.Offset)
			}
			lastErr = errors.New(newError)
			continue
		}

		// check message expiration
		if !CheckTime(decrypted.MessageExpiration) {
			return types.Decrypted{}, fmt.Errorf("could not verify intermediate signing key signature: %w", ErrValidateTimeMessage)
		}

		// If we get here, the message has been successfully decrypted and validated
		return decrypted, nil
	}

	// If we get here, none of the keys worked
	if lastErr != nil {
		return types.Decrypted{}, fmt.Errorf("failed to decrypt with any key: %w", lastErr)
	}
	return types.Decrypted{}, errors.New("no active keys available for decryption")
}
