// Package testtoken generates valid Google Pay ECv2 test tokens for integration testing.
//
// It implements the encryption side of the ECv2 protocol, producing tokens that can be
// decrypted by the decrypt package when configured with the matching test keys.
//
// Usage:
//
//	gen := testtoken.NewGenerator(testtoken.DefaultConfig())
//	token, err := gen.Generate(testtoken.PaymentData{
//	    PAN:             "4111111111111111",
//	    ExpirationMonth: 12,
//	    ExpirationYear:  2027,
//	    AuthMethod:      "PAN_ONLY",
//	    CardNetwork:     "VISA",
//	})
//
// The generator creates tokens using self-signed test keys. Use DefaultConfig() to get
// a configuration whose RootKeys and RecipientPrivateKey are pre-matched. Pass the
// RootKeysJSON to decrypt.New() and the RecipientID to the decryptor for round-trip testing.
package testtoken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	subsig "github.com/google/tink/go/signature/subtle"
	"github.com/moovfinancial/google-pay-decryptor/decrypt/types"
	"golang.org/x/crypto/hkdf"
)

const (
	senderID        = "Google"
	protocolVersion = "ECv2"
)

// Config holds the keys needed to generate test tokens.
type Config struct {
	// RootPrivateKey is a PEM-less, base64-encoded PKCS8 ECDSA private key used as the
	// "Google root signing key" for test purposes. Its public key appears in RootKeysJSON.
	RootPrivateKey string

	// RootKeysJSON is the JSON root signing keys document (same format as Google publishes).
	// Pass this to decrypt.New() as the rootKeys parameter.
	RootKeysJSON string

	// RecipientPrivateKey is a base64-encoded PKCS8 ECDSA private key for the merchant/recipient.
	// The decryptor must be configured with this key.
	RecipientPrivateKey string

	// RecipientID is the identifier passed to decrypt.New() (e.g. "merchant:12345678901234567890").
	RecipientID string

	// GatewayMerchantID is the value placed in the decrypted payload's gatewayMerchantId field.
	GatewayMerchantID string
}

// PaymentData describes the card details to embed in the test token.
type PaymentData struct {
	PAN             string
	ExpirationMonth int
	ExpirationYear  int
	AuthMethod      string // e.g. "PAN_ONLY", "CRYPTOGRAM_3DS"
	CardNetwork     string // e.g. "VISA", "MASTERCARD"
	CardDetails     string // last 4 digits (optional, derived from PAN if empty)
	Cryptogram      string // only for CRYPTOGRAM_3DS
	EciIndicator    string // only for CRYPTOGRAM_3DS
}

// Generator creates valid ECv2 test tokens.
type Generator struct {
	cfg              Config
	rootKey          *ecdsa.PrivateKey
	recipientPubKey  *ecdsa.PublicKey
}

// NewGenerator creates a Generator from the given Config.
func NewGenerator(cfg Config) (*Generator, error) {
	rootKey, err := loadPrivateKey(cfg.RootPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("loading root private key: %w", err)
	}

	recipientKey, err := loadPrivateKey(cfg.RecipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("loading recipient private key: %w", err)
	}

	return &Generator{
		cfg:             cfg,
		rootKey:         rootKey,
		recipientPubKey: &recipientKey.PublicKey,
	}, nil
}

// Generate produces a valid ECv2 token that can be decrypted by the decrypt package.
func (g *Generator) Generate(pd PaymentData) (types.Token, error) {
	// 1. Build the plaintext payment data
	now := time.Now()
	expiration := strconv.FormatInt((now.Add(24*time.Hour).UnixMilli()), 10)

	decrypted := types.Decrypted{
		GatewayMerchantId:    g.cfg.GatewayMerchantID,
		MessageExpiration:    expiration,
		MessageId:            fmt.Sprintf("test-%d", now.UnixNano()),
		PaymentMethod:        "CARD",
		PaymentMethodDetails: types.PaymentMethodDetails{
			Pan:             pd.PAN,
			ExpirationMonth: pd.ExpirationMonth,
			ExpirationYear:  pd.ExpirationYear,
			AuthMethod:      pd.AuthMethod,
			CardNetwork:     pd.CardNetwork,
			CardDetails:     pd.CardDetails,
			Cryptogram:      pd.Cryptogram,
			EciIndicator:    pd.EciIndicator,
		},
	}
	if decrypted.PaymentMethodDetails.CardDetails == "" && len(pd.PAN) >= 4 {
		decrypted.PaymentMethodDetails.CardDetails = pd.PAN[len(pd.PAN)-4:]
	}

	plaintext, err := json.Marshal(decrypted)
	if err != nil {
		return types.Token{}, fmt.Errorf("marshaling payment data: %w", err)
	}

	// 2. Generate ephemeral key pair
	ephemeralKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return types.Token{}, fmt.Errorf("generating ephemeral key: %w", err)
	}

	// 3. Compute shared secret via ECDH
	sharedX, _ := elliptic.P256().ScalarMult(g.recipientPubKey.X, g.recipientPubKey.Y, ephemeralKey.D.Bytes())
	if sharedX == nil {
		return types.Token{}, fmt.Errorf("computing shared secret: point at infinity")
	}
	sharedSecret := make([]byte, 32)
	sharedX.FillBytes(sharedSecret)

	// 4. Encode ephemeral public key (uncompressed point)
	ephemeralPubBytes := elliptic.Marshal(elliptic.P256(), ephemeralKey.PublicKey.X, ephemeralKey.PublicKey.Y)
	ephemeralPubB64 := base64.StdEncoding.EncodeToString(ephemeralPubBytes)

	// 5. Derive encryption key and MAC key via HKDF
	ikm := append(ephemeralPubBytes, sharedSecret...)
	salt := make([]byte, 32)
	hkdfReader := hkdf.New(sha256.New, ikm, salt, []byte(senderID))
	derivedKey := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return types.Token{}, fmt.Errorf("deriving keys: %w", err)
	}
	encryptionKey := derivedKey[:32]
	macKey := derivedKey[32:]

	// 6. Encrypt with AES-256-CTR (zero IV)
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return types.Token{}, fmt.Errorf("creating AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, plaintext)
	encryptedMessageB64 := base64.StdEncoding.EncodeToString(ciphertext)

	// 7. Compute HMAC-SHA256 tag
	mac := hmac.New(sha256.New, macKey)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)
	tagB64 := base64.StdEncoding.EncodeToString(tag)

	// 8. Build signedMessage JSON
	signedMsg := types.SignedMessage{
		EncryptedMessage:   encryptedMessageB64,
		EphemeralPublicKey: ephemeralPubB64,
		Tag:                tagB64,
	}
	signedMsgJSON, err := json.Marshal(signedMsg)
	if err != nil {
		return types.Token{}, fmt.Errorf("marshaling signed message: %w", err)
	}

	// 9. Generate intermediate signing key
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return types.Token{}, fmt.Errorf("generating intermediate key: %w", err)
	}
	intermediatePubDER, err := x509.MarshalPKIXPublicKey(&intermediateKey.PublicKey)
	if err != nil {
		return types.Token{}, fmt.Errorf("marshaling intermediate public key: %w", err)
	}
	intermediateKeyB64 := base64.StdEncoding.EncodeToString(intermediatePubDER)

	keyExp := strconv.FormatInt((now.Add(24*time.Hour).UnixMilli()), 10)
	sk := types.SignedKey{
		KeyValue:      intermediateKeyB64,
		KeyExpiration: keyExp,
	}
	skJSON, err := json.Marshal(sk)
	if err != nil {
		return types.Token{}, fmt.Errorf("marshaling signed key: %w", err)
	}
	signedKeyJSON := string(skJSON)

	// 10. Sign intermediate key with root key
	intermediateKeySigData := constructSignature(senderID, protocolVersion, signedKeyJSON)
	intermediateKeySig, err := signECDSA(g.rootKey, intermediateKeySigData)
	if err != nil {
		return types.Token{}, fmt.Errorf("signing intermediate key: %w", err)
	}

	// 11. Sign message with intermediate key
	messageSigData := constructSignature(senderID, g.cfg.RecipientID, protocolVersion, string(signedMsgJSON))
	messageSig, err := signECDSA(intermediateKey, messageSigData)
	if err != nil {
		return types.Token{}, fmt.Errorf("signing message: %w", err)
	}

	return types.Token{
		ProtocolVersion: protocolVersion,
		Signature:       base64.StdEncoding.EncodeToString(messageSig),
		IntermediateSigningKey: types.IntermediateSigningKey{
			SignedKey:   signedKeyJSON,
			Signatures:  []string{base64.StdEncoding.EncodeToString(intermediateKeySig)},
		},
		SignedMessage: string(signedMsgJSON),
	}, nil
}

// DefaultConfig returns a Config with pre-generated test keys that work together.
// The root keys, recipient private key, and recipient ID are all matched.
func DefaultConfig() Config {
	return Config{
		RootPrivateKey:    defaultRootPrivateKey,
		RootKeysJSON:      defaultRootKeysJSON,
		RecipientPrivateKey: defaultRecipientPrivateKey,
		RecipientID:       "merchant:12345678901234567890",
		GatewayMerchantID: "exampleGatewayMerchantId",
	}
}

func loadPrivateKey(b64Key string) (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA private key")
	}
	return ecKey, nil
}

func signECDSA(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	signer, err := subsig.NewECDSASignerFromPrivateKey("SHA256", "DER", key)
	if err != nil {
		return nil, err
	}
	return signer.Sign(data)
}

func constructSignature(params ...string) []byte {
	var signed []byte
	b := make([]byte, 4)
	for _, a := range params {
		binary.LittleEndian.PutUint32(b, uint32(len(a)))
		signed = append(signed, b...)
		signed = append(signed, []byte(a)...)
	}
	return signed
}
