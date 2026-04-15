package testtoken_test

import (
	"encoding/json"
	"testing"

	"github.com/moov-io/google-pay-decryptor/decrypt"
	"github.com/moov-io/google-pay-decryptor/decrypt/types"
	"github.com/moov-io/google-pay-decryptor/testtoken"
	"github.com/stretchr/testify/require"
)

func TestGenerate_RoundTrip(t *testing.T) {
	cfg := testtoken.DefaultConfig()
	gen, err := testtoken.NewGenerator(cfg)
	require.NoError(t, err)

	token, err := gen.Generate(testtoken.PaymentData{
		PAN:             "4111111111111111",
		ExpirationMonth: 12,
		ExpirationYear:  2027,
		AuthMethod:      "PAN_ONLY",
		CardNetwork:     "VISA",
	})
	require.NoError(t, err)
	require.Equal(t, "ECv2", token.ProtocolVersion)
	require.NotEmpty(t, token.Signature)
	require.NotEmpty(t, token.SignedMessage)
	require.NotEmpty(t, token.IntermediateSigningKey.SignedKey)
	require.Len(t, token.IntermediateSigningKey.Signatures, 1)

	// Now decrypt it using the decrypt package
	decryptor := decrypt.New(
		[]byte(cfg.RootKeysJSON),
		cfg.RecipientID,
		cfg.RecipientPrivateKey,
	)

	decrypted, err := decryptor.Decrypt(token)
	require.NoError(t, err)
	require.Equal(t, "4111111111111111", decrypted.PaymentMethodDetails.Pan)
	require.Equal(t, 12, decrypted.PaymentMethodDetails.ExpirationMonth)
	require.Equal(t, 2027, decrypted.PaymentMethodDetails.ExpirationYear)
	require.Equal(t, "PAN_ONLY", decrypted.PaymentMethodDetails.AuthMethod)
	require.Equal(t, "CARD", decrypted.PaymentMethod)
	require.Equal(t, cfg.GatewayMerchantID, decrypted.GatewayMerchantId)
}

func TestGenerate_TokenIsValidJSON(t *testing.T) {
	cfg := testtoken.DefaultConfig()
	gen, err := testtoken.NewGenerator(cfg)
	require.NoError(t, err)

	token, err := gen.Generate(testtoken.PaymentData{
		PAN:             "5555555555554444",
		ExpirationMonth: 6,
		ExpirationYear:  2028,
		AuthMethod:      "PAN_ONLY",
		CardNetwork:     "MASTERCARD",
	})
	require.NoError(t, err)

	// SignedMessage should be valid JSON
	var sm types.SignedMessage
	err = json.Unmarshal([]byte(token.SignedMessage), &sm)
	require.NoError(t, err)
	require.NotEmpty(t, sm.EncryptedMessage)
	require.NotEmpty(t, sm.EphemeralPublicKey)
	require.NotEmpty(t, sm.Tag)
}
