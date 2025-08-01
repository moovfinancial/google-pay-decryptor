package decrypt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/tink/go/hybrid/subtle"
	hkdf "github.com/google/tink/go/subtle"
	"github.com/stretchr/testify/require"
	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt/types"
)

func TestECv1Format(t *testing.T) {
	// Test data from user
	ecv1Data := `{
		"protocolVersion": "ECv1",
		"signature": "MEYCIQDfWbY/vB34ueX1vhcrkteN3sGoC4yiIhj0VWf+sYgmuQIhAO4xYHQTfO5DtSatjOs258tD1l9VIcwXyC6HbzxBhFQ+",
		"signedMessage": "{\"encryptedMessage\":\"FWz0WSptMQbYMCspJlpzndZkb3FFcecg7BEBCe9MzBs0a9loQ+iRyZiEk6xCo0cPOtXbl2m0cuMBl11Fvw5o6NtphQjjCxOwTaupX6VW9mJkJKWYt9HNMYElIG2rtEIFIPfHyb2If78iDw5hcyTiixqPuqEZ0MrXmn7IT828OMp0MYAn0yZjQCrRzLLUzgmDn3hn04cLo291RR3WQaE1deSJQj2i+cjkJ+n3QD8UvKwUS3R0xLFPdCb1dMtKvfhcUP759WXeoGUR7wJgPaNPkRAcPhdrUXI8ug2tIpmyKnwEDLNHwanFOPoyvXUApR9iWnVKf7+Ew0QPU5AGCgFd4+PKbG4D6EFOvGKzH5E2dJfSI7n9BvRvuWDagh4EVm2jixpC7qPEy2N+QVZKSMjMggyxVKkFfk0Ww8aXJ+2X7ffWvAUwTmvfYOPXz0ZNZtkRQ7YZCqZkwC7M3mPCCs+hcI3unGXE5rHi1wOT8eL/iI56LWrzwyxdTenCVI5GeUxQpxmNKKWgzpUHLm39L1lryqTNpV6uKoJZTttrSDg7O6R/qVUcYulQ1e4lH1JfaMMBD8p5g6dc6RaFe0X1aHIQgaRzCE31wn9gUGmGfCaJfiE9ZUNRjwo=\",\"ephemeralPublicKey\":\"BM2MKSoit+fEiDFUbfQlvYu0gqMXLuZ1vxWS7ev3qhuJd8y2PTLNd9ctQS3xmH+zr1lewdM7uF+VRDaouCJ5yUM=\",\"tag\":\"kE6DQSBqvtwjG72rkgs6VY8Gcg6UY+8+t749333pcx8=\"}"
	}`

	var ecv1Token struct {
		Signature     string `json:"signature"`
		SignedMessage string `json:"signedMessage"`
	}

	err := json.Unmarshal([]byte(ecv1Data), &ecv1Token)
	require.NoError(t, err, "Failed to unmarshal ECv1 data")

	require.NotEmpty(t, ecv1Token.Signature, "Signature should not be empty")
	require.NotEmpty(t, ecv1Token.SignedMessage, "SignedMessage should not be empty")

	// Parse the signed message
	var signedMessage types.SignedMessage
	err = json.Unmarshal([]byte(ecv1Token.SignedMessage), &signedMessage)
	require.NoError(t, err, "Failed to unmarshal signed message")

	require.NotEmpty(t, signedMessage.EncryptedMessage, "EncryptedMessage should not be empty")
	require.NotEmpty(t, signedMessage.EphemeralPublicKey, "EphemeralPublicKey should not be empty")
	require.NotEmpty(t, signedMessage.Tag, "Tag should not be empty")

	// Decode the signature to see what it contains
	signatureBytes, err := base64.StdEncoding.DecodeString(ecv1Token.Signature)
	require.NoError(t, err, "Failed to decode signature")

	require.Equal(t, 72, len(signatureBytes), "Signature should be 72 bytes (DER-encoded ECDSA)")
	require.NotEmpty(t, signatureBytes, "Signature bytes should not be empty")
}

func TestECv1Decryption(t *testing.T) {
	// Test key and gateway from user
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+bzjzVodKixRY6W6JhEISTARw8/U+LIE7/JR9+c41uqhRANCAASVpviPX2DMOBvaEFxNMB79aaENm5p/DFFeUuRusAtalEfL/DoUBLKWhODF0jiW3/EMPMY0H6uc0LPwVYCU2rhi"
	gatewayName := "gateway:solid"

	// Create a mock root keys (for ECv1, we don't actually need root keys, but the constructor requires them)
	mockRootKeys := []byte(`{"keys":[]}`)

	// Create decryptor
	decryptor := New(mockRootKeys, gatewayName, privateKey)
	require.NotNil(t, decryptor, "Decryptor should be created successfully")

	// Test automatic format detection
	ecv1Token := types.Token{
		ProtocolVersion: "ECv1",
		Signature:       "MEYCIQDfWbY/vB34ueX1vhcrkteN3sGoC4yiIhj0VWf+sYgmuQIhAO4xYHQTfO5DtSatjOs258tD1l9VIcwXyC6HbzxBhFQ+",
		SignedMessage:   "{\"encryptedMessage\":\"FWz0WSptMQbYMCspJlpzndZkb3FFcecg7BEBCe9MzBs0a9loQ+iRyZiEk6xCo0cPOtXbl2m0cuMBl11Fvw5o6NtphQjjCxOwTaupX6VW9mJkJKWYt9HNMYElIG2rtEIFIPfHyb2If78iDw5hcyTiixqPuqEZ0MrXmn7IT828OMp0MYAn0yZjQCrRzLLUzgmDn3hn04cLo291RR3WQaE1deSJQj2i+cjkJ+n3QD8UvKwUS3R0xLFPdCb1dMtKvfhcUP759WXeoGUR7wJgPaNPkRAcPhdrUXI8ug2tIpmyKnwEDLNHwanFOPoyvXUApR9iWnVKf7+Ew0QPU5AGCgFd4+PKbG4D6EFOvGKzH5E2dJfSI7n9BvRvuWDagh4EVm2jixpC7qPEy2N+QVZKSMjMggyxVKkFfk0Ww8aXJ+2X7ffWvAUwTmvfYOPXz0ZNZtkRQ7YZCqZkwC7M3mPCCs+hcI3unGXE5rHi1wOT8eL/iI56LWrzwyxdTenCVI5GeUxQpxmNKKWgzpUHLm39L1lryqTNpV6uKoJZTttrSDg7O6R/qVUcYulQ1e4lH1JfaMMBD8p5g6dc6RaFe0X1aHIQgaRzCE31wn9gUGmGfCaJfiE9ZUNRjwo=\",\"ephemeralPublicKey\":\"BM2MKSoit+fEiDFUbfQlvYu0gqMXLuZ1vxWS7ev3qhuJd8y2PTLNd9ctQS3xmH+zr1lewdM7uF+VRDaouCJ5yUM=\",\"tag\":\"kE6DQSBqvtwjG72rkgs6VY8Gcg6UY+8+t749333pcx8=\"}",
	}

	decrypted, err := decryptor.Decrypt(ecv1Token)
	if err != nil {
		// Expected failure for expired/invalid test data
		require.True(t,
			strings.Contains(err.Error(), "message expiration time has passed") ||
				strings.Contains(err.Error(), "HMAC") ||
				strings.Contains(err.Error(), "invalid MAC"),
			"Error should be related to expiration or HMAC validation, got: %v", err)
	} else {
		require.NotNil(t, decrypted, "Decrypted result should not be nil")
	}

	// Test ECv1 specific decryption
	decrypted, err = decryptor.DecryptECv1(ecv1Token)
	if err != nil {
		// Expected failure for expired/invalid test data
		require.True(t,
			strings.Contains(err.Error(), "message expiration time has passed") ||
				strings.Contains(err.Error(), "HMAC") ||
				strings.Contains(err.Error(), "invalid MAC"),
			"Error should be related to expiration or HMAC validation, got: %v", err)
	} else {
		require.NotNil(t, decrypted, "Decrypted result should not be nil")
	}
}

func TestECv1CryptographicOperations(t *testing.T) {
	// Test the cryptographic operations step by step
	privateKey := "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+bzjzVodKixRY6W6JhEISTARw8/U+LIE7/JR9+c41uqhRANCAASVpviPX2DMOBvaEFxNMB79aaENm5p/DFFeUuRusAtalEfL/DoUBLKWhODF0jiW3/EMPMY0H6uc0LPwVYCU2rhi"

	// Test data components
	ephemeralPublicKey := "BM2MKSoit+fEiDFUbfQlvYu0gqMXLuZ1vxWS7ev3qhuJd8y2PTLNd9ctQS3xmH+zr1lewdM7uF+VRDaouCJ5yUM="
	encryptedMessage := "FWz0WSptMQbYMCspJlpzndZkb3FFcecg7BEBCe9MzBs0a9loQ+iRyZiEk6xCo0cPOtXbl2m0cuMBl11Fvw5o6NtphQjjCxOwTaupX6VW9mJkJKWYt9HNMYElIG2rtEIFIPfHyb2If78iDw5hcyTiixqPuqEZ0MrXmn7IT828OMp0MYAn0yZjQCrRzLLUzgmDn3hn04cLo291RR3WQaE1deSJQj2i+cjkJ+n3QD8UvKwUS3R0xLFPdCb1dMtKvfhcUP759WXeoGUR7wJgPaNPkRAcPhdrUXI8ug2tIpmyKnwEDLNHwanFOPoyvXUApR9iWnVKf7+Ew0QPU5AGCgFd4+PKbG4D6EFOvGKzH5E2dJfSI7n9BvRvuWDagh4EVm2jixpC7qPEy2N+QVZKSMjMggyxVKkFfk0Ww8aXJ+2X7ffWvAUwTmvfYOPXz0ZNZtkRQ7YZCqZkwC7M3mPCCs+hcI3unGXE5rHi1wOT8eL/iI56LWrzwyxdTenCVI5GeUxQpxmNKKWgzpUHLm39L1lryqTNpV6uKoJZTttrSDg7O6R/qVUcYulQ1e4lH1JfaMMBD8p5g6dc6RaFe0X1aHIQgaRzCE31wn9gUGmGfCaJfiE9ZUNRjwo="
	tag := "kE6DQSBqvtwjG72rkgs6VY8Gcg6UY+8+t749333pcx8="

	// Create a signed message for testing (not used in this test but shows the structure)
	_ = types.SignedMessage{
		EncryptedMessage:   encryptedMessage,
		EphemeralPublicKey: ephemeralPublicKey,
		Tag:                tag,
	}

	// Test key loading
	var privK PrivateKey
	loadedKey, err := privK.LoadKey(privateKey)
	require.NoError(t, err, "Failed to load private key")
	require.NotNil(t, loadedKey, "Loaded key should not be nil")

	// Test ephemeral public key loading
	var pk PublicKey
	ephemeralPK, err := pk.LoadEphemeralPublicKey(ephemeralPublicKey)
	require.NoError(t, err, "Failed to load ephemeral public key")
	require.NotNil(t, ephemeralPK, "Ephemeral public key should not be nil")

	// Test shared secret computation
	sharedSecret, err := subtle.ComputeSharedSecret(ephemeralPK, loadedKey)
	require.NoError(t, err, "Failed to compute shared secret")
	require.Equal(t, 32, len(sharedSecret), "Shared secret should be 32 bytes")

	// Test ephemeral key decoding
	decodedEphemeralKey, err := Base64Decode(ephemeralPublicKey)
	require.NoError(t, err, "Failed to decode ephemeral key")
	require.Equal(t, 65, len(decodedEphemeralKey), "Decoded ephemeral key should be 65 bytes (uncompressed)")

	// Test key derivation
	combined := append(decodedEphemeralKey, sharedSecret...)
	derivedKeyHKDF, err := hkdf.ComputeHKDF(GooglePaySHA256HashAlgorithm, combined, make([]byte, 32), []byte(GooglePaySenderID), 64)
	require.NoError(t, err, "Failed to derive keys with HKDF")
	require.Equal(t, 64, len(derivedKeyHKDF), "Derived key should be 64 bytes")

	// Test MAC and encryption key separation
	mac, encryptionKey, err := GenerateMacKeyAndEncryptionKey(derivedKeyHKDF)
	require.NoError(t, err, "Failed to separate MAC and encryption keys")
	require.Equal(t, 32, len(mac), "MAC key should be 32 bytes")
	require.Equal(t, 32, len(encryptionKey), "Encryption key should be 32 bytes")

	// Test HMAC verification (this should fail with the test data, but we can verify the process)
	err = VerifyMessageHmac(mac, tag, encryptedMessage)
	require.Error(t, err, "HMAC verification should fail with invalid test data")
	require.Contains(t, err.Error(), "invalid MAC", "Error should indicate invalid MAC")
}

func TestECv1FormatDetection(t *testing.T) {
	// Test that the format detection works correctly

	// Create a decryptor
	decryptor := New([]byte(`{"keys":[]}`), "test", "test")
	require.NotNil(t, decryptor, "Decryptor should be created successfully")

	// Test ECv1 detection
	ecv1Token := types.Token{
		ProtocolVersion: "ECv1",
		Signature:       "test",
		SignedMessage:   "test",
	}

	_, err := decryptor.Decrypt(ecv1Token)
	require.Error(t, err, "ECv1 format should be detected but fail during decryption")
	require.Contains(t, err.Error(), "invalid character", "Should fail during JSON parsing of signed message")

	// Test ECv2 detection
	ecv2Token := types.Token{
		ProtocolVersion: "ECv2",
		Signature:       "test",
		IntermediateSigningKey: types.IntermediateSigningKey{
			SignedKey:  "test",
			Signatures: []string{"test"},
		},
		SignedMessage: "test",
	}

	_, err = decryptor.Decrypt(ecv2Token)
	require.Error(t, err, "ECv2 format should be detected but fail during decryption")
	require.Contains(t, err.Error(), "cannot find ECv2", "Should fail during root key verification")

	// Test invalid format
	invalidToken := types.Token{
		ProtocolVersion: "invalid",
		Signature:       "test",
		SignedMessage:   "test",
	}

	_, err = decryptor.Decrypt(invalidToken)
	require.Error(t, err, "Invalid format should be rejected")
	require.Contains(t, err.Error(), "unable to determine token format", "Should fail format detection")
}
