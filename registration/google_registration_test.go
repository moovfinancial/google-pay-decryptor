package registration

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/moov-io/google-pay-decryptor/decrypt"
	"github.com/moov-io/google-pay-decryptor/decrypt/types"
)

// Google Pay Token Decryption parameters
const googleRegTestEnvironment = decrypt.EnvironmentTest
const googleRegProdEnvironment = decrypt.EnvironmentProduction
const googleRegTestGatewayID = "moov"

// Google Pay Keys for testing
const googleRegTestPrivateKey = "../keys/pk8.pem"
const googleRegTestPrivateKey2 = "../keys/pk8_2.pem" // Secondary key for testing (if doesn't exist, will be skipped)
const googleRegTestPrivateKeyBad = "../keys/pk8_bad.pem"
const googleRegTestPrivateKeyBad2 = "../keys/pk8_bad2.pem"

// Test Payloads from Google Token Generator: https://developers.google.com/pay/api/processors/guides/test-and-validation/token-generator
const testPayloadJSON = ``

// For testing with Google, update with payload from Google
const googleRegistrationTestPayload1 = ``
const googleRegistrationTestPayload2 = ``

// setupGoogleRegistrationDecryptor reads the primary and optional secondary test keys,
// creates a decryptor, and adds the secondary key if present. Skips the test if the
// secondary key file does not exist. Returns the decryptor or nil on fatal error.
func setupGoogleRegistrationDecryptor(t *testing.T) *decrypt.GooglePayDecryptor {
	t.Helper()
	privateKeyBytes, err := os.ReadFile(googleRegTestPrivateKey)
	if err != nil {
		t.Fatalf("reading test private key: %v", err)
	}

	// Use for test environment
	fmt.Printf("Environment: %s\n", googleRegTestEnvironment)
	decryptor, err := decrypt.NewWithRootKeysFromGoogle(googleRegTestEnvironment, "gateway:"+googleRegTestGatewayID, string(privateKeyBytes))

	// Use for production environment
	//fmt.Printf("Environment: %s\n", googleRegProdEnvironment)
	//decryptor, err := decrypt.NewWithRootKeysFromGoogle(googleRegProdEnvironment, "gateway:"+googleRegTestGatewayID, string(privateKeyBytes))
	if err != nil {
		t.Fatalf("create decryptor: %v", err)
	}
	privateKeyBytes2, err := os.ReadFile(googleRegTestPrivateKey2)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skip("Secondary private key file does not exist, skipping")
		}
		t.Fatalf("reading secondary test private key: %v", err)
	}
	if len(privateKeyBytes2) > 0 {
		err = decryptor.AddPrivateKey(string(privateKeyBytes2), "secondary_key")
		if err != nil {
			t.Fatalf("add secondary key: %v", err)
		}
	}
	return decryptor
}

func TestGoogleRegistrationPayload1(t *testing.T) {
	// Payloads from Google - Each are to fail for different reasons
	// Update these payloads with the latest from Google each time you rotate the keys

	t.Run("GooglePayload1", func(t *testing.T) {
		if os.Getenv("TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE") != "true" {
			t.Skip("Skipping test because TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE is not set")
		}
		if strings.TrimSpace(googleRegistrationTestPayload1) == "" {
			t.Skip("Google registration test payload 1 not configured")
		}

		var input types.Token
		var output types.Decrypted

		err := json.Unmarshal([]byte(googleRegistrationTestPayload1), &input)
		if err != nil {
			t.Errorf("failed to unmarshal test payload: %v", err)
		}

		decryptor := setupGoogleRegistrationDecryptor(t)

		// Decrypt the test payload
		output, err = decryptor.Decrypt(input) // input is payload in types.Token
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}

		// Pretty print the decrypted token
		prettyOutput, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			t.Fatalf("error formatting output: %v", err)
		}
		fmt.Printf("Decrypted Token:\n%s\n", string(prettyOutput))
		fmt.Printf("Key used: %s\n", output.KeyIdentifier)
	})
}

func TestGoogleRegistrationPayload2(t *testing.T) {
	// Payloads from Google - Each are to fail for different reasons
	// Update these payloads with the latest from Google each time you rotate the keys

	t.Run("GooglePayload2", func(t *testing.T) {
		if os.Getenv("TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE") != "true" {
			t.Skip("Skipping test because TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE is not set")
		}
		if strings.TrimSpace(googleRegistrationTestPayload2) == "" {
			t.Skip("Google registration test payload 2 not configured")
		}

		var input types.Token
		var output types.Decrypted

		err := json.Unmarshal([]byte(googleRegistrationTestPayload2), &input)
		if err != nil {
			t.Errorf("failed to unmarshal test payload: %v", err)
		}

		decryptor := setupGoogleRegistrationDecryptor(t)

		// Decrypt the test payload
		output, err = decryptor.Decrypt(input) // input is payload in types.Token
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}

		// Pretty print the decrypted token
		prettyOutput, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			t.Fatalf("error formatting output: %v", err)
		}
		fmt.Printf("Decrypted Token:\n%s\n", string(prettyOutput))
		fmt.Printf("Key used: %s\n", output.KeyIdentifier)
	})
}

func TestWith2KeysPrimaryGood(t *testing.T) {
	t.Run("PrimaryKeyGood", func(t *testing.T) {
		if strings.TrimSpace(testPayloadJSON) == "" {
			t.Skip("testPayloadJSON not configured")
		}
		var input types.Token
		var output types.Decrypted

		err := json.Unmarshal([]byte(testPayloadJSON), &input)
		if err != nil {
			t.Errorf("failed to unmarshal test payload: %v", err)
		}

		// Test Key registered with Google
		privateKeyBytes, err := os.ReadFile(googleRegTestPrivateKey)
		if err != nil {
			fmt.Printf("Error reading test private key: %v\n", err)
			return
		}

		// Create a new GooglePayDecryptor with the test private key
		decryptor, err := decrypt.NewWithRootKeysFromGoogle(googleRegTestEnvironment, "gateway:"+googleRegTestGatewayID, string(privateKeyBytes))
		if err != nil {
			t.Errorf("failed to create decryptor: %v", err)
		}

		// Add a bad key for testing
		privateKeyBytesBad, err := os.ReadFile(googleRegTestPrivateKeyBad)
		if err != nil {
			fmt.Printf("Error reading test private key: %v\n", err)
			return
		}
		decryptor.AddPrivateKey(string(privateKeyBytesBad), "bad_key")

		// Decrypt the test payload
		output, err = decryptor.Decrypt(input) // input is payload in types.Token
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}

		// Pretty print the decrypted token
		prettyOutput, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			t.Fatalf("error formatting output: %v", err)
		}
		fmt.Printf("Decrypted Token:\n%s\n", string(prettyOutput))
	})
}

func TestWith2KeysSecondaryGood(t *testing.T) {
	t.Run("SecondaryKeyGood", func(t *testing.T) {
		if strings.TrimSpace(testPayloadJSON) == "" {
			t.Skip("testPayloadJSON not configured")
		}
		var input types.Token
		var output types.Decrypted

		err := json.Unmarshal([]byte(testPayloadJSON), &input)
		if err != nil {
			t.Errorf("failed to unmarshal test payload: %v", err)
		}

		// Test Bad Key
		privateKeyBytes, err := os.ReadFile(googleRegTestPrivateKeyBad)
		if err != nil {
			fmt.Printf("Error reading test private key: %v\n", err)
			return
		}

		// Create a new GooglePayDecryptor with the test private key
		decryptor, err := decrypt.NewWithRootKeysFromGoogle(googleRegTestEnvironment, "gateway:"+googleRegTestGatewayID, string(privateKeyBytes))
		if err != nil {
			t.Errorf("failed to create decryptor: %v", err)
		}

		// Add a bad key for testing
		privateKeyBytesBad, err := os.ReadFile(googleRegTestPrivateKey)
		if err != nil {
			fmt.Printf("Error reading test private key: %v\n", err)
			return
		}
		decryptor.AddPrivateKey(string(privateKeyBytesBad), "good_key")

		// Decrypt the test payload
		output, err = decryptor.Decrypt(input) // input is payload in types.Token
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}

		// Pretty print the decrypted token
		prettyOutput, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			t.Fatalf("error formatting output: %v", err)
		}
		fmt.Printf("Decrypted Token:\n%s\n", string(prettyOutput))
	})
}

func TestWith2BadKeys(t *testing.T) {
	t.Run("TwoBadKeys", func(t *testing.T) {
		if strings.TrimSpace(testPayloadJSON) == "" {
			t.Skip("testPayloadJSON not configured")
		}
		var input types.Token

		err := json.Unmarshal([]byte(testPayloadJSON), &input)
		if err != nil {
			t.Errorf("failed to unmarshal test payload: %v", err)
		}

		// Test Bad Key
		privateKeyBytes, err := os.ReadFile(googleRegTestPrivateKeyBad)
		if err != nil {
			fmt.Printf("Error reading test private key: %v\n", err)
			return
		}

		// Create a new GooglePayDecryptor with the test private key
		decryptor, err := decrypt.NewWithRootKeysFromGoogle(googleRegTestEnvironment, "gateway:"+googleRegTestGatewayID, string(privateKeyBytes))
		if err != nil {
			t.Errorf("failed to create decryptor: %v", err)
		}

		// Add a bad key for testing
		privateKeyBytesBad, err := os.ReadFile(googleRegTestPrivateKeyBad2)
		if err != nil {
			fmt.Printf("Error reading test private key: %v\n", err)
			return
		}
		decryptor.AddPrivateKey(string(privateKeyBytesBad), "2nd_bad_key")

		// Decrypt the test payload
		output, err := decryptor.Decrypt(input) // input is payload in types.Token
		if err == nil {
			t.Errorf("expected error when decrypting with 2 bad keys, got nil: %v", output)
		}
	})
}

func TestWithTokenGenerator(t *testing.T) {
	t.Run("TokenGenerator", func(t *testing.T) {
		if strings.TrimSpace(testPayloadJSON) == "" {
			t.Skip("testPayloadJSON not configured")
		}
		var input types.Token
		var output types.Decrypted

		err := json.Unmarshal([]byte(testPayloadJSON), &input)
		if err != nil {
			t.Errorf("failed to unmarshal test payload: %v", err)
		}

		// Get Key
		privateKeyBytes, err := os.ReadFile(googleRegTestPrivateKey)
		if err != nil {
			fmt.Printf("Error reading test private key: %v\n", err)
			return
		}

		// Create a new GooglePayDecryptor with the test private key
		decryptor, err := decrypt.NewWithRootKeysFromGoogle(googleRegTestEnvironment, "gateway:"+googleRegTestGatewayID, string(privateKeyBytes))
		if err != nil {
			t.Errorf("failed to create decryptor: %v", err)
		}

		// Decrypt the test payload
		output, err = decryptor.Decrypt(input) // input is payload in types.Token
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}

		// Pretty print the decrypted token
		prettyOutput, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			t.Fatalf("error formatting output: %v", err)
		}
		fmt.Printf("Decrypted Token:\n%s\n", string(prettyOutput))
	})
}
