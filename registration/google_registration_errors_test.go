package registration

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/moov-io/google-pay-decryptor/decrypt/types"
)

// Google Pay Token Decryption parameters (uses setupGoogleRegistrationDecryptor for multi-key decryptor)
const googleRegErrorTestMerchantID = "googletest"

// Payloads from Google - Each are to fail for different reasons
// Update these payloads with the latest from Google each time you rotate the keys
const googleRegistrationErrorPayload1 = ``
const googleRegistrationErrorPayload2 = ``
const googleRegistrationErrorPayload3 = ``
const googleRegistrationErrorPayload4 = ``
const googleRegistrationErrorPayload5 = ``

func TestGoogleRegistrationErrorPayload1(t *testing.T) {
	t.Run("ErrorPayload1", func(t *testing.T) {
		if os.Getenv("TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE") != "true" {
			t.Skip("Skipping test because TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE is not set")
		}
		if strings.TrimSpace(googleRegistrationErrorPayload1) == "" {
			t.Skip("Error payload 1 not configured")
		}

		output, err := decryptToken(t, googleRegistrationErrorPayload1)
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}
		prettyPrintDecryptedToken(output)
	})
}

func TestGoogleRegistrationErrorPayload2(t *testing.T) {
	t.Run("ErrorPayload2", func(t *testing.T) {
		if os.Getenv("TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE") != "true" {
			t.Skip("Skipping test because TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE is not set")
		}
		if strings.TrimSpace(googleRegistrationErrorPayload2) == "" {
			t.Skip("Error payload 2 not configured")
		}

		output, err := decryptToken(t, googleRegistrationErrorPayload2)
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}
		prettyPrintDecryptedToken(output)
	})
}

func TestGoogleRegistrationErrorPayload3(t *testing.T) {
	t.Run("ErrorPayload3", func(t *testing.T) {
		if os.Getenv("TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE") != "true" {
			t.Skip("Skipping test because TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE is not set")
		}
		if strings.TrimSpace(googleRegistrationErrorPayload3) == "" {
			t.Skip("Error payload 3 not configured")
		}

		output, err := decryptToken(t, googleRegistrationErrorPayload3)
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}
		prettyPrintDecryptedToken(output)
	})
}

func TestGoogleRegistrationErrorPayload4(t *testing.T) {
	t.Run("ErrorPayload4", func(t *testing.T) {
		if os.Getenv("TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE") != "true" {
			t.Skip("Skipping test because TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE is not set")
		}
		if strings.TrimSpace(googleRegistrationErrorPayload4) == "" {
			t.Skip("Error payload 4 not configured")
		}

		output, err := decryptToken(t, googleRegistrationErrorPayload4)
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}
		prettyPrintDecryptedToken(output)
	})
}

func TestGoogleRegistrationErrorPayload5(t *testing.T) {
	t.Run("ErrorPayload5", func(t *testing.T) {
		if os.Getenv("TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE") != "true" {
			t.Skip("Skipping test because TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE is not set")
		}
		if strings.TrimSpace(googleRegistrationErrorPayload5) == "" {
			t.Skip("Error payload 5 not configured")
		}

		output, err := decryptToken(t, googleRegistrationErrorPayload5)
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}
		prettyPrintDecryptedToken(output)
	})
}

// decryptToken unmarshals the payload and decrypts it using the shared multi-key
// decryptor (primary + optional secondary key). Uses DecryptWithMerchantId for merchant validation.
func decryptToken(t *testing.T, jsonPayload string) (types.Decrypted, error) {
	t.Helper()
	var input types.Token

	err := json.Unmarshal([]byte(jsonPayload), &input)
	if err != nil {
		return types.Decrypted{}, fmt.Errorf("failed to unmarshal test payload: %v", err)
	}

	decryptor := setupGoogleRegistrationDecryptor(t)
	output, err := decryptor.DecryptWithMerchantId(input, googleRegErrorTestMerchantID)
	if err != nil {
		return types.Decrypted{}, fmt.Errorf("failed to decrypt: %v", err)
	}

	return output, nil
}

func prettyPrintDecryptedToken(output types.Decrypted) {
	prettyOutput, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Printf("error formatting output: %v", err)
	}
	fmt.Printf("Decrypted Token:\n%s\n", string(prettyOutput))
}
