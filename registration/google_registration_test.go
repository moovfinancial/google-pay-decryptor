package registration

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/moovfinancial/google-pay-decryptor/decrypt"
	"github.com/moovfinancial/google-pay-decryptor/decrypt/types"
)

// Google Pay Token Decryption parameters
const googleRegTestEnvironment = decrypt.EnvironmentTest
const googleRegTestGatewayID = "moov"

// Google Pay Keys for testing
const googleRegTestPrivateKey = "../keys/pk8.pem"
const googleRegTestPrivateKeyBad = "../keys/pk8_bad.pem"
const googleRegTestPrivateKeyBad2 = "../keys/pk8_bad2.pem"

// Test Payloads from Google Token Generator: https://developers.google.com/pay/api/processors/guides/test-and-validation/token-generator
const testPayloadJSON = `{"signature":"MEQCIDVrTfFyAZqMD0XS7xZX70U3wXF2DF14EkxpEhlETZ6XAiBtci3TOBdEFVnfLPOparob5s4LECAgWNNECJwHw0YM5g\u003d\u003d","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOYVyo7fQZ3PiceeF/Iv8zfoEVLZbyxoVBWuGfFqoqM+sDxTxsgyjHDCdpMggfOQw6DcmTQZHiGDwnvP9sMsyAg\\u003d\\u003d\",\"keyExpiration\":\"1759584961586\"}","signatures":["MEUCIQCNVcTIXcJr9Z07v9uLmJQcpyOhfkybed73WuN2vMHfuQIgf5bRIOiTOW8TxAj+PhL+jZWYoOT8LE9PElZoUqE6YDs\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"Q77M6TJjrcDqg8wbmFBP83uPydS87qwhFrmpxhygC86vGPBtgAsY6ZkoWhMKVhaP7cke9pEW56qSC+p0O87wZi4v1orcEZOWARdLkjBQNP2Eo+b8LkREYTRrlsAyqeM5q9WrCuJDwS+FTsvFOzm0IyntgX7T7lrkDmnrjIKP/8PW0uVVemIOpxCzkvtSxJkhK6y1un5X3CZt5WvVbF2PMWLlLAiQkTHg29Q90Y4oFHDBLxCNX7Mf7O1StwlWcN0Dfo/RJLXJuCVfX544GFFgDACgH2yX9BXiPr1HsYOfxGjittqX7JC8UNT3MyPvxWafmytOckOXVlrr8i2n4D27+Rf4OP+8j31Ie612auYAEugPpy3ocjjQ4StmWUhVXnP/CuT8S6dlGnPTuhhjyeBcyrPK+1KctpP/l89jclqaORDF7xmI5i8otqAit1etpkfMd8VgCizB0jtFEijIG0NLEG7xoox7t66wxR4WuJS0m+yEuaexFYgTWdvB7LdJhUuD0YSJITMBb3jObuwuqdCtwr68JPXNd9tIKb9CL3RSCcFfN4dL\",\"ephemeralPublicKey\":\"BDoRlhUJIPkq0PM+rlQWgccHvU1AO+YLzDriQFIyKXBvIs9OFqv+fj4x5dIuhijnsefBnttNXumVyfGTCaeBwPQ\\u003d\",\"tag\":\"3mP3kShq8m5JUfo338+T+o5RXaJf94yfQ6/RcycFPyA\\u003d\"}"}`

// For testing with Google, update with payload from Google
const googleRegistrationTestPayload1 = `{"signature":"MEQCIDVrTfFyAZqMD0XS7xZX70U3wXF2DF14EkxpEhlETZ6XAiBtci3TOBdEFVnfLPOparob5s4LECAgWNNECJwHw0YM5g\u003d\u003d","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOYVyo7fQZ3PiceeF/Iv8zfoEVLZbyxoVBWuGfFqoqM+sDxTxsgyjHDCdpMggfOQw6DcmTQZHiGDwnvP9sMsyAg\\u003d\\u003d\",\"keyExpiration\":\"1759584961586\"}","signatures":["MEUCIQCNVcTIXcJr9Z07v9uLmJQcpyOhfkybed73WuN2vMHfuQIgf5bRIOiTOW8TxAj+PhL+jZWYoOT8LE9PElZoUqE6YDs\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"Q77M6TJjrcDqg8wbmFBP83uPydS87qwhFrmpxhygC86vGPBtgAsY6ZkoWhMKVhaP7cke9pEW56qSC+p0O87wZi4v1orcEZOWARdLkjBQNP2Eo+b8LkREYTRrlsAyqeM5q9WrCuJDwS+FTsvFOzm0IyntgX7T7lrkDmnrjIKP/8PW0uVVemIOpxCzkvtSxJkhK6y1un5X3CZt5WvVbF2PMWLlLAiQkTHg29Q90Y4oFHDBLxCNX7Mf7O1StwlWcN0Dfo/RJLXJuCVfX544GFFgDACgH2yX9BXiPr1HsYOfxGjittqX7JC8UNT3MyPvxWafmytOckOXVlrr8i2n4D27+Rf4OP+8j31Ie612auYAEugPpy3ocjjQ4StmWUhVXnP/CuT8S6dlGnPTuhhjyeBcyrPK+1KctpP/l89jclqaORDF7xmI5i8otqAit1etpkfMd8VgCizB0jtFEijIG0NLEG7xoox7t66wxR4WuJS0m+yEuaexFYgTWdvB7LdJhUuD0YSJITMBb3jObuwuqdCtwr68JPXNd9tIKb9CL3RSCcFfN4dL\",\"ephemeralPublicKey\":\"BDoRlhUJIPkq0PM+rlQWgccHvU1AO+YLzDriQFIyKXBvIs9OFqv+fj4x5dIuhijnsefBnttNXumVyfGTCaeBwPQ\\u003d\",\"tag\":\"3mP3kShq8m5JUfo338+T+o5RXaJf94yfQ6/RcycFPyA\\u003d\"}"}`
const googleRegistrationTestPayload2 = `{"signature":"MEYCIQDUGBBM5v1RIEgBZ5ubymWKe7OCaNfySO/TSZWwHszzeQIhALweUvBSPdCY9kr8BLRzrTFu/hV3rCF/6T5IXF8z7eB6","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGalwFwLnUoh1h/ZW4qdSgR9CaO9lZSFC3bj0QI0u3GCXWR2+YmJ2g3n9kZFh1P2qYfsW2epi2wNl/vLD3mf93g\\u003d\\u003d\",\"keyExpiration\":\"1746202989451\"}","signatures":["MEUCIGk7RGbRdQz5UyzpKmQPeGOlV25KJE23mwwRjXt3mwHuAiEA6dL4Bpj0yGs3+/w88NFMrYodvjXfVn+zvPTLt5XwGiQ\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"8NRn2kDk/Y9E3MjnSkTMg8vHkj06bCYva6WDbMHJd7xCptJHf2yrM0VEJhgrx1J1HnxzIIcInFisD3njx8tkPbHcl/qyhg5tI5CF9x+P6ipCeXyRQ9CNFVxLrztHyhQGIgd5lJ5IXotGeIpVhil0BFaTILoUvJMcgca2ZH+04tFHNo4zdZdiJ5K+1rmK+MAipb+Plkt8v8Pq47J8nq4P+FrqOqjXI3IIwCMwPhEdvCelSoB/5LxWbPcgAjZbLSCciBdT3xv6siO0/hQam7ONIsB1O9FgVMgWSZem1CU2QZQuup6qDMESgUxtCYww/W0zpbfexgW09wP0ua4DvDXsTy6DC+7U6FQuJfBKmlZjQggKLqbWILXvK1iplTlBc+/Ba+idGallBdPdFoK26+0pzaOF2IN8KZOHKIWxJNREIfj56taCuldxE1KKMS/hEg3E2+i4Gg1FXi2RoRy7cAiRu+IJiLRbQOhFDlgqsvFc0qrWCfZ/eLkfboHrJr8L87Aebfhce5eyGtc/s0xfTb4I0lkO35X96ZruBfsTq5gotW+5rlMm\",\"ephemeralPublicKey\":\"BHQJ4wdlO/s22yhEfzMvqMB05IF3KEWoeHD4ejjI2UNky5XdGl52c17Rh/8TM1FZ6L8s6egiWzVI6aX/BTfE2a4\\u003d\",\"tag\":\"gry72UABDT9zWP2LdmuTftWWqfE2URHRilosd7iFVlM\\u003d\"}"}`

func TestGoogleRegistrationPayload1(t *testing.T) {
	// Payloads from Google - Each are to fail for different reasons
	// Update these payloads with the latest from Google each time you rotate the keys

	t.Run("GooglePayload1", func(t *testing.T) {
		if os.Getenv("TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE") != "true" {
			t.Skip("Skipping test because TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE is not set")
		}

		var input types.Token
		var output types.Decrypted

		err := json.Unmarshal([]byte(googleRegistrationTestPayload1), &input)
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

func TestGoogleRegistrationPayload2(t *testing.T) {
	// Payloads from Google - Each are to fail for different reasons
	// Update these payloads with the latest from Google each time you rotate the keys

	t.Run("GooglePayload2", func(t *testing.T) {
		if os.Getenv("TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE") != "true" {
			t.Skip("Skipping test because TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE is not set")
		}

		var input types.Token
		var output types.Decrypted

		err := json.Unmarshal([]byte(googleRegistrationTestPayload2), &input)
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

func TestWith2KeysPrimaryGood(t *testing.T) {
	t.Run("PrimaryKeyGood", func(t *testing.T) {
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
		//fmt.Printf("Root Keys:\n%v\n", decryptor.RootKeys)
	})
}
