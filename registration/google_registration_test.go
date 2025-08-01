package registration

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt"
	"github.com/vladyslavpavlenko/google-pay-decryptor/decrypt/types"
)

func tokenToBytes(token types.Token, t *testing.T) []byte {
	bytes, err := json.Marshal(token)
	require.NoError(t, err, "failed to marshal token to bytes")

	return bytes
}

// New Token Payloads can be created here: https://developers.google.com/pay/api/processors/guides/test-and-validation/token-generator
// Use Gateway ID = moov
// Use Merchant ID = googletest
// Use Country Code = US

func TestGoogleRegistrationPayload1(t *testing.T) {
	var input types.Token
	var output types.Decrypted

	// Test Payload1 from Google
	// const testPayloadJSON = `{"signature":"MEQCICqbBNX4TtLq0H/HlHzgd607brsA7ewEXOxck3XJskEiAiBHwB2hJT5HxQNsnSHlzJkv5q5lVoDI/pZu7GoIPW+jJg\u003d\u003d","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9+quuFRqI7fjx6Q5wXk76JywJ2KLnysCWgd3fIddum8pusYMXOMucCaoKeegIa3LHbBZILqFE/UtO6Z79Fu35Q\\u003d\\u003d\",\"keyExpiration\":\"1745444874600\"}","signatures":["MEUCIGWzT7KbucJW1t74W4iZk6oLnATL5n06MNNxkq4Yayl0AiEA6fyaEJNIARPgeRnUlugM7rGSloar6X7QLjUInLDkllo\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"F1Oy9yyUAk+YDkzAm40h685jqvfV+Rua10hTXH4ljDeL6qP9WxtmTzT2zLnXvURBPtnsX0+NeX1TJCJDwFJGGh7z0+w3707EkOF1DnqEjPVrXUuaiUI2ramoSEAOu8k0IbNyVv29Dxrv1UwaWeqBAeT8PCde70SgorNhZtLjAsChPIhjMBtqGmSYB2mwlDXHWmoVnQvR80hA6QZ97er8pzN8wBRVgIb53Pk4z/zuFLBWrX9Zur+/zIMT+h2CU9A4KIf7k9DgNTjInm2SxffF618XUdu+6COk6AaOlQsLJjxCEwm8kMzD1K4hQ/JANLlppTMjxtivFhQ5AAN6WqqltHob/sxSIIQAOCqGCMDr4gmx6thLK6jAKrpEQbM1NdaGRTC+3x/vCfd0ETpg2TlksTVRo8KRf0EqeqhYWlKgSGBGR8tKNKdbxdXlKcH7jCt5jqiPsKpTVXFaOECtYIY5xlhC+vdV51hfI7uKhzfwdPGRDxB53tQMwgH8BaWT756MebIQIhZCai9xEAsbWX+Huoycu47ZDGMLaGnKrI/Hj0XAhMMJJBFHb3WhfNVHpo3NFz8o0xytXG08ZgNAgcub/+2Xg3xyWC6l0MamLNL4oXCS0fwscIM5fmxvikuI8VK/8hB2N66/nY78\",\"ephemeralPublicKey\":\"BPElFOvEM6mynmy3enzAxTTXd/6SkCkkcBuj2e/aWqW7ThauyGojBZk2Ik8BGz2ihjjtiHmEOkrEdsq3DuXRHeM\\u003d\",\"tag\":\"IUpc9fhaSOFZFmHMw9q2vnk3JCKLJUYM/nuBMxtnG5M\\u003d\"}"}`
	const testPayloadJSON = `{"signature":"MEYCIQDUGBBM5v1RIEgBZ5ubymWKe7OCaNfySO/TSZWwHszzeQIhALweUvBSPdCY9kr8BLRzrTFu/hV3rCF/6T5IXF8z7eB6","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGalwFwLnUoh1h/ZW4qdSgR9CaO9lZSFC3bj0QI0u3GCXWR2+YmJ2g3n9kZFh1P2qYfsW2epi2wNl/vLD3mf93g\\u003d\\u003d\",\"keyExpiration\":\"1746202989451\"}","signatures":["MEUCIGk7RGbRdQz5UyzpKmQPeGOlV25KJE23mwwRjXt3mwHuAiEA6dL4Bpj0yGs3+/w88NFMrYodvjXfVn+zvPTLt5XwGiQ\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"8NRn2kDk/Y9E3MjnSkTMg8vHkj06bCYva6WDbMHJd7xCptJHf2yrM0VEJhgrx1J1HnxzIIcInFisD3njx8tkPbHcl/qyhg5tI5CF9x+P6ipCeXyRQ9CNFVxLrztHyhQGIgd5lJ5IXotGeIpVhil0BFaTILoUvJMcgca2ZH+04tFHNo4zdZdiJ5K+1rmK+MAipb+Plkt8v8Pq47J8nq4P+FrqOqjXI3IIwCMwPhEdvCelSoB/5LxWbPcgAjZbLSCciBdT3xv6siO0/hQam7ONIsB1O9FgVMgWSZem1CU2QZQuup6qDMESgUxtCYww/W0zpbfexgW09wP0ua4DvDXsTy6DC+7U6FQuJfBKmlZjQggKLqbWILXvK1iplTlBc+/Ba+idGallBdPdFoK26+0pzaOF2IN8KZOHKIWxJNREIfj56taCuldxE1KKMS/hEg3E2+i4Gg1FXi2RoRy7cAiRu+IJiLRbQOhFDlgqsvFc0qrWCfZ/eLkfboHrJr8L87Aebfhce5eyGtc/s0xfTb4I0lkO35X96ZruBfsTq5gotW+5rlMm\",\"ephemeralPublicKey\":\"BHQJ4wdlO/s22yhEfzMvqMB05IF3KEWoeHD4ejjI2UNky5XdGl52c17Rh/8TM1FZ6L8s6egiWzVI6aX/BTfE2a4\\u003d\",\"tag\":\"gry72UABDT9zWP2LdmuTftWWqfE2URHRilosd7iFVlM\\u003d\"}"}`

	// testPayloadJSON, err := os.ReadFile("formatted.json")
	err := json.Unmarshal([]byte(testPayloadJSON), &input)
	require.NoError(t, err, "failed to unmarshal test payload")

	// Test Key registered with Google
	privateKeyBytes, err := os.ReadFile("pk8.pem")
	require.NoError(t, err, "failed to read test private key")

	// Create a new GooglePayDecryptor with the test private key
	decryptor, err := decrypt.NewWithRootKeysFromGoogle(decrypt.EnvironmentTest, "gateway:moov", string(privateKeyBytes))
	require.NoError(t, err, "failed to create decryptor")

	// Decrypt the test payload
	output, err = decryptor.Decrypt(input) // input is payload in types.Token
	require.NoError(t, err, "failed to decrypt")

	// Pretty print the decrypted token
	prettyOutput, err := json.MarshalIndent(output, "", "  ")
	require.NoError(t, err, "error formatting output")

	fmt.Printf("Decrypted Token:\n%s\n", string(prettyOutput))
}

func TestGoogleRegistrationPayload2(t *testing.T) {
	var input types.Token
	var output types.Decrypted

	// Test Payload2 from Google
	// const testPayloadJSON = `{"signature":"MEUCIDBed/eQewSKTwPE+WRd5lRzvBHtZffxqysmKrt+TdwFAiEAnYTyx6kVIQaNoC9UuoCWrnM/+IeTXVHU00Naf6EMU0o\u003d","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6XJ3IxVGm4UPb5A/VPE1iz9QWROqWbsdvbOZKxYm+BABNbp+8SK8yKqZJzJy8mLsECWoGdOpZh7vz215sxwctw\\u003d\\u003d\",\"keyExpiration\":\"1745446608521\"}","signatures":["MEQCIHS4b9KsBS1wErym+fZk+HRezXxUME13YQ0A3RKLbYJQAiBS04vGDPzrff7+0Ngs8CmeOMu2CX4dzOEfek8WjEVmlg\u003d\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"oStU+6sQXUhFEZsA9eGD09ptlmcIEklu5AlZxNH75BUcMgUCxout/5BhSauginexuOaA2um5TA0XdSAOSEYr13myzth8Vr4CXlElrnF5qXB8MgkxW2pV3CbXa+GX35BMprTkT2CwCUU8p3tz7D6DpBlZQHUhBOHrdNSHRNyUK3jzZZidVdb9J4KZSl3Z+hEgUYW4qBSfH2V6gIRYTX8X++SqV0L2zEWXlYiKHqekf1/oG1g0Zc6wp0gCzv+M4/MICFnc84sJRluqCQRyFQeLjjHL67/PC6TP3PvAwQIGBX2v+kp4vdGbOVY15DIcdjGAf/Gd3JKr9JeT8yoJ4WU2VbxY/f2CW9PpkSmQ1EJC+XILz9WKnuZ/CsQdzvZFYbKc7Nj4bWS3CdPs9+xDZmimhqH2qo/eZ6B/aP+JWdRuKybPyBGyo3i6Yz8Ug5hkQ0UBpM9y8Q2c0ze+vFlBG8MIKx7g4Y31ikB2Bj8ak6sj5zKb4Kh7ieQVALKJYX6g+UsEG7zndoHjET3gLhQnyXevndqwh82nVLBbyJB8EjE0F6z16ywb\",\"ephemeralPublicKey\":\"BIVyySX2QXz5zZCKW0LEwGqVl2LyS7DM1AJBzuKZeHJcSXhNZuSP2dKyRN/CkTeH/1Ura62Ro3PzUhVEHM8ytCo\\u003d\",\"tag\":\"wmb7b2JCFqZbFKxpJV1vcV58eVkwdNrQdzqcj+0dxNw\\u003d\"}"}`
	const testPayloadJSON = `{"signature":"MEYCIQDUGBBM5v1RIEgBZ5ubymWKe7OCaNfySO/TSZWwHszzeQIhALweUvBSPdCY9kr8BLRzrTFu/hV3rCF/6T5IXF8z7eB6","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGalwFwLnUoh1h/ZW4qdSgR9CaO9lZSFC3bj0QI0u3GCXWR2+YmJ2g3n9kZFh1P2qYfsW2epi2wNl/vLD3mf93g\\u003d\\u003d\",\"keyExpiration\":\"1746202989451\"}","signatures":["MEUCIGk7RGbRdQz5UyzpKmQPeGOlV25KJE23mwwRjXt3mwHuAiEA6dL4Bpj0yGs3+/w88NFMrYodvjXfVn+zvPTLt5XwGiQ\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"8NRn2kDk/Y9E3MjnSkTMg8vHkj06bCYva6WDbMHJd7xCptJHf2yrM0VEJhgrx1J1HnxzIIcInFisD3njx8tkPbHcl/qyhg5tI5CF9x+P6ipCeXyRQ9CNFVxLrztHyhQGIgd5lJ5IXotGeIpVhil0BFaTILoUvJMcgca2ZH+04tFHNo4zdZdiJ5K+1rmK+MAipb+Plkt8v8Pq47J8nq4P+FrqOqjXI3IIwCMwPhEdvCelSoB/5LxWbPcgAjZbLSCciBdT3xv6siO0/hQam7ONIsB1O9FgVMgWSZem1CU2QZQuup6qDMESgUxtCYww/W0zpbfexgW09wP0ua4DvDXsTy6DC+7U6FQuJfBKmlZjQggKLqbWILXvK1iplTlBc+/Ba+idGallBdPdFoK26+0pzaOF2IN8KZOHKIWxJNREIfj56taCuldxE1KKMS/hEg3E2+i4Gg1FXi2RoRy7cAiRu+IJiLRbQOhFDlgqsvFc0qrWCfZ/eLkfboHrJr8L87Aebfhce5eyGtc/s0xfTb4I0lkO35X96ZruBfsTq5gotW+5rlMm\",\"ephemeralPublicKey\":\"BHQJ4wdlO/s22yhEfzMvqMB05IF3KEWoeHD4ejjI2UNky5XdGl52c17Rh/8TM1FZ6L8s6egiWzVI6aX/BTfE2a4\\u003d\",\"tag\":\"gry72UABDT9zWP2LdmuTftWWqfE2URHRilosd7iFVlM\\u003d\"}"}`

	// testPayloadJSON, err := os.ReadFile("formatted.json")
	err := json.Unmarshal([]byte(testPayloadJSON), &input)
	if err != nil {
		t.Errorf("failed to unmarshal test payload: %v", err)
	}

	// Test Key registered with Google
	privateKeyBytes, err := os.ReadFile("pk8.pem")
	if err != nil {
		fmt.Printf("Error reading test private key: %v\n", err)
		return
	}

	// Create a new GooglePayDecryptor with the test private key
	decryptor, err := decrypt.NewWithRootKeysFromGoogle(decrypt.EnvironmentTest, "gateway:moov", string(privateKeyBytes))
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
}

func TestWith2KeysPrimaryGood(t *testing.T) {
	var input types.Token
	var output types.Decrypted

	// Test Payload2 from Google
	// const testPayloadJSON = `{"signature":"MEUCIDBed/eQewSKTwPE+WRd5lRzvBHtZffxqysmKrt+TdwFAiEAnYTyx6kVIQaNoC9UuoCWrnM/+IeTXVHU00Naf6EMU0o\u003d","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6XJ3IxVGm4UPb5A/VPE1iz9QWROqWbsdvbOZKxYm+BABNbp+8SK8yKqZJzJy8mLsECWoGdOpZh7vz215sxwctw\\u003d\\u003d\",\"keyExpiration\":\"1745446608521\"}","signatures":["MEQCIHS4b9KsBS1wErym+fZk+HRezXxUME13YQ0A3RKLbYJQAiBS04vGDPzrff7+0Ngs8CmeOMu2CX4dzOEfek8WjEVmlg\u003d\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"oStU+6sQXUhFEZsA9eGD09ptlmcIEklu5AlZxNH75BUcMgUCxout/5BhSauginexuOaA2um5TA0XdSAOSEYr13myzth8Vr4CXlElrnF5qXB8MgkxW2pV3CbXa+GX35BMprTkT2CwCUU8p3tz7D6DpBlZQHUhBOHrdNSHRNyUK3jzZZidVdb9J4KZSl3Z+hEgUYW4qBSfH2V6gIRYTX8X++SqV0L2zEWXlYiKHqekf1/oG1g0Zc6wp0gCzv+M4/MICFnc84sJRluqCQRyFQeLjjHL67/PC6TP3PvAwQIGBX2v+kp4vdGbOVY15DIcdjGAf/Gd3JKr9JeT8yoJ4WU2VbxY/f2CW9PpkSmQ1EJC+XILz9WKnuZ/CsQdzvZFYbKc7Nj4bWS3CdPs9+xDZmimhqH2qo/eZ6B/aP+JWdRuKybPyBGyo3i6Yz8Ug5hkQ0UBpM9y8Q2c0ze+vFlBG8MIKx7g4Y31ikB2Bj8ak6sj5zKb4Kh7ieQVALKJYX6g+UsEG7zndoHjET3gLhQnyXevndqwh82nVLBbyJB8EjE0F6z16ywb\",\"ephemeralPublicKey\":\"BIVyySX2QXz5zZCKW0LEwGqVl2LyS7DM1AJBzuKZeHJcSXhNZuSP2dKyRN/CkTeH/1Ura62Ro3PzUhVEHM8ytCo\\u003d\",\"tag\":\"wmb7b2JCFqZbFKxpJV1vcV58eVkwdNrQdzqcj+0dxNw\\u003d\"}"}`
	const testPayloadJSON = `{"signature":"MEYCIQDUGBBM5v1RIEgBZ5ubymWKe7OCaNfySO/TSZWwHszzeQIhALweUvBSPdCY9kr8BLRzrTFu/hV3rCF/6T5IXF8z7eB6","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGalwFwLnUoh1h/ZW4qdSgR9CaO9lZSFC3bj0QI0u3GCXWR2+YmJ2g3n9kZFh1P2qYfsW2epi2wNl/vLD3mf93g\\u003d\\u003d\",\"keyExpiration\":\"1746202989451\"}","signatures":["MEUCIGk7RGbRdQz5UyzpKmQPeGOlV25KJE23mwwRjXt3mwHuAiEA6dL4Bpj0yGs3+/w88NFMrYodvjXfVn+zvPTLt5XwGiQ\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"8NRn2kDk/Y9E3MjnSkTMg8vHkj06bCYva6WDbMHJd7xCptJHf2yrM0VEJhgrx1J1HnxzIIcInFisD3njx8tkPbHcl/qyhg5tI5CF9x+P6ipCeXyRQ9CNFVxLrztHyhQGIgd5lJ5IXotGeIpVhil0BFaTILoUvJMcgca2ZH+04tFHNo4zdZdiJ5K+1rmK+MAipb+Plkt8v8Pq47J8nq4P+FrqOqjXI3IIwCMwPhEdvCelSoB/5LxWbPcgAjZbLSCciBdT3xv6siO0/hQam7ONIsB1O9FgVMgWSZem1CU2QZQuup6qDMESgUxtCYww/W0zpbfexgW09wP0ua4DvDXsTy6DC+7U6FQuJfBKmlZjQggKLqbWILXvK1iplTlBc+/Ba+idGallBdPdFoK26+0pzaOF2IN8KZOHKIWxJNREIfj56taCuldxE1KKMS/hEg3E2+i4Gg1FXi2RoRy7cAiRu+IJiLRbQOhFDlgqsvFc0qrWCfZ/eLkfboHrJr8L87Aebfhce5eyGtc/s0xfTb4I0lkO35X96ZruBfsTq5gotW+5rlMm\",\"ephemeralPublicKey\":\"BHQJ4wdlO/s22yhEfzMvqMB05IF3KEWoeHD4ejjI2UNky5XdGl52c17Rh/8TM1FZ6L8s6egiWzVI6aX/BTfE2a4\\u003d\",\"tag\":\"gry72UABDT9zWP2LdmuTftWWqfE2URHRilosd7iFVlM\\u003d\"}"}`

	// testPayloadJSON, err := os.ReadFile("formatted.json")
	err := json.Unmarshal([]byte(testPayloadJSON), &input)
	if err != nil {
		t.Errorf("failed to unmarshal test payload: %v", err)
	}

	// Test Key registered with Google
	privateKeyBytes, err := os.ReadFile("pk8.pem")
	if err != nil {
		fmt.Printf("Error reading test private key: %v\n", err)
		return
	}

	// Create a new GooglePayDecryptor with the test private key
	decryptor, err := decrypt.NewWithRootKeysFromGoogle(decrypt.EnvironmentTest, "gateway:moov", string(privateKeyBytes))
	if err != nil {
		t.Errorf("failed to create decryptor: %v", err)
	}

	// Add a bad key for testing
	privateKeyBytesBad, err := os.ReadFile("pk8_bad.pem")
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
}

func TestWith2KeysSecondaryGood(t *testing.T) {
	var input types.Token
	var output types.Decrypted

	// Test Payload2 from Google
	// const testPayloadJSON = `{"signature":"MEUCIDBed/eQewSKTwPE+WRd5lRzvBHtZffxqysmKrt+TdwFAiEAnYTyx6kVIQaNoC9UuoCWrnM/+IeTXVHU00Naf6EMU0o\u003d","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6XJ3IxVGm4UPb5A/VPE1iz9QWROqWbsdvbOZKxYm+BABNbp+8SK8yKqZJzJy8mLsECWoGdOpZh7vz215sxwctw\\u003d\\u003d\",\"keyExpiration\":\"1745446608521\"}","signatures":["MEQCIHS4b9KsBS1wErym+fZk+HRezXxUME13YQ0A3RKLbYJQAiBS04vGDPzrff7+0Ngs8CmeOMu2CX4dzOEfek8WjEVmlg\u003d\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"oStU+6sQXUhFEZsA9eGD09ptlmcIEklu5AlZxNH75BUcMgUCxout/5BhSauginexuOaA2um5TA0XdSAOSEYr13myzth8Vr4CXlElrnF5qXB8MgkxW2pV3CbXa+GX35BMprTkT2CwCUU8p3tz7D6DpBlZQHUhBOHrdNSHRNyUK3jzZZidVdb9J4KZSl3Z+hEgUYW4qBSfH2V6gIRYTX8X++SqV0L2zEWXlYiKHqekf1/oG1g0Zc6wp0gCzv+M4/MICFnc84sJRluqCQRyFQeLjjHL67/PC6TP3PvAwQIGBX2v+kp4vdGbOVY15DIcdjGAf/Gd3JKr9JeT8yoJ4WU2VbxY/f2CW9PpkSmQ1EJC+XILz9WKnuZ/CsQdzvZFYbKc7Nj4bWS3CdPs9+xDZmimhqH2qo/eZ6B/aP+JWdRuKybPyBGyo3i6Yz8Ug5hkQ0UBpM9y8Q2c0ze+vFlBG8MIKx7g4Y31ikB2Bj8ak6sj5zKb4Kh7ieQVALKJYX6g+UsEG7zndoHjET3gLhQnyXevndqwh82nVLBbyJB8EjE0F6z16ywb\",\"ephemeralPublicKey\":\"BIVyySX2QXz5zZCKW0LEwGqVl2LyS7DM1AJBzuKZeHJcSXhNZuSP2dKyRN/CkTeH/1Ura62Ro3PzUhVEHM8ytCo\\u003d\",\"tag\":\"wmb7b2JCFqZbFKxpJV1vcV58eVkwdNrQdzqcj+0dxNw\\u003d\"}"}`
	const testPayloadJSON = `{"signature":"MEYCIQDUGBBM5v1RIEgBZ5ubymWKe7OCaNfySO/TSZWwHszzeQIhALweUvBSPdCY9kr8BLRzrTFu/hV3rCF/6T5IXF8z7eB6","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGalwFwLnUoh1h/ZW4qdSgR9CaO9lZSFC3bj0QI0u3GCXWR2+YmJ2g3n9kZFh1P2qYfsW2epi2wNl/vLD3mf93g\\u003d\\u003d\",\"keyExpiration\":\"1746202989451\"}","signatures":["MEUCIGk7RGbRdQz5UyzpKmQPeGOlV25KJE23mwwRjXt3mwHuAiEA6dL4Bpj0yGs3+/w88NFMrYodvjXfVn+zvPTLt5XwGiQ\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"8NRn2kDk/Y9E3MjnSkTMg8vHkj06bCYva6WDbMHJd7xCptJHf2yrM0VEJhgrx1J1HnxzIIcInFisD3njx8tkPbHcl/qyhg5tI5CF9x+P6ipCeXyRQ9CNFVxLrztHyhQGIgd5lJ5IXotGeIpVhil0BFaTILoUvJMcgca2ZH+04tFHNo4zdZdiJ5K+1rmK+MAipb+Plkt8v8Pq47J8nq4P+FrqOqjXI3IIwCMwPhEdvCelSoB/5LxWbPcgAjZbLSCciBdT3xv6siO0/hQam7ONIsB1O9FgVMgWSZem1CU2QZQuup6qDMESgUxtCYww/W0zpbfexgW09wP0ua4DvDXsTy6DC+7U6FQuJfBKmlZjQggKLqbWILXvK1iplTlBc+/Ba+idGallBdPdFoK26+0pzaOF2IN8KZOHKIWxJNREIfj56taCuldxE1KKMS/hEg3E2+i4Gg1FXi2RoRy7cAiRu+IJiLRbQOhFDlgqsvFc0qrWCfZ/eLkfboHrJr8L87Aebfhce5eyGtc/s0xfTb4I0lkO35X96ZruBfsTq5gotW+5rlMm\",\"ephemeralPublicKey\":\"BHQJ4wdlO/s22yhEfzMvqMB05IF3KEWoeHD4ejjI2UNky5XdGl52c17Rh/8TM1FZ6L8s6egiWzVI6aX/BTfE2a4\\u003d\",\"tag\":\"gry72UABDT9zWP2LdmuTftWWqfE2URHRilosd7iFVlM\\u003d\"}"}`

	// testPayloadJSON, err := os.ReadFile("formatted.json")
	err := json.Unmarshal([]byte(testPayloadJSON), &input)
	if err != nil {
		t.Errorf("failed to unmarshal test payload: %v", err)
	}

	// Test Bad Key
	privateKeyBytes, err := os.ReadFile("pk8_bad.pem")
	if err != nil {
		fmt.Printf("Error reading test private key: %v\n", err)
		return
	}

	// Create a new GooglePayDecryptor with the test private key
	decryptor, err := decrypt.NewWithRootKeysFromGoogle(decrypt.EnvironmentTest, "gateway:moov", string(privateKeyBytes))
	if err != nil {
		t.Errorf("failed to create decryptor: %v", err)
	}

	// Add a bad key for testing
	privateKeyBytesBad, err := os.ReadFile("pk8.pem")
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
}

func TestWith2BadKeys(t *testing.T) {
	var input types.Token

	// Test Payload2 from Google
	// const testPayloadJSON = `{"signature":"MEUCIDBed/eQewSKTwPE+WRd5lRzvBHtZffxqysmKrt+TdwFAiEAnYTyx6kVIQaNoC9UuoCWrnM/+IeTXVHU00Naf6EMU0o\u003d","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6XJ3IxVGm4UPb5A/VPE1iz9QWROqWbsdvbOZKxYm+BABNbp+8SK8yKqZJzJy8mLsECWoGdOpZh7vz215sxwctw\\u003d\\u003d\",\"keyExpiration\":\"1745446608521\"}","signatures":["MEQCIHS4b9KsBS1wErym+fZk+HRezXxUME13YQ0A3RKLbYJQAiBS04vGDPzrff7+0Ngs8CmeOMu2CX4dzOEfek8WjEVmlg\u003d\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"oStU+6sQXUhFEZsA9eGD09ptlmcIEklu5AlZxNH75BUcMgUCxout/5BhSauginexuOaA2um5TA0XdSAOSEYr13myzth8Vr4CXlElrnF5qXB8MgkxW2pV3CbXa+GX35BMprTkT2CwCUU8p3tz7D6DpBlZQHUhBOHrdNSHRNyUK3jzZZidVdb9J4KZSl3Z+hEgUYW4qBSfH2V6gIRYTX8X++SqV0L2zEWXlYiKHqekf1/oG1g0Zc6wp0gCzv+M4/MICFnc84sJRluqCQRyFQeLjjHL67/PC6TP3PvAwQIGBX2v+kp4vdGbOVY15DIcdjGAf/Gd3JKr9JeT8yoJ4WU2VbxY/f2CW9PpkSmQ1EJC+XILz9WKnuZ/CsQdzvZFYbKc7Nj4bWS3CdPs9+xDZmimhqH2qo/eZ6B/aP+JWdRuKybPyBGyo3i6Yz8Ug5hkQ0UBpM9y8Q2c0ze+vFlBG8MIKx7g4Y31ikB2Bj8ak6sj5zKb4Kh7ieQVALKJYX6g+UsEG7zndoHjET3gLhQnyXevndqwh82nVLBbyJB8EjE0F6z16ywb\",\"ephemeralPublicKey\":\"BIVyySX2QXz5zZCKW0LEwGqVl2LyS7DM1AJBzuKZeHJcSXhNZuSP2dKyRN/CkTeH/1Ura62Ro3PzUhVEHM8ytCo\\u003d\",\"tag\":\"wmb7b2JCFqZbFKxpJV1vcV58eVkwdNrQdzqcj+0dxNw\\u003d\"}"}`
	const testPayloadJSON = `{"signature":"MEYCIQDUGBBM5v1RIEgBZ5ubymWKe7OCaNfySO/TSZWwHszzeQIhALweUvBSPdCY9kr8BLRzrTFu/hV3rCF/6T5IXF8z7eB6","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGalwFwLnUoh1h/ZW4qdSgR9CaO9lZSFC3bj0QI0u3GCXWR2+YmJ2g3n9kZFh1P2qYfsW2epi2wNl/vLD3mf93g\\u003d\\u003d\",\"keyExpiration\":\"1746202989451\"}","signatures":["MEUCIGk7RGbRdQz5UyzpKmQPeGOlV25KJE23mwwRjXt3mwHuAiEA6dL4Bpj0yGs3+/w88NFMrYodvjXfVn+zvPTLt5XwGiQ\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"8NRn2kDk/Y9E3MjnSkTMg8vHkj06bCYva6WDbMHJd7xCptJHf2yrM0VEJhgrx1J1HnxzIIcInFisD3njx8tkPbHcl/qyhg5tI5CF9x+P6ipCeXyRQ9CNFVxLrztHyhQGIgd5lJ5IXotGeIpVhil0BFaTILoUvJMcgca2ZH+04tFHNo4zdZdiJ5K+1rmK+MAipb+Plkt8v8Pq47J8nq4P+FrqOqjXI3IIwCMwPhEdvCelSoB/5LxWbPcgAjZbLSCciBdT3xv6siO0/hQam7ONIsB1O9FgVMgWSZem1CU2QZQuup6qDMESgUxtCYww/W0zpbfexgW09wP0ua4DvDXsTy6DC+7U6FQuJfBKmlZjQggKLqbWILXvK1iplTlBc+/Ba+idGallBdPdFoK26+0pzaOF2IN8KZOHKIWxJNREIfj56taCuldxE1KKMS/hEg3E2+i4Gg1FXi2RoRy7cAiRu+IJiLRbQOhFDlgqsvFc0qrWCfZ/eLkfboHrJr8L87Aebfhce5eyGtc/s0xfTb4I0lkO35X96ZruBfsTq5gotW+5rlMm\",\"ephemeralPublicKey\":\"BHQJ4wdlO/s22yhEfzMvqMB05IF3KEWoeHD4ejjI2UNky5XdGl52c17Rh/8TM1FZ6L8s6egiWzVI6aX/BTfE2a4\\u003d\",\"tag\":\"gry72UABDT9zWP2LdmuTftWWqfE2URHRilosd7iFVlM\\u003d\"}"}`

	// testPayloadJSON, err := os.ReadFile("formatted.json")
	err := json.Unmarshal([]byte(testPayloadJSON), &input)
	if err != nil {
		t.Errorf("failed to unmarshal test payload: %v", err)
	}

	// Test Bad Key
	privateKeyBytes, err := os.ReadFile("pk8_bad.pem")
	if err != nil {
		fmt.Printf("Error reading test private key: %v\n", err)
		return
	}

	// Create a new GooglePayDecryptor with the test private key
	decryptor, err := decrypt.NewWithRootKeysFromGoogle(decrypt.EnvironmentTest, "gateway:moov", string(privateKeyBytes))
	if err != nil {
		t.Errorf("failed to create decryptor: %v", err)
	}

	// Add a bad key for testing
	privateKeyBytesBad, err := os.ReadFile("pk8_bad2.pem")
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
}

func TestWithTokenGenerator(t *testing.T) {
	var input types.Token
	var output types.Decrypted

	// Test Payload from Google Token Generator: https://developers.google.com/pay/api/processors/guides/test-and-validation/token-generator
	const testPayloadJSON = `{"signature":"MEYCIQDUGBBM5v1RIEgBZ5ubymWKe7OCaNfySO/TSZWwHszzeQIhALweUvBSPdCY9kr8BLRzrTFu/hV3rCF/6T5IXF8z7eB6","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGalwFwLnUoh1h/ZW4qdSgR9CaO9lZSFC3bj0QI0u3GCXWR2+YmJ2g3n9kZFh1P2qYfsW2epi2wNl/vLD3mf93g\\u003d\\u003d\",\"keyExpiration\":\"1746202989451\"}","signatures":["MEUCIGk7RGbRdQz5UyzpKmQPeGOlV25KJE23mwwRjXt3mwHuAiEA6dL4Bpj0yGs3+/w88NFMrYodvjXfVn+zvPTLt5XwGiQ\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"8NRn2kDk/Y9E3MjnSkTMg8vHkj06bCYva6WDbMHJd7xCptJHf2yrM0VEJhgrx1J1HnxzIIcInFisD3njx8tkPbHcl/qyhg5tI5CF9x+P6ipCeXyRQ9CNFVxLrztHyhQGIgd5lJ5IXotGeIpVhil0BFaTILoUvJMcgca2ZH+04tFHNo4zdZdiJ5K+1rmK+MAipb+Plkt8v8Pq47J8nq4P+FrqOqjXI3IIwCMwPhEdvCelSoB/5LxWbPcgAjZbLSCciBdT3xv6siO0/hQam7ONIsB1O9FgVMgWSZem1CU2QZQuup6qDMESgUxtCYww/W0zpbfexgW09wP0ua4DvDXsTy6DC+7U6FQuJfBKmlZjQggKLqbWILXvK1iplTlBc+/Ba+idGallBdPdFoK26+0pzaOF2IN8KZOHKIWxJNREIfj56taCuldxE1KKMS/hEg3E2+i4Gg1FXi2RoRy7cAiRu+IJiLRbQOhFDlgqsvFc0qrWCfZ/eLkfboHrJr8L87Aebfhce5eyGtc/s0xfTb4I0lkO35X96ZruBfsTq5gotW+5rlMm\",\"ephemeralPublicKey\":\"BHQJ4wdlO/s22yhEfzMvqMB05IF3KEWoeHD4ejjI2UNky5XdGl52c17Rh/8TM1FZ6L8s6egiWzVI6aX/BTfE2a4\\u003d\",\"tag\":\"gry72UABDT9zWP2LdmuTftWWqfE2URHRilosd7iFVlM\\u003d\"}"}`

	// testPayloadJSON, err := os.ReadFile("formatted.json")
	err := json.Unmarshal([]byte(testPayloadJSON), &input)
	if err != nil {
		t.Errorf("failed to unmarshal test payload: %v", err)
	}

	// Get Key
	privateKeyBytes, err := os.ReadFile("pk8.pem")
	if err != nil {
		fmt.Printf("Error reading test private key: %v\n", err)
		return
	}

	// Create a new GooglePayDecryptor with the test private key
	decryptor, err := decrypt.NewWithRootKeysFromGoogle(decrypt.EnvironmentTest, "gateway:moov", string(privateKeyBytes))
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
	// fmt.Printf("Root Keys:\n%v\n", decryptor.RootKeys)
}
