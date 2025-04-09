package registration

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/moovfinancial/google-pay-decryptor/decrypt"
	"github.com/moovfinancial/google-pay-decryptor/decrypt/types"
)

func TestGoogleRegistration(t *testing.T) {
	var input types.Token
	var output types.Decrypted

	// Test Payload from Google
	const testPayloadJSON = `{
		"protocolVersion":"ECv2",
		"signature":"MEUCIG39tbaQPwJe28U+UMsJmxUBUWSkwlOv9Ibohacer+CoAiEA8Wuq3lLUCwLQ06D2kErxaMg3b/oLDFbd2gcFze1zDqU\u003d",
		"intermediateSigningKey":{
		  "signedKey": "{\"keyExpiration\":\"1542394027316\",\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw\\u003d\\u003d\"}",
		  "signatures": ["MEYCIQDcXCoB4fYJF3EolxrE2zB+7THZCfKA7cWxSztKceXTCgIhAN/d5eBgx/1A6qKBdH0IS7/aQ7dO4MuEt26OrLCUxZnl"]
		},
		"signedMessage":"{\"tag\":\"TjkIKzIOvCrFvjf7/aeeL8/FZJ3tigaNnerag68hIaw\\u003d\",\"ephemeralPublicKey\":\"BLJoTmxP2z7M2N6JmaN786aJcT/L/OJfuJKQdIXcceuBBZ00sf5nm2+snxAJxeJ4HYFTdNH4MOJrH58GNDJ9lJw\\u003d\",\"encryptedMessage\":\"mleAf23XkKjj\"}"
	  }`

	err := json.Unmarshal([]byte(testPayloadJSON), &input)
	if err != nil {
		t.Errorf("failed to unmarshal test payload: %v", err)
	}

	// Test Key registered with Google
	privateKeyBytes, err := os.ReadFile("./private_keys/pk8.pem")
	if err != nil {
		fmt.Printf("Error reading test private key: %v\n", err)
		return
	}

	// Create a new GooglePayDecryptor with the test private key
	decryptor, err := decrypt.NewWithRootKeysFromGoogle("test", "merchant:12345678901234567890", string(privateKeyBytes))
	if err != nil {
		t.Errorf("failed to create decryptor: %v", err)
	}

	// Decrypt the test payload
	output, err = decryptor.Decrypt(input) // input is payload in types.Token
	if err != nil {
		t.Errorf("failed to decrypt: %v", err)
	}

	fmt.Println(output)
}
