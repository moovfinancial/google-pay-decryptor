> **IMPORTANT**: The file library has not been through a formal code review!!!
>
> Please peer-review the code before using.

# Google Pay Decryptor

The Google Pay Decryptor library provides functions to verify Google Pay Token Signatures, decrypt Google Pay encrypted messages and format the data according to the Google Pay specifications.

**Google Pay Documentation Resources**
- [Google Pay Response Objects](https://developers.google.com/pay/api/web/reference/response-objects)
- [Google Pay Web Overview](https://developers.google.com/pay/api/web/overview)
- [Google Pay Processor Overview](https://developers.google.com/pay/api/processors/overview)

## Getting Started

This library uses the [Tink](https://github.com/google/tink) library, which is the recommended decryption library from Google.
- **NOTE**: The Go version of the Tink library is not full featured like the Java version
   - In the Google Pay documentation, you will find functions available in Java that are NOT available in Go.

### Types

There are two main types in library:
1. Token - encrypted payload from GooglePay
   - `var input types.Token`
   - [Payment Method Token Structure](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#payment-method-token-structure)
2. Decrypted - decrypted payload
   - `var output types.Decrypted`
   - [Encrypted Message Structure](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#encrypted-message)
   - [Decrypted Card Payment Method Structure](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#card)

Example of a Token (encrypted payload from Google Pay):
```json
{
  "protocolVersion":"ECv2",
  "signature":"MEQCIH6Q4OwQ0jAceFEkGF0JID6sJNXxOEi4r+mA7biRxqBQAiAondqoUpU/bdsrAOpZIsrHQS9nwiiNwOrr24RyPeHA0Q\u003d\u003d",
  "intermediateSigningKey":{
    "signedKey": "{\"keyExpiration\":\"1542323393147\",\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw\\u003d\\u003d\"}",
    "signatures": ["MEYCIQCO2EIi48s8VTH+ilMEpoXLFfkxAwHjfPSCVED/QDSHmQIhALLJmrUlNAY8hDQRV/y1iKZGsWpeNmIP+z+tCQHQxP0v"]
  },
  "signedMessage":"{\"tag\":\"jpGz1F1Bcoi/fCNxI9n7Qrsw7i7KHrGtTf3NrRclt+U\\u003d\",\"ephemeralPublicKey\":\"BJatyFvFPPD21l8/uLP46Ta1hsKHndf8Z+tAgk+DEPQgYTkhHy19cF3h/bXs0tWTmZtnNm+vlVrKbRU9K8+7cZs\\u003d\",\"encryptedMessage\":\"mKOoXwi8OavZ\"}"
}
```

Example of a Decrypted payload:
```json
{
  "messageId": "some-message-id",
  "messageExpiration": "1759309000000"
  "paymentMethod": "CARD",
  "paymentMethodDetails": {
    "authMethod": "PAN_ONLY",
    "pan": "1111222233334444",
    "expirationMonth": 10,
    "expirationYear": 2025
  },
}
```

### Setup

Load the following information:
1. [Google Root Signing Keys](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#root-signing-keys)
2. [Private Key](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#using-openssl)
3. [Recipient ID](https://developers.google.com/pay/api/web/guides/tutorial#tokenization)
   - If processor, recipient id is the gateway id.
   - If merchant, recipient id is the merchant id.

### Usage

The following shows a basic example to verify and decrypt a Google Pay Token payload:
```go
var input types.Token
var output types.Decrypted

// Read the Payload
const payloadJSON = `ADD PAYLOAD FROM GOOGLE HERE`
err := json.Unmarshal([]byte(testPayloadJSON), &input)
if err != nil {
  t.Errorf("failed to unmarshal payload: %v", err)
}

// Load Private Key
privateKeyBytes, err := os.ReadFile("pk8.pem")
if err != nil {
  fmt.Printf("Error reading test private key: %v\n", err)
  return
}

// Create a new GooglePayDecryptor with the private key and auto-fetch latest Google Pay Root Signing Keys
decryptor, err := decrypt.NewWithRootKeysFromGoogle(decrypt.EnvironmentTest, "gateway:moov", string(privateKeyBytes))
if err != nil {
  t.Errorf("failed to create decryptor: %v", err)
}

// Decrypt the test payload
output, err = decryptor.DecryptWithMerchantId(input, "googletest")  // Replace googletest with the Gateway Merchant ID Assigned to the Merchant
if err != nil {
  t.Errorf("failed to decrypt: %v", err)
}

// Pretty print the decrypted token
prettyOutput, err := json.MarshalIndent(output, "", "  ")
if err != nil {
  t.Fatalf("error formatting output: %v", err)
}
fmt.Printf("Decrypted Token:\n%s\n", string(prettyOutput))
```

If the payload is invalid, the key is bad or the message is expired then decryption will fail.

## Key Rotation

Google requires Processors to support [Annual Key Rotation](https://developers.google.com/pay/api/processors/guides/implementation/rotate-keys-with).
- This repo allows multiple keys to be added to the repo.

### Key Generation

The `./key_generation/generate_keys.sh` script will generate keys in the format that [Google requires for key registration](https://developers.google.com/pay/api/processors/guides/implementation/prepare-your-key)
- Once the new public key is generated, it needs to be sent to Google to be registered

### Supporting more than one key at runtime

During Key Rotation, the Processor must support both the old key and new key in order to prevent decryption issues
- Both private keys should be used to try and decrypt the payload until it's confirmed that the new public key has been loaded
- Once Google has confirmed that the new public key has been loaded, the old private key can be removed

### Usage

After creating a new `GooglePayDecryptor` add the second key:
```go
// ...

// Create a new GooglePayDecryptor with the private key
decryptor, err := decrypt.NewWithRootKeysFromGoogle(decrypt.EnvironmentTest, "gateway:moov", string(privateKeyBytes))
if err != nil {
  t.Errorf("failed to create decryptor: %v", err)
}

// Load a 2nd Private Key for Key Rotation
decryptor.AddPrivateKey(string(privateKeyBytesBad), "old_key")

// ...
```

**NOTE:** Decryption will attempted with the first key loaded
- The 2nd key will only be used to attempt decryption if the first key failed to decrypt the payload

## Original Authors

* **Zhuman Rakhat** - *Initial work* - [Google Pay Decryptor](https://github.com/zethuman/google-pay-decryptor)
* **Naidenko Dmytro** - *Forked work* - [Google Pay Decryptor](https://github.com/M1crogravity/google-pay-decryptor)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
- All copyright notices have been persisted in observance with the MIT license requirements
