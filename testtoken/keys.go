package testtoken

// These are pre-generated test keys that work together for round-trip ECv2 token
// generation and decryption. They are NOT production keys and must never be used
// outside of testing.

// defaultRootPrivateKey is the PKCS8 base64-encoded private key whose public key
// appears in defaultRootKeysJSON. Used to sign intermediate signing keys.
const defaultRootPrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpSUdbEqo4+QjCZK7WM8zMCFs72hSeh9Lb5lfHePxgvOhRANCAAQKtrxMWMWTx1qXPQgRSnIdFG8yMcNm2qT3NP2M8X1ultD7bfVDYo/X/mrlfK3gO62qxJBBMiuqEkpH53vz7TME"

// defaultRecipientPrivateKey is the PKCS8 base64-encoded private key for the
// test merchant/recipient. The decryptor must be configured with this key.
const defaultRecipientPrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9NOcYUqB/r6INl03CFTwfQNfgPhoniRmw/C61KnLUvShRANCAASNetViWVbnNrZlMkmllIcF4EP8Su3i+ZYv9mcrvZ/SSMKWhnqK61FrrPOkVFwQuPUjZpVTZnbRx3CtQpwPJXj+"

// defaultRootKeysJSON contains the public key matching defaultRootPrivateKey,
// formatted as Google's root signing keys JSON document.
const defaultRootKeysJSON = `{"keys":[{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECra8TFjFk8dalz0IEUpyHRRvMjHDZtqk9zT9jPF9bpbQ+231Q2KP1/5q5Xyt4DutqsSQQTIrqhJKR+d78+0zBA==","protocolVersion":"ECv2","keyExpiration":"2154841200000"}]}`
