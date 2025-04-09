# Google Pay Decryptor Tool

Tired of looking for information about cryptography and decrypting google pay token in Golang? Then this library will definitely make your work easier. I can’t say that the solution is ideal, so I accept any suggestions and will be glad to contributors.

## Getting Started

Library was written in base of [Tink](https://github.com/google/tink) library, which is official from Google.

### Prerequisites

Install by one step

```
go get -v github.com/moovfinancial/google-pay-decryptor
```

### Types

There are two main types in library:

1. Token - encrypted payload from GooglePay

```
var input types.Token
```

2. Decrypted - decrypted payload

```
var output types.Decrypted
```

### Demo

Load the following information:
1. [root signing keys](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#root-signing-keys)
2. [private key](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#using-openssl)
3. [merchantID](https://developers.google.com/pay/api/web/guides/tutorial#tokenization) as recipientId while launching app

```
decrypt.Init(rootKeys, recipientId, privateKey)
```

Keys will be initialized and stored to environment variables.

If you want to renew keys, just restart app.

2. Decrypt payload

```
decryptor, err = decrypt.NewGooglePayDecryptor()
if err != nil {
    return types.Decrypted{}, err
}

output, err = decrypt.Decrypt(input) // input is payload in types.Token
if err != nil {
    return types.Decrypted{}, err
}
```

## Running the tests

To run tests

```
go test -v ./...
```

To see coverage of tests

```
go test -cover -coverprofile=c.out
```

To visualize coverage by tests

```
go tool cover -html=c.out -o coverage.html
```

## Original Authors

* **Zhuman Rakhat** - *Initial work* - [Google Pay Decryptor](https://github.com/zethuman/google-pay-decryptor)
* **Naidenko Dmytro** - *Forked work* - [Google Pay Decryptor](https://github.com/M1crogravity/google-pay-decryptor)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
