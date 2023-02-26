# Google Pay Decryptor Tool

Tired of looking for information about cryptography and decrypting google pay token in Golang? Then this library will definitely make your work easier. I can’t say that the solution is ideal, so I accept any suggestions and will be glad to contributors.

## Getting Started

Library was written in base of [Tink](https://github.com/google/tink) library, which is official from Google.

### Prerequisites

Install by one step

```
go get -v github.com/zethuman/google-pay-decryptor
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

1. Load [root signing keys](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#root-signing-keys), [private key](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography#using-openssl) and [merchantID](https://developers.google.com/pay/api/web/guides/tutorial#tokenization) as recipientId while launching app

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

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **Zhuman Rakhat** - *Initial work* - [Google Pay Decryptor](https://github.com/zethuman/google-pay-decryptor)

See also the list of [contributors](https://github.com/zethuman/google-pay-decryptor/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* If you find an error, feel free to open an issue and we will figure it out
* Let's make the world easier and improve the design and implementations in Go
