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
const googleRegErrorTestEnvironment = decrypt.EnvironmentTest
const googleRegErrorTestGatewayID = "moov"
const googleRegErrorTestMerchantID = "googletest"

// Google Pay Keys for testing
const googleRegErrorTestPrivateKey = "../keys/pk8.pem"

// Payloads from Google - Each are to fail for different reasons
// Update these payloads with the latest from Google each time you rotate the keys
const googleRegistrationErrorPayload1 = `{"signature":"MEYCIQC3ztVNZG97bb2xjIJlqiUlHM3XhOaFojfBjv/v1NeWQwIhAJah3BX5Ityi2UOVt0EUSncRVvijGHAyYx7tklAMXrOX","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9oUyWqdSf+KwXPiyZbDydlwEvhDPkFTez1ifOVWDrFmegje5B5OWIOy0cUe/rnEjPlw2CFvqg9mZ4FzXfwPnnA\\u003d\\u003d\",\"keyExpiration\":\"1746723557000\"}","signatures":["MEYCIQCWXdn/O2GqykZKD1HmwVIguq58CrgeZHsauS7oy+9yjQIhAPvyYX5tTwGQ9fqKAbXZO8D6GdAtTmTW1p+990iI/tpU"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"Y9Fol3vRLQBRny6obsYZk7d0MqxPPRpl9LAqjNbWmfBmZDCdl3XeMgbfl+rAUo99q5VVh1fBKaCDz0zeS04piSTfZUbYWcfyvDinQWLSUTGGfexFU6J0lm9haF9YzVJcgQKGdWOHEgtZNcoEMxmjDPBERrhGecOIvPeI726XFRVeq0A/rtSohakmIVi3z4vVIK/YvQGJAD3TQpEFAXIpVQyAvG27bekZf/3brqDw5nX4fKmj7CWt7/7xT7qceA2vdtzouvX68wKnsm8QxjbxnYYGfTPj7m0TiJI9WT3VCjmSX8W8LIUYVapvDNDLRmM4fRqpmAWbTz5mA+OFos2b3AJaNCBx5jROOy2dIanu9Np3iZwtNWXw6sjssb4Ttf+EoVLUCUcuz0dh54qOzPAWH3+IPYOuznLewjzHAYaWA+BXsEtR44xSLEsxd5IrOXaYCUB+r7V3VSX1NsRrK8KJ4toos46rZB/7pfwX+jlZ++yiklrKI80tXdGhrhUoUJVWWLy+c+cpd4x9p1Il8OwXDC2t6ey0y16CUwlmP9JmYGjkKyP6OjT2oSNT9n5cZZ2mF5OApIv1T0QKDRh2urhDwm5yypGXQizqE3blgFTziwEZbz9S9ktpjeFLkQO1xx8cdYGZBkRT2FQm\",\"ephemeralPublicKey\":\"BK1uDITp/+ecaZF6jBgBmXa5QDA5QvuE7UVgL4D21434fh140AzjtMSBAvBtTfsGkXjYZexhiAqNkeyYjyjHJ48\\u003d\",\"tag\":\"Re7anwUGWmYh4LEJErDBTiIncxrSMzrbePDotBtPHos\\u003d\"}"}`
const googleRegistrationErrorPayload2 = `{"signature":"MEUCIGhir7Q0DSa9GKCshLx4gOxfR1WuVwcsuabkLpZfRrPLAiEAzVS7/fb1MymeGTS2I9dn8mnGbOlAXRL8xWAfAKPtU1E\u003d","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMG2yAna3IBvkLpoDmgNY8U5mv6aMqw/IUDvtu0PyLWWXOzIWsEL2KTSz0VW+U5ahlVudigIwSAUtXGejaIS8Bw\\u003d\\u003d\",\"keyExpiration\":\"1746722864000\"}","signatures":["MEUCIHct418B63GlC85M44N7gabLTRdFGYhj5L91WAOWozwrAiEA76KlDaAfxB68eVDSt5h47EhPl3lF7IBIiiGvfQUt2Co\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"07IrkEp7YTCG64KQrqBi9kBGfRdmVeFAZNXQWXN6fTK5Z8QnGdDq2dGTQev5syHxlfEx+frR6Et9flFKrO/Q4P1TuDRlYjq/kundRpJLE00kqbPeguH4XAroAx/1xB9trEwDzqoBbCE1pMGmpWvSCA5ZIVh4P64Nek/MwGnfdQpY58xoCdfz/+WvOpWC2JwM5JVXiW6XVTKfuoWhHL3ts+DBpWB5KkAfJi1ipDMgBQ50/HPTMX84G5Ot9BynfWshGNhHYVMnPeB9t/CZbM1qwOaUsCHLZbdu6+F19TVGdgs1i/PEzvLCHocTdUvoESrJlkEo1hGI0krljTZYGswrddsfFhrsjmpgnD2gFzAVU/OhLTib7ZlXfPtGR+epZSl22yoNUYmLxqle8XGHOm21WYlKrHuZ6YTGkWeisXgKcNwsoh+f5qTD+uO/DGSh2PYnuf4wCNFuS9gZ2ERomMex8KGsZwwJCMbjafvhU5yvAQt0DJGDjys2nKq5BrUILm5J8bPq2ml0XYsCmcC5W/zkxsvr8+2nZKWWfj3zgip2M5GfW84\\u003d\",\"ephemeralPublicKey\":\"BHheZelXIKyKOhjG1l7zoOLpWhEQz1W6TFtEausH7zjWjBu36b6vCCW5atuEkrm/ZaH7+KMK628uJY36tHwZkps\\u003d\",\"tag\":\"TcJloufBQ+ipb2FtG/ELv8FEFuyZgXhtHqZmKacO+8E\\u003d\"}"}`
const googleRegistrationErrorPayload3 = `{"signature":"MEUCIEPZnn/iBgNKEbdnhlChK0VhXoVaUxKBIxUC+85D3xcTAiEA3R6n0ojHXgUoqnB+JLhN7PFIWkE1bhME61munX1R/Ho\u003d","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkb0VPMl6QfvYbd2Ijjro+9g+Th5/EG1S4k4sdzJjZDDs4SJkoXnxHGsr9dwwYfRHZNeMp7iohyOG0YrtaYdgwg\\u003d\\u003d\",\"keyExpiration\":\"1746724086000\"}","signatures":["MEYCIQCBDlJRx3bYHZDGZjaYjBOImbhIGl5R319NCbj3/kJEkwIhAMx/iQUigJh5n4h0NQ8j4hLKkv3RyqsN/JibQmu487Xc"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"wOD66mYxijoWS+9ZE7gtTIerUNL/mJHlJ5+Qvxc3HMMYWaMRueBG7HfdTb6hhG0clSVQJjktgW00rTRWSOM6Rc81lb6h9gwaxRsfxX9vAjBKg31NUu3G9CDfJYKE+YgAGK6lsWtk10Vm274zjuSO5oAN55yTR38qYVAiKMu6V5KEUK0C1aoj5Gxwyw0j2CtCcPmIc0TxrS796Ukp7/khBqGVYKf1+yyqNTt+St2K8BtHHZO/sCViUo+A7hz7Deld0sMvSYT+nNmGa+bp3082xDbHOFwxI82/YjT7rkz6DGQ84yQnCBhECmPED6cVp/GTbbaFQPZJgrlhOJvNHMSG0mwS02qgb1CeqOGr0C6ouczVTJs3JI4EBYb8kfLk/4lZTRXXZVxAUbWGMfJL7jMOq8DEBVjRMrGYWyo7JvX2pLmD3yUUkVcFD6hhB8moKOmXeiUTnKqO0FTh6tTbaYQaxVxCS2Z9NDpT2g4RKmW5fetXRfeCEZq284cezfN77rJJn9aPoDOrecZnRURhyXLDx4VAcydIouaRUMioG0zoQD0r3gMBe8zy//4OiXS0nAdTlDJRmWKAeljEBXCvHj5OU5YYRKXZdU2jPYLPb4YPMemV3BXWPEpK9A9Jiw4zbl4e/HJNTdIPuWPi\",\"ephemeralPublicKey\":\"BHACHKOKjTc0pJaDGA/YQxePHOo+Bfa4zw6vC2+julg/MD5lxA/Eu8jz3XphxX9PpbuVQ/YQ0qaKO6NUAduBNrg\\u003d\",\"tag\":\"yBASFol+/I/epyZ/bdT+3ei7TdOsWzX0NiCMmcQPBM4\\u003d\"}"}`
const googleRegistrationErrorPayload4 = `{"signature":"MEYCIQCoRbSGOko/841mWTtQvxF19rVQOF7UzwNpx5ogyAsiJAIhAP3EfDokdcDSudCNSU5ytvyu9AM+gEMZPA2YmiQ6HfFm","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkb0VPMl6QfvYbd2Ijjro+9g+Th5/EG1S4k4sdzJjZDDs4SJkoXnxHGsr9dwwYfRHZNeMp7iohyOG0YrtaYdgwg\\u003d\\u003d\",\"keyExpiration\":\"1746724086000\"}","signatures":["MEYCIQCBDlJRx3bYHZDGZjaYjBOImbhIGl5R319NCbj3/kJEkwIhAMx/iQUigJh5n4h0NQ8j4hLKkv3RyqsN/JibQmu487Xc"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"JS7ITSqwQ05t5keP1F5fffKG7B+j+lHu5E9YpF0RRXcowreMKJ2L5zw6ZPgsfd2Pu6+Zfh6vCUZDi/JfcANAY4+bxpgHcWYb4gklVNhjoOypV1mRKLY4IPkD9tzWSfN/34IOgiQf7MToNbysDa7cavQA0OMW9OzGw7EFJwELXpCGqrVo+dDzXaKNCNEiVFvTeBs7YEE572PkGDJgQGRrAGNy7ovq4unFvDVhJSsRl9ejKeQaPOapYvR2yv/2rnk2asrpOxvWc4RIUG/P3hcqhF4WEZSN9bGNwVtcG6iPhRiA+kvfdhIl6N74HCKs4r3PWCFp5NqwMxokLkB65j+c5BmjItTkOq6LQlrLojSrydEV1r5gQX7Gv0QvQ0This5TDmgCB0SCq69rzwSoeYqcXZnwCxAscCNUaSmgkj/UzBl3Bk13bxgd9L9u3leTtG66RliC8LB8EznTaVtZ5NEKhd21MnR1NsdaNLwc+qwbfrFACcOWdk4T7ffpCbA8c24+Sh8FQRVLnd00TSs50mp5KHidosD40Xr/bbtWC8wtqEpQYT5d18d73ojCa4UxXsoOPfunkUIl88gtuYB1rn3jQyhvDwYbyTNW1LmEQwR6cIOfLFJYXEREHH+ksxMOoXRMIriV4JC76wI2\",\"ephemeralPublicKey\":\"BPcZrDdMlNAObiG/RfjrPFgJkINso+ofI6vZM5w27cXG4aPjbroAJsVp/b+L54t2CNEI6Sz+rgIZFZ52U6mbPrE\\u003d\",\"tag\":\"0fV27JXXoGa72w+k/zhOJgYEJJToCil9XCJhT0f2Z7U\\u003d\"}"}`
const googleRegistrationErrorPayload5 = `{"signature":"MEUCIQC/ixnvd9Bj0Oe73qttuow91hcB1opVHq/dLoDiOCmUJAIgSNIJD/X0qpJfDUVfj8qwc9klLFReDqbsgviyW5izX60\u003d","intermediateSigningKey":{"signedKey":"{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPIJj1HScqjpfX+zV8Mo2/VdzgMVUWML/mFRGKDdfyudUoHaeFBLGlrd8wOYzxHz8aqyD++ytlZHyn4lUojae4Q\\u003d\\u003d\",\"keyExpiration\":\"1746724177000\"}","signatures":["MEUCIQC3ViDg8SBcrBb2x/16hK8loDXINFFYUUf4hxXzG+S+NAIgC18RdNMSADPGuutnh+sI7JK7h309EVU64wv7kEGZeUY\u003d"]},"protocolVersion":"ECv2","signedMessage":"{\"encryptedMessage\":\"j4yG4TshcnnN8erN+RaYuKNKApYjSByxAPYvB8+kKTJCqjre4Q7Jbck21JAwbKQOeSQuri/qRH4Dr9DgKxL/gZVCIwtDtWc5khIZYQM1GCP+WZzSwhXL+MMl1CZbUod/ZRyJki5+S0gMShf8EsOXUBaG7zdsubNWAY2j5+GwNxGq79TaNn8Glo62KZ+zAtoSWluXlXWSLScrflTQpbF9AOdgF/MJn9Mw8T2wtgLsLf2QRQOTbOuBsFoALH9H4AfDg8BC2n+Ek6mmAI1GOqK9/kILAw0zOv2V0ROONgD3hFWNPEtzUWYzO9R2bcGVL0o4rXG+Z/fSgv2ilWSTI8MkchpB81mZgRsRlQGPruRrQ3ghYSmMmaLNibXDluaCFzOGzJKv0fGAJ+v9eRLAyE12Rc6Tcz0VioLPuyz0T30wCSet+1o+h/UV9xadtZnVlxWnhzZZGBxI6fiLGjD/8bJP+S3UznZFTgEfiETNbtGqXHcnlcl9juDY1vDNe6eGwJ/qyVqeDiyKCZMh8xlwzghIYN19y5gTk7VoJLKd9sIeputAk1MZ7t25tJ3ak1bcAJadSGprBlBCQMOi8697lEGICK88EuHrvlB5XmGZLuuOGCXQXYqkcRADkiNtNMJCeKTBiKj0dxqusKvN13qWWA\\u003d\\u003d\",\"ephemeralPublicKey\":\"BBaylolOwKI8jsIOwzfB/gubBVIYtEVyGtrDBpVrVEMczxsMry8hg8MZLcR2KsFCh8I4HKZU05l+jlmIEJNl6/w\\u003d\",\"tag\":\"Tr02zSnTQ1WnWeG3Yc/FUanOz9G9FeauIgcZn5zbWVE\\u003d\"}"}`

func TestGoogleRegistrationErrorPayload1(t *testing.T) {
	t.Run("ErrorPayload1", func(t *testing.T) {
		if os.Getenv("TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE") != "true" {
			t.Skip("Skipping test because TEST_NEW_KEYS_AND_PAYLOADS_FROM_GOOGLE is not set")
		}

		output, err := decryptToken(googleRegistrationErrorPayload1)
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

		output, err := decryptToken(googleRegistrationErrorPayload2)
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

		output, err := decryptToken(googleRegistrationErrorPayload3)
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

		output, err := decryptToken(googleRegistrationErrorPayload4)
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

		output, err := decryptToken(googleRegistrationErrorPayload5)
		if err != nil {
			t.Errorf("failed to decrypt: %v", err)
		}
		prettyPrintDecryptedToken(output)
	})
}

func decryptToken(jsonPayload string) (types.Decrypted, error) {
	var input types.Token
	var output types.Decrypted

	// Unmarshal the JSON payload
	err := json.Unmarshal([]byte(jsonPayload), &input)
	if err != nil {
		return types.Decrypted{}, fmt.Errorf("failed to unmarshal test payload: %v", err)
	}

	// Key registered with Google
	privateKeyBytes, err := os.ReadFile(googleRegErrorTestPrivateKey)
	if err != nil {
		return types.Decrypted{}, fmt.Errorf("Error reading test private key: %v\n", err)
	}

	// Create a new GooglePayDecryptor with the test private key
	decryptor, err := decrypt.NewWithRootKeysFromGoogle(googleRegErrorTestEnvironment, "gateway:"+googleRegErrorTestGatewayID, string(privateKeyBytes))
	if err != nil {
		return types.Decrypted{}, fmt.Errorf("failed to create decryptor: %v", err)
	}

	// Decrypt the test payload
	output, err = decryptor.DecryptWithMerchantId(input, googleRegErrorTestMerchantID) // input is payload in types.Token
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
