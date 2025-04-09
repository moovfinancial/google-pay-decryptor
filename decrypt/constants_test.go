// Copyright (c) 2022 Rakhat

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package decrypt_test

import (
	"fmt"
	"time"

	"github.com/google/tink/go/subtle/random"
	"github.com/moovfinancial/google-pay-decryptor/decrypt/types"
)

var KeyExp = fmt.Sprintf("%d", (time.Now().Unix()+86400)*1000)
var RandomBytes = random.GetRandomBytes(64)
var TestRootKeys = `{"keys":[{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIsFro6K+IUxRr4yFTOTO+kFCCEvHo7B9IOMLxah6c977oFzX\/beObH4a9OfosMHmft3JJZ6B3xpjIb8kduK4\/A==","protocolVersion":"ECv1"},{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnJ7Yo1sX9b4kr4Aa5uq58JRQfzD8bIJXw7WXaap\/hVE+PnFxvjx4nVxt79SdRuUVeu++HZD0cGAv4IOznc96w==","protocolVersion":"ECv2","keyExpiration":"2154841200000"},{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnJ7Yo1sX9b4kr4Aa5uq58JRQfzD8bIJXw7WXaap\/hVE+PnFxvjx4nVxt79SdRuUVeu++HZD0cGAv4IOznc96w==","protocolVersion":"ECv2SigningOnly","keyExpiration":"2154841200000"}]}`
var TestToken = types.Token{
	ProtocolVersion: "ECv2",
	Signature:       "MEQCICgayPPjbzuvzFN/2/7gPxIYHIROaouYd0aegk5xuVmRAiB7X5ksxyhmGi1tx+nnrlAPnlqpX0fy/vlFfexxd1s1tA==",
	IntermediateSigningKey: types.IntermediateSigningKey{
		SignedKey:  `{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8vPzuDtvMbegr5qCTN6IRYaigyr6A+heGx1xdEoWHQPNnyIIHXjrsua/6FPjbLLldLM3646GaO+CnlkkGUfeLQ\u003d\u003d","keyExpiration":"1645569858115"}`,
		Signatures: []string{"MEYCIQDJvRet0TswS+0+QGdLE+qhDC6PtYDk+lvws8PzPCfygQIhAOeIkYEzK+lhVbrhYDdlx1NVZApOM4j5tONm/dDJjhQX"},
	},
	SignedMessage: "{\"encryptedMessage\":\"5RB8tx7IeHATogErh29B44USzvUAeDdjlDspWP9uQAzH1qiefn2p/WTFjk429sQvUT7oLts+bTAqVXihEnV69zWyNqW0a0oFeIjCC5YqdBMqOsHdo1dWYuDWXJOQNgOnUghFRJSLGnb4KRvQMiF06GRGqxHgJoS+IiaxXX98Zcsa/ljBtvkqQ3Pug91E9+FJmzWDgrUDf3mDXAac4cZf/hW1mUt+XhWAI1Q0etwpW7DwdeDyt5GFOXqBhsF6a6qVtwNIxltd0NaGz2Yj+NhrinCb0aiyXELn9Hw6vkRssRPXUqygbkBDffU+XP9LjbBweS1usODcSb8IJ/uP1QO3tYlj9Qd44OMxuXaEjM2B2RrNZKuNd7uUByZ1B7OyL3NEvwY5ebMYkDJx51JfPATIzcGzU9/7rrR3mny9pZvJmEwY3y7rO7jDrcZYBQ3452GRlDTC67gRZopx4OJlj0pWX7aaO7ZtRowqkynANL0mdrz4wZihR5AFPOiVFKPh3iWv2EzszAceY4xqqoawmqyGFS4L24TiQ0WX\",\"ephemeralPublicKey\":\"BIG60+zjF3baoQRqNiZ7ZRQFzKnzITgUu9e4sS3MJ0JSxRk4MTUj9Z+rMeJQogXeSUfSlRVTfDELv1X9got3yeg\\u003d\",\"tag\":\"3Q7cmZwn/hk2xVZ+sSbHYa0bOAQQSWFr0ehpPf94wlg\\u003d\"}",
}
var TestDecrypted = types.Decrypted{
	MessageExpiration: "1645501069135",
	MessageId:         "AH2EjtdXWjOxGkyAxyLlyakvWxUcS638Tn37UKPUw2fvpyVOmAZwE0Rs_NzCllF3iluLTIRQesQ8_q8P0KUI87hlBIsi2pkscVlnwKtmUEzIe3l6MRJePlr-IfgWi8wqMh35Rs3MG8H2",
	PaymentMethod:     "CARD",
	PaymentMethodDetails: types.PaymentMethodDetails{
		AuthMethod:      "PAN_ONLY",
		ExpirationMonth: 12,
		ExpirationYear:  2027,
		Pan:             "4111111111111111",
		AssuranceDetails: &types.AssuranceDetails{
			AccountVerified:         true,
			CardHolderAuthenticated: false,
		},
	},
}
