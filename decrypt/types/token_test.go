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

package types_test

import (
	"testing"

	"github.com/moovfinancial/google-pay-decryptor/decrypt/types"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalSignedMessage(t *testing.T) {
	table := []struct {
		name, signedMessage   string
		expectedSignedMessage types.SignedMessage
	}{
		{
			name:          "Normal Case",
			signedMessage: "{\"encryptedMessage\":\"5RB8tx7IeHATogErh29B44USzvUAeDdjlDspWP9uQAzH1qiefn2p/WTFjk429sQvUT7oLts+bTAqVXihEnV69zWyNqW0a0oFeIjCC5YqdBMqOsHdo1dWYuDWXJOQNgOnUghFRJSLGnb4KRvQMiF06GRGqxHgJoS+IiaxXX98Zcsa/ljBtvkqQ3Pug91E9+FJmzWDgrUDf3mDXAac4cZf/hW1mUt+XhWAI1Q0etwpW7DwdeDyt5GFOXqBhsF6a6qVtwNIxltd0NaGz2Yj+NhrinCb0aiyXELn9Hw6vkRssRPXUqygbkBDffU+XP9LjbBweS1usODcSb8IJ/uP1QO3tYlj9Qd44OMxuXaEjM2B2RrNZKuNd7uUByZ1B7OyL3NEvwY5ebMYkDJx51JfPATIzcGzU9/7rrR3mny9pZvJmEwY3y7rO7jDrcZYBQ3452GRlDTC67gRZopx4OJlj0pWX7aaO7ZtRowqkynANL0mdrz4wZihR5AFPOiVFKPh3iWv2EzszAceY4xqqoawmqyGFS4L24TiQ0WX\",\"ephemeralPublicKey\":\"BIG60+zjF3baoQRqNiZ7ZRQFzKnzITgUu9e4sS3MJ0JSxRk4MTUj9Z+rMeJQogXeSUfSlRVTfDELv1X9got3yeg\\u003d\",\"tag\":\"3Q7cmZwn/hk2xVZ+sSbHYa0bOAQQSWFr0ehpPf94wlg\\u003d\"}",
			expectedSignedMessage: types.SignedMessage{
				EncryptedMessage:   "5RB8tx7IeHATogErh29B44USzvUAeDdjlDspWP9uQAzH1qiefn2p/WTFjk429sQvUT7oLts+bTAqVXihEnV69zWyNqW0a0oFeIjCC5YqdBMqOsHdo1dWYuDWXJOQNgOnUghFRJSLGnb4KRvQMiF06GRGqxHgJoS+IiaxXX98Zcsa/ljBtvkqQ3Pug91E9+FJmzWDgrUDf3mDXAac4cZf/hW1mUt+XhWAI1Q0etwpW7DwdeDyt5GFOXqBhsF6a6qVtwNIxltd0NaGz2Yj+NhrinCb0aiyXELn9Hw6vkRssRPXUqygbkBDffU+XP9LjbBweS1usODcSb8IJ/uP1QO3tYlj9Qd44OMxuXaEjM2B2RrNZKuNd7uUByZ1B7OyL3NEvwY5ebMYkDJx51JfPATIzcGzU9/7rrR3mny9pZvJmEwY3y7rO7jDrcZYBQ3452GRlDTC67gRZopx4OJlj0pWX7aaO7ZtRowqkynANL0mdrz4wZihR5AFPOiVFKPh3iWv2EzszAceY4xqqoawmqyGFS4L24TiQ0WX",
				EphemeralPublicKey: "BIG60+zjF3baoQRqNiZ7ZRQFzKnzITgUu9e4sS3MJ0JSxRk4MTUj9Z+rMeJQogXeSUfSlRVTfDELv1X9got3yeg=",
				Tag:                "3Q7cmZwn/hk2xVZ+sSbHYa0bOAQQSWFr0ehpPf94wlg=",
			},
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			var token types.Token
			signedMessage, err := token.UnmarshalSignedMessage(tb.signedMessage)
			if err != nil {
				t.Error(err)
			}

			if !assert.Equal(t, tb.expectedSignedMessage, signedMessage) {
				t.Errorf("actual signed message are incorrect or does not match expected one")
			}
		})
	}
}

func TestUnmarshalSignedKey(t *testing.T) {
	table := []struct {
		name, signedKey   string
		expectedSignedKey types.SignedKey
	}{
		{
			name:      "Normal Case",
			signedKey: `{"keyValue":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8vPzuDtvMbegr5qCTN6IRYaigyr6A+heGx1xdEoWHQPNnyIIHXjrsua/6FPjbLLldLM3646GaO+CnlkkGUfeLQ\u003d\u003d","keyExpiration":"1645569858115"}`,
			expectedSignedKey: types.SignedKey{
				KeyValue:      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8vPzuDtvMbegr5qCTN6IRYaigyr6A+heGx1xdEoWHQPNnyIIHXjrsua/6FPjbLLldLM3646GaO+CnlkkGUfeLQ==",
				KeyExpiration: "1645569858115",
			},
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			var token types.Token
			signedKey, err := token.IntermediateSigningKey.UnmarshalSignedKey(tb.signedKey)
			if err != nil {
				t.Error(err)
			}

			if !assert.Equal(t, tb.expectedSignedKey, signedKey) {
				t.Errorf("actual signed message are incorrect or does not match expected one")
			}
		})
	}
}
