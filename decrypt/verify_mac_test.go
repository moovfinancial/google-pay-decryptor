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
	"testing"

	"github.com/moovfinancial/google-pay-decryptor/decrypt"
)

func TestVerifyMessageHmac(t *testing.T) {
	table := []struct {
		name, tag, encryptedMessage string
		mac                         []byte
		expected                    error
	}{
		{
			name:             "Normal case",
			mac:              []byte{254, 126, 190, 74, 145, 45, 85, 141, 82, 231, 171, 227, 17, 124, 132, 162, 207, 84, 15, 123, 218, 193, 153, 156, 36, 94, 103, 61, 124, 4, 15, 138},
			tag:              "3Q7cmZwn/hk2xVZ+sSbHYa0bOAQQSWFr0ehpPf94wlg=",
			encryptedMessage: "5RB8tx7IeHATogErh29B44USzvUAeDdjlDspWP9uQAzH1qiefn2p/WTFjk429sQvUT7oLts+bTAqVXihEnV69zWyNqW0a0oFeIjCC5YqdBMqOsHdo1dWYuDWXJOQNgOnUghFRJSLGnb4KRvQMiF06GRGqxHgJoS+IiaxXX98Zcsa/ljBtvkqQ3Pug91E9+FJmzWDgrUDf3mDXAac4cZf/hW1mUt+XhWAI1Q0etwpW7DwdeDyt5GFOXqBhsF6a6qVtwNIxltd0NaGz2Yj+NhrinCb0aiyXELn9Hw6vkRssRPXUqygbkBDffU+XP9LjbBweS1usODcSb8IJ/uP1QO3tYlj9Qd44OMxuXaEjM2B2RrNZKuNd7uUByZ1B7OyL3NEvwY5ebMYkDJx51JfPATIzcGzU9/7rrR3mny9pZvJmEwY3y7rO7jDrcZYBQ3452GRlDTC67gRZopx4OJlj0pWX7aaO7ZtRowqkynANL0mdrz4wZihR5AFPOiVFKPh3iWv2EzszAceY4xqqoawmqyGFS4L24TiQ0WX",
			expected:         nil,
		},
		{
			name:             "Invalid tag",
			mac:              []byte{254, 126, 190, 74, 145, 45, 85, 141, 82, 231, 171, 227, 17, 124, 132, 162, 207, 84, 15, 123, 218, 193, 153, 156, 36, 94, 103, 61, 124, 4, 15, 138},
			tag:              "invalid_tag",
			encryptedMessage: "5RB8tx7IeHATogErh29B44USzvUAeDdjlDspWP9uQAzH1qiefn2p/WTFjk429sQvUT7oLts+bTAqVXihEnV69zWyNqW0a0oFeIjCC5YqdBMqOsHdo1dWYuDWXJOQNgOnUghFRJSLGnb4KRvQMiF06GRGqxHgJoS+IiaxXX98Zcsa/ljBtvkqQ3Pug91E9+FJmzWDgrUDf3mDXAac4cZf/hW1mUt+XhWAI1Q0etwpW7DwdeDyt5GFOXqBhsF6a6qVtwNIxltd0NaGz2Yj+NhrinCb0aiyXELn9Hw6vkRssRPXUqygbkBDffU+XP9LjbBweS1usODcSb8IJ/uP1QO3tYlj9Qd44OMxuXaEjM2B2RrNZKuNd7uUByZ1B7OyL3NEvwY5ebMYkDJx51JfPATIzcGzU9/7rrR3mny9pZvJmEwY3y7rO7jDrcZYBQ3452GRlDTC67gRZopx4OJlj0pWX7aaO7ZtRowqkynANL0mdrz4wZihR5AFPOiVFKPh3iWv2EzszAceY4xqqoawmqyGFS4L24TiQ0WX",
			expected:         decrypt.ErrVerifyMac,
		},
		{
			name:             "Tag will not match Computed MAC",
			mac:              []byte{254, 126, 190, 74, 145, 45, 85, 141, 82, 231, 171, 227, 17, 124, 132, 162, 207, 84, 15, 123, 218, 193, 153, 156, 36, 94, 103, 61, 124, 4, 15, 138},
			tag:              "3Q7cmZwn/hk2xVZ+sSbHYa0bOAQQSWFr0ehpPf94wwg=",
			encryptedMessage: "5RB8tx7IeHATogErh29B44USzvUAeDdjlDspWP9uQAzH1qiefn2p/WTFjk429sQvUT7oLts+bTAqVXihEnV69zWyNqW0a0oFeIjCC5YqdBMqOsHdo1dWYuDWXJOQNgOnUghFRJSLGnb4KRvQMiF06GRGqxHgJoS+IiaxXX98Zcsa/ljBtvkqQ3Pug91E9+FJmzWDgrUDf3mDXAac4cZf/hW1mUt+XhWAI1Q0etwpW7DwdeDyt5GFOXqBhsF6a6qVtwNIxltd0NaGz2Yj+NhrinCb0aiyXELn9Hw6vkRssRPXUqygbkBDffU+XP9LjbBweS1usODcSb8IJ/uP1QO3tYlj9Qd44OMxuXaEjM2B2RrNZKuNd7uUByZ1B7OyL3NEvwY5ebMYkDJx51JfPATIzcGzU9/7rrR3mny9pZvJmEwY3y7rO7jDrcZYBQ3452GRlDTC67gRZopx4OJlj0pWX7aaO7ZtRowqkynANL0mdrz4wZihR5AFPOiVFKPh3iWv2EzszAceY4xqqoawmqyGFS4L24TiQ0WX",
			expected:         decrypt.ErrVerifyMac,
		},
	}

	for _, tb := range table {
		t.Run(tb.name, func(t *testing.T) {
			err := decrypt.VerifyMessageHmac(tb.mac, tb.tag, tb.encryptedMessage)
			if tb.expected != nil {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Error(err)
			}
		})
	}
}
