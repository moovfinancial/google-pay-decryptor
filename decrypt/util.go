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

package decrypt

import (
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"time"
)

func Base64Decode(base64PublicKey string) ([]byte, error) {
	base64Decoded, err := base64.StdEncoding.DecodeString(base64PublicKey)
	if err != nil {
		return nil, err
	}
	return base64Decoded, nil
}

func GenerateMacKeyAndEncryptionKey(sharedSecret []byte) ([]byte, []byte, error) {
	if len(sharedSecret) != 64 {
		return nil, nil, ErrLengthDoesnotMatch
	}
	encryptionKey := sharedSecret[:32]
	macKey := sharedSecret[32:]
	return macKey, encryptionKey, nil
}

func CheckTime(exp string) bool {
	i, _ := strconv.ParseInt(exp, 10, 64)
	return time.Now().Unix()*1000 < i
}

func ConstructSignature(params ...string) []byte {
	var signed []byte
	for _, a := range params {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint16(b, uint16(len(a)))
		signed = append(signed, b...)
		signed = append(signed, []byte(a)...)
	}
	return signed
}
