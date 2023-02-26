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
	"bytes"
	"testing"

	"github.com/m1crogravity/google-pay-decryptor/decrypt"
)

func TestDecode(t *testing.T) {
	tables := []struct {
		name, context, ciphertext string
		key, plaintext            []byte
	}{
		{
			name:       "Empty plaintext",
			key:        []byte{196, 231, 38, 149, 234, 51, 142, 186, 230, 214, 96, 243, 229, 153, 103, 74, 117, 241, 237, 135, 91, 170, 216, 167, 235, 154, 180, 28, 125, 48, 82, 44},
			ciphertext: "",
			context:    "Google",
			plaintext:  nil,
		},
		{
			name:       "Small plaintext",
			key:        []byte{196, 231, 38, 149, 234, 51, 142, 186, 230, 214, 96, 243, 229, 153, 103, 74, 117, 241, 237, 135, 91, 170, 216, 167, 235, 154, 180, 28, 125, 48, 82, 44},
			ciphertext: "614756736247383d",
			context:    "Google",
			plaintext:  []byte{254, 66, 119, 211, 159, 233, 74, 143, 23, 4, 196, 53},
		},
		{
			name:       "Normal case",
			key:        []byte{196, 231, 38, 149, 234, 51, 142, 186, 230, 214, 96, 243, 229, 153, 103, 74, 117, 241, 237, 135, 91, 170, 216, 167, 235, 154, 180, 28, 125, 48, 82, 44},
			ciphertext: "7b226d65737361676545787069726174696f6e223a2231363434383331333036303037222c226d6573736167654964223a22414832456a74635157674c4f31364b415a702d316f6e5f353954386a58736f356135305064426f555f39664e737a396e763533376c6c52674e70345a4e4a5536754177714d7845646e50625a6c69753656666568665150366d514534326448544b4b5f6f6f765a74316a30796c6a7a424778424743326f7333655f33654b6f503463745a4b65694139767637222c227061796d656e744d6574686f64223a2243415244222c227061796d656e744d6574686f6444657461696c73223a7b2265787069726174696f6e59656172223a323032372c2265787069726174696f6e4d6f6e7468223a31322c2270616e223a2234313131313131313131313131313131222c22617574684d6574686f64223a2250414e5f4f4e4c59227d7d",
			context:    "Google",
			plaintext:  []byte{248, 161, 250, 221, 239, 167, 78, 159, 219, 48, 87, 83, 185, 1, 96, 189, 53, 170, 250, 175, 106, 87, 165, 36, 37, 195, 236, 101, 59, 21, 176, 186, 157, 81, 171, 210, 115, 144, 212, 221, 249, 163, 122, 90, 249, 43, 247, 210, 248, 131, 50, 5, 7, 106, 214, 10, 78, 182, 207, 128, 59, 106, 150, 79, 31, 206, 62, 227, 80, 108, 37, 203, 61, 25, 93, 148, 89, 24, 255, 252, 15, 68, 23, 46, 216, 147, 169, 209, 222, 198, 116, 22, 161, 96, 75, 37, 205, 7, 20, 160, 151, 41, 10, 53, 222, 229, 96, 32, 8, 172, 143, 238, 80, 106, 118, 45, 252, 244, 253, 129, 136, 230, 104, 47, 231, 31, 4, 122, 116, 250, 39, 160, 254, 82, 140, 10, 74, 96, 126, 188, 230, 134, 168, 182, 243, 241, 204, 70, 56, 104, 206, 28, 245, 73, 99, 133, 58, 138, 157, 179, 90, 42, 64, 55, 182, 250, 167, 183, 162, 209, 23, 228, 188, 51, 214, 250, 81, 51, 156, 28, 172, 8, 170, 118, 201, 218, 97, 71, 122, 189, 166, 214, 18, 156, 87, 78, 109, 149, 81, 197, 102, 223, 140, 140, 146, 60, 245, 197, 33, 183, 172, 198, 122, 24, 125, 86, 175, 35, 148, 25, 46, 92, 183, 34, 51, 17, 209, 249, 60, 214, 206, 156, 134, 93, 152, 232, 243, 190, 159, 159, 39, 163, 134, 45, 22, 136, 104, 9, 165, 74, 138, 222, 110, 173, 209, 107, 188, 60, 222, 109, 122, 203, 137, 237, 209, 89, 150, 53, 216, 114, 112, 66, 245, 49, 187, 10, 234, 90, 227, 218, 55, 122, 216, 69, 157, 228, 217, 178, 251, 203, 238, 180, 253, 113, 91, 154, 153, 11, 97, 241, 155, 192, 169, 139, 80, 123, 42, 72, 127, 148, 158, 107, 40, 229, 62, 54, 127, 102, 53, 116, 136, 120, 187, 146, 118, 202, 243, 28, 239, 132, 179, 223, 95, 19, 117, 130, 2, 109, 50, 149, 12, 177, 153, 86, 67, 107, 39, 27, 186, 11, 236, 47, 67, 174, 196, 216, 22, 192, 80, 54, 189, 137, 25, 75, 158, 77, 72, 222, 219, 93, 136, 113, 29, 231, 232, 22, 173, 235, 36, 183, 103, 69, 143, 240, 43, 189, 84, 153, 113, 57, 203, 40, 205, 143, 129, 111, 219, 67, 6, 149, 85, 122, 224, 29, 21, 33, 195, 184, 242, 123, 170, 222, 222, 161, 217, 102, 8, 135, 188, 16, 168, 107, 141, 84, 232, 226, 24, 79, 31, 246, 215, 155, 186, 230, 89, 244, 194, 29, 85, 23, 50, 133, 225, 48, 17, 216, 106, 54, 29, 137, 204, 238, 158, 185, 229, 202, 127, 69, 230, 125, 228, 60, 229, 165, 187, 90, 46, 116, 90, 234, 97, 157, 210, 248, 98, 184, 29, 214, 224, 153, 91, 183, 123, 176, 163, 206, 68, 136, 83, 156, 226, 141, 103, 10, 221, 94, 133, 42},
		},
	}
	for _, tb := range tables {
		t.Run(tb.name, func(t *testing.T) {
			decoded, err := decrypt.Decode(tb.key, tb.ciphertext)
			if err != nil {
				t.Fatalf("error decoding cipertext: %s", err)
			}

			decodedBytes := []byte(decoded)
			plaintextBytes := []byte(tb.plaintext)
			if !bytes.Equal(plaintextBytes, decodedBytes) {
				t.Errorf("decryption failed, decoded text does not match plaintext")
			}
		})
	}
}
