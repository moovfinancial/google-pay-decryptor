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

package types

import (
	"errors"
)

var (
	ErrRootKeys           = errors.New("an error is occured while filtering root keys")
	ErrParseJson          = errors.New("cannot find ECv2 in parsed jsonfile")
	ErrProtocolV          = errors.New("only ECv2-signed tokens are supported")
	ErrValidateTime       = errors.New("failed checking expiration date")
	ErrPrivateKey         = errors.New("failed loading private key")
	ErrPublicKey          = errors.New("failed loading public key")
	ErrTyping             = errors.New("error while typing")
	ErrVerifySignature    = errors.New("could not verify intermediate signing key signature")
	ErrLengthDoesnotMatch = errors.New("length of key does not match")
	ErrLoadingKeys        = errors.New("please call Init() function to initialize keys")
)
