/*
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at
		http://www.apache.org/licenses/LICENSE-2.0
	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package aes

import "fmt"

// pad appends PKCS#7 padding (RFC 5652 section 6.3) to plainBytes so that its
// length becomes a multiple of blockSize. Input that is already block aligned
// gains a whole extra block of padding, so the padding is always removable
// without ambiguity. An empty input therefore yields a single full block.
//
// The input slice is never modified; a new slice is always returned.
func pad(plainBytes []byte, blockSize int) []byte {
	padLen := blockSize - len(plainBytes)%blockSize

	padded := make([]byte, 0, len(plainBytes)+padLen)
	padded = append(padded, plainBytes...)
	for i := 0; i < padLen; i++ {
		padded = append(padded, byte(padLen))
	}
	return padded
}

// unpad removes PKCS#7 padding (RFC 5652 section 6.3) from paddedBytes. It
// returns an error when the padding is not well formed.
//
// A padding error is not evidence of tampering alone, and callers must not
// treat it as an integrity check: CBC is unauthenticated, so a modified
// ciphertext can just as easily decrypt to well formed padding. Reporting
// padding failures to an untrusted caller also exposes a padding oracle.
//
// The input slice is never modified; the returned slice is a copy.
func unpad(paddedBytes []byte, blockSize int) ([]byte, error) {
	if len(paddedBytes) == 0 {
		return nil, fmt.Errorf("padded input is empty")
	}
	if len(paddedBytes)%blockSize != 0 {
		return nil, fmt.Errorf("padded input length %d is not a multiplier of block size %d", len(paddedBytes), blockSize)
	}

	padLen := int(paddedBytes[len(paddedBytes)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, fmt.Errorf("invalid padding")
	}

	for _, padByte := range paddedBytes[len(paddedBytes)-padLen:] {
		if int(padByte) != padLen {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	plainBytes := make([]byte, len(paddedBytes)-padLen)
	copy(plainBytes, paddedBytes)
	return plainBytes, nil
}
