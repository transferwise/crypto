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

// iso9797M2Marker is the single 0x80 byte that ISO/IEC 9797-1 padding method 2
// appends before the zero filler. At bit level the standard appends one 1 bit
// followed by 0 bits; on byte aligned data that is 0x80 then 0x00.
const iso9797M2Marker = 0x80

// padISO9797M2 appends ISO/IEC 9797-1 padding method 2 to plainBytes so that
// its length becomes a multiple of blockSize. The padding is a single 0x80 byte
// followed by as many 0x00 bytes as the block boundary requires.
//
// The same construction appears in ISO/IEC 7816-4 and is what BouncyCastle
// calls ISO7816-4Padding. Card personalisation interfaces often label it
// "ISO2", including the aes-256-cbc-iso2 algorithm name used by the G+D CII
// data provider interface. It is NOT ISO 10126-2, which pads with random bytes
// and stores the padding length in the final byte, and it is NOT PKCS#7.
//
// At least one byte is always added, so input that is already block aligned
// gains a whole extra block. That is what makes the padding removable without
// ambiguity, including when the message itself ends in 0x80 or 0x00. An empty
// input yields a single full block.
//
// The input slice is never modified; a new slice is always returned.
func padISO9797M2(plainBytes []byte, blockSize int) []byte {
	padLen := blockSize - len(plainBytes)%blockSize

	padded := make([]byte, 0, len(plainBytes)+padLen)
	padded = append(padded, plainBytes...)
	padded = append(padded, iso9797M2Marker)
	padded = append(padded, make([]byte, padLen-1)...)
	return padded
}

// unpadISO9797M2 removes ISO/IEC 9797-1 padding method 2 from paddedBytes by
// scanning back from the end over the zero filler to the 0x80 marker. It
// returns an error when the padding is not well formed.
//
// A padding error is not evidence of tampering alone, and callers must not
// treat it as an integrity check: CBC is unauthenticated, so a modified
// ciphertext can just as easily decrypt to well formed padding. Reporting
// padding failures to an untrusted caller also exposes a padding oracle.
//
// The input slice is never modified; the returned slice is a copy.
func unpadISO9797M2(paddedBytes []byte, blockSize int) ([]byte, error) {
	if len(paddedBytes) == 0 {
		return nil, fmt.Errorf("padded input is empty")
	}
	if len(paddedBytes)%blockSize != 0 {
		return nil, fmt.Errorf("padded input length %d is not a multiplier of block size %d", len(paddedBytes), blockSize)
	}

	markerIndex := len(paddedBytes) - 1
	for markerIndex >= 0 && paddedBytes[markerIndex] == 0x00 {
		markerIndex--
	}
	if markerIndex < 0 || paddedBytes[markerIndex] != iso9797M2Marker {
		return nil, fmt.Errorf("invalid padding")
	}

	// A well formed marker sits within the final block, because the padding is
	// between 1 and blockSize bytes long. Anything longer means the trailing
	// zeroes are message content and the padding is absent or corrupt.
	if len(paddedBytes)-markerIndex > blockSize {
		return nil, fmt.Errorf("invalid padding")
	}

	plainBytes := make([]byte, markerIndex)
	copy(plainBytes, paddedBytes)
	return plainBytes, nil
}
