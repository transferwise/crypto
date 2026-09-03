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

const iso9797M2Marker = 0x80

// padISO9797M2 appends 0x80 and zeroes to the next block boundary. It always
// adds padding and returns a new slice.
func padISO9797M2(plainBytes []byte, blockSize int) []byte {
	padLen := blockSize - len(plainBytes)%blockSize

	padded := make([]byte, 0, len(plainBytes)+padLen)
	padded = append(padded, plainBytes...)
	padded = append(padded, iso9797M2Marker)
	padded = append(padded, make([]byte, padLen-1)...)
	return padded
}

// unpadISO9797M2 removes ISO/IEC 9797-1 method 2 padding. It rejects malformed
// padding and returns a new slice.
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

	// Valid padding starts within the final block.
	if len(paddedBytes)-markerIndex > blockSize {
		return nil, fmt.Errorf("invalid padding")
	}

	plainBytes := make([]byte, markerIndex)
	copy(plainBytes, paddedBytes)
	return plainBytes, nil
}
