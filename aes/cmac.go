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

import "crypto/cipher"

// rb is the constant Rb for 128-bit block ciphers as defined in RFC 4493.
var rb = byte(0x87)

// cmac computes AES-CMAC per RFC 4493 for a message whose length is a
// multiple of the block size (16 bytes). For KCV computation the message
// is always 16 zero bytes, so partial-block padding is not needed.
func cmac(block cipher.Block, message []byte) []byte {
	k1 := generateSubkey(block)

	n := len(message) / block.BlockSize()
	if n == 0 {
		n = 1
	}
	lastBlock := message[(n-1)*block.BlockSize():]

	xored := make([]byte, block.BlockSize())
	for i := range xored {
		xored[i] = lastBlock[i] ^ k1[i]
	}

	x := make([]byte, block.BlockSize())
	for i := 0; i < n-1; i++ {
		start := i * block.BlockSize()
		for j := 0; j < block.BlockSize(); j++ {
			x[j] ^= message[start+j]
		}
		block.Encrypt(x, x)
	}

	for j := 0; j < block.BlockSize(); j++ {
		x[j] ^= xored[j]
	}
	block.Encrypt(x, x)

	return x
}

// generateSubkey derives the CMAC subkey K1 from the cipher block per RFC 4493.
func generateSubkey(block cipher.Block) []byte {
	l := make([]byte, block.BlockSize())
	block.Encrypt(l, l)

	k1 := leftShift(l)
	if l[0]&0x80 != 0 {
		k1[len(k1)-1] ^= rb
	}

	return k1
}

// leftShift performs a one-bit left shift on a byte slice.
func leftShift(input []byte) []byte {
	output := make([]byte, len(input))
	for i := 0; i < len(input)-1; i++ {
		output[i] = (input[i] << 1) | (input[i+1] >> 7)
	}
	output[len(input)-1] = input[len(input)-1] << 1
	return output
}
