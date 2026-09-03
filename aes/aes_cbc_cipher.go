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

import (
	"crypto/cipher"
	"errors"
	"fmt"
)

// CBCCipher is a wrapper of the AES CBC cipher and stores the raw key bytes.
//
// CBC provides confidentiality only. Unlike Cipher, which wraps AES GCM, it is
// NOT authenticated:
//
//   - A modified initialisation vector or ciphertext will usually still decrypt
//     without error, producing attacker influenced plaintext. Decryption
//     succeeding is therefore no evidence that the message is genuine.
//   - Callers MUST authenticate the initialisation vector together with the
//     ciphertext by separate means, for example an HMAC over both, and MUST
//     verify it before decrypting.
//   - Reporting padding failures back to an untrusted caller exposes a padding
//     oracle, which can be used to recover plaintext.
//
// Prefer Cipher (AES GCM) unless an external protocol mandates CBC.
//
// The initialisation vector is always supplied by the caller and is never
// prefixed to, or stripped from, the ciphertext by this type. How the
// initialisation vector is transported or derived is a property of the
// surrounding protocol, so it is left to the caller.
type CBCCipher struct {
	block    cipher.Block
	KeyBytes []byte
}

// Encrypt encrypts plainBytes under the given initialisation vector without
// applying any padding. plainBytes must be a non-zero multiple of the AES block
// size; use EncryptISO9797M2Padded for arbitrary length input. iv must be
// exactly one AES block long, for every supported key size.
//
// Neither plainBytes nor iv is modified.
func (c *CBCCipher) Encrypt(plainBytes []byte, iv []byte) ([]byte, error) {
	blockSize := c.block.BlockSize()
	if err := validateIV(iv, blockSize); err != nil {
		return nil, err
	}
	if len(plainBytes) == 0 {
		return nil, errors.New("input is empty")
	}
	if len(plainBytes)%blockSize != 0 {
		return nil, fmt.Errorf("input length %d is not a multiplier of block size %d", len(plainBytes), blockSize)
	}

	cipherBytes := make([]byte, len(plainBytes))
	cipher.NewCBCEncrypter(c.block, cloneBytes(iv)).CryptBlocks(cipherBytes, plainBytes)
	return cipherBytes, nil
}

// Decrypt decrypts cipherBytes under the given initialisation vector without
// removing any padding. cipherBytes must be a non-zero multiple of the AES block
// size and iv must be exactly one AES block long.
//
// Decrypt does not, and cannot, detect modification of cipherBytes or iv. See
// CBCCipher for the caller's obligations.
//
// Neither cipherBytes nor iv is modified.
func (c *CBCCipher) Decrypt(cipherBytes []byte, iv []byte) ([]byte, error) {
	blockSize := c.block.BlockSize()
	if err := validateIV(iv, blockSize); err != nil {
		return nil, err
	}
	if len(cipherBytes) == 0 {
		return nil, errors.New("input is empty")
	}
	if len(cipherBytes)%blockSize != 0 {
		return nil, fmt.Errorf("input length %d is not a multiplier of block size %d", len(cipherBytes), blockSize)
	}

	plainBytes := make([]byte, len(cipherBytes))
	cipher.NewCBCDecrypter(c.block, cloneBytes(iv)).CryptBlocks(plainBytes, cipherBytes)
	return plainBytes, nil
}

// EncryptISO9797M2Padded applies ISO/IEC 9797-1 padding method 2 to plainBytes
// and encrypts the result, so plainBytes may be of any length, including empty.
// iv must be exactly one AES block long.
//
// The padding is a single 0x80 byte followed by zero filler to the block
// boundary, and at least one byte is always added. The same construction appears
// in ISO/IEC 7816-4 and is labelled "ISO2" by several card personalisation
// interfaces, including the aes-256-cbc-iso2 algorithm name used by the G+D CII
// data provider interface.
//
// Padding is a choice made by the surrounding protocol rather than a property of
// CBC. This method is named after its scheme so that a protocol requiring a
// different one, such as PKCS#7 or ISO 10126-2, cannot reach it by accident. Use
// Encrypt when the protocol pads by other means or not at all.
//
// Neither plainBytes nor iv is modified.
func (c *CBCCipher) EncryptISO9797M2Padded(plainBytes []byte, iv []byte) ([]byte, error) {
	blockSize := c.block.BlockSize()
	if err := validateIV(iv, blockSize); err != nil {
		return nil, err
	}

	return c.Encrypt(padISO9797M2(plainBytes, blockSize), iv)
}

// DecryptISO9797M2Padded decrypts cipherBytes and removes its ISO/IEC 9797-1
// padding method 2. cipherBytes must be a non-zero multiple of the AES block
// size and iv must be exactly one AES block long.
//
// A padding error is NOT an integrity check. A modified ciphertext can decrypt
// to well formed padding just as easily as to malformed padding, so a nil error
// says nothing about authenticity. Do not surface padding errors to untrusted
// callers; doing so exposes a padding oracle. See CBCCipher.
//
// Neither cipherBytes nor iv is modified.
func (c *CBCCipher) DecryptISO9797M2Padded(cipherBytes []byte, iv []byte) ([]byte, error) {
	paddedBytes, err := c.Decrypt(cipherBytes, iv)
	if err != nil {
		return nil, err
	}

	return unpadISO9797M2(paddedBytes, c.block.BlockSize())
}

// CheckValue returns the key check value of the underlying key. It is derived
// from the key alone and is identical to the value Cipher reports for the same
// key, being independent of the mode of operation.
func (c *CBCCipher) CheckValue() string {
	return deriveCheckValue(c.KeyBytes)
}

// VerifyCheckValue reports whether the given key check value matches the one
// derived from the underlying key. The comparison is case insensitive.
func (c *CBCCipher) VerifyCheckValue(checkValue string) bool {
	return verifyCheckValue(c.KeyBytes, checkValue)
}

func validateIV(iv []byte, blockSize int) error {
	if len(iv) != blockSize {
		return fmt.Errorf("IV must be %d bytes but got %d", blockSize, len(iv))
	}
	return nil
}

func cloneBytes(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}
