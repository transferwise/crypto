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

// CBCCipher encrypts and decrypts data with AES-CBC.
//
// CBC does not authenticate data. Callers must authenticate the IV and
// ciphertext separately and must not expose padding errors to untrusted callers.
// The caller supplies the IV; CBCCipher does not include it in the ciphertext.
type CBCCipher struct {
	block    cipher.Block
	KeyBytes []byte
}

// Encrypt encrypts non-empty, block-aligned plainBytes with a 16-byte IV.
// It does not add padding or modify its inputs.
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

// Decrypt decrypts non-empty, block-aligned cipherBytes with a 16-byte IV.
// It does not remove padding or modify its inputs.
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

// EncryptISO9797M2Padded pads plainBytes with ISO/IEC 9797-1 method 2, then
// encrypts it with a 16-byte IV. It accepts empty input and does not modify its
// inputs.
func (c *CBCCipher) EncryptISO9797M2Padded(plainBytes []byte, iv []byte) ([]byte, error) {
	blockSize := c.block.BlockSize()
	if err := validateIV(iv, blockSize); err != nil {
		return nil, err
	}

	return c.Encrypt(padISO9797M2(plainBytes, blockSize), iv)
}

// DecryptISO9797M2Padded decrypts cipherBytes with a 16-byte IV, then removes
// ISO/IEC 9797-1 method 2 padding. It does not modify its inputs.
func (c *CBCCipher) DecryptISO9797M2Padded(cipherBytes []byte, iv []byte) ([]byte, error) {
	paddedBytes, err := c.Decrypt(cipherBytes, iv)
	if err != nil {
		return nil, err
	}

	return unpadISO9797M2(paddedBytes, c.block.BlockSize())
}

// CheckValue returns the AES key check value.
func (c *CBCCipher) CheckValue() string {
	return deriveCheckValue(c.KeyBytes)
}

// VerifyCheckValue reports whether checkValue matches the key, ignoring case.
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
