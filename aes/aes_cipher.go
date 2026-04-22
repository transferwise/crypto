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

// Package aes provides wrapper methods on top of the AES GCM cipher for our own usage
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/hashicorp/go-uuid"
)

const checkValueBytes = 3

var keyCheckValuePlainText16Bytes = make([]byte, 16)

// Cipher is wrapper of the AES GCM cipher and stores the raw key bytes
type Cipher struct {
	gcm      cipher.AEAD
	KeyBytes []byte
}

func New(keyBytes []byte) (Cipher, error) {
	return CreateFromKeyBytes(keyBytes)
}

// Encrypt takes plain bytes and output cipher bytes, the nonce will be prefixed to
// cipher bytes if prefixNonce is true.
func (cipher *Cipher) Encrypt(plainBytes []byte, prefixNonce bool) ([]byte, []byte, error) {
	nonce, err := uuid.GenerateRandomBytes(cipher.gcm.NonceSize())
	if err != nil {
		return nil, nil, errors.New("fail to generate nonce")
	}

	cipherBytes := cipher.gcm.Seal(nil, nonce, plainBytes, nil)
	if prefixNonce {
		cipherBytes = append(nonce, cipherBytes...)
	}

	return cipherBytes, nonce, nil
}

// Decrypt takes cipher bytes and output plain bytes, it is assumed the nonce is prefixed
// to cipher bytes if its value is not being provided
func (cipher *Cipher) Decrypt(cipherBytes []byte, nonce []byte) ([]byte, error) {
	if nonce == nil {
		nonceSize := cipher.gcm.NonceSize()
		nonce, cipherBytes = cipherBytes[:nonceSize], cipherBytes[nonceSize:]
	}

	return cipher.gcm.Open(nil, nonce, cipherBytes, nil)
}

func (c *Cipher) CheckValue() string {
	block, err := aes.NewCipher(c.KeyBytes)
	if err != nil {
		return ""
	}
	cipherBytes := make([]byte, len(keyCheckValuePlainText16Bytes))
	block.Encrypt(cipherBytes, keyCheckValuePlainText16Bytes)
	return hex.EncodeToString(cipherBytes[:checkValueBytes])
}

func (c *Cipher) VerifyCheckValue(checkValue string) bool {
	return strings.EqualFold(c.CheckValue(), checkValue)
}
