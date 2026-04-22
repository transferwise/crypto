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
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

func CreateFromKeyBytes(keyBytes []byte) (Cipher, error) {
	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		return Cipher{}, errors.New("AES key must be 16, 24, or 32 bytes")
	}

	aesCipher, err := aes.NewCipher(keyBytes)
	if err != nil {
		return Cipher{}, errors.New("invalid AES keyBlock")
	}

	gcmCipher, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return Cipher{}, errors.New("invalid AES GCM cipher")
	}

	return Cipher{gcmCipher, keyBytes}, nil
}

func CreateFromKeyString(key string) (Cipher, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return Cipher{}, errors.New("AES key is not in correct hex format")
	}
	return CreateFromKeyBytes(keyBytes)
}
