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
	"encoding/hex"
	"errors"

	"github.com/hashicorp/go-uuid"
)

// CreateCBCFromKeyBytes creates an AES-CBC cipher from a 16, 24, or 32-byte key.
func CreateCBCFromKeyBytes(keyBytes []byte) (CBCCipher, error) {
	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		return CBCCipher{}, errors.New("AES key must be 16, 24, or 32 bytes")
	}

	keyBlock, err := aes.NewCipher(keyBytes)
	if err != nil {
		return CBCCipher{}, errors.New("invalid AES keyBlock")
	}

	return CBCCipher{keyBlock, keyBytes}, nil
}

// CreateCBCFromKeyString creates an AES-CBC cipher from a hex-encoded key.
func CreateCBCFromKeyString(key string) (CBCCipher, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return CBCCipher{}, errors.New("AES key is not in correct hex format")
	}
	return CreateCBCFromKeyBytes(keyBytes)
}

// GenerateCBCIV returns a random 16-byte IV. Generate a new IV for each message.
func GenerateCBCIV() ([]byte, error) {
	iv, err := uuid.GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, errors.New("fail to generate IV")
	}
	return iv, nil
}
