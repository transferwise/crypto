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

// CreateCBCFromKeyBytes constructs a new AES CBC cipher using the raw key bytes provided, the raw bytes must be either 16, 24, or 32 bytes
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

// CreateCBCFromKeyString constructs a new AES CBC cipher using the hex-encoded key string provided
func CreateCBCFromKeyString(key string) (CBCCipher, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return CBCCipher{}, errors.New("AES key is not in correct hex format")
	}
	return CreateCBCFromKeyBytes(keyBytes)
}

// GenerateCBCIV returns a cryptographically random initialisation vector of one
// AES block, suitable for a single CBC encryption.
//
// NIST SP 800-38A requires the initialisation vector to be unpredictable, and a
// fresh one must be generated for every message encrypted under the same key.
// The initialisation vector need not be kept secret and may travel alongside the
// ciphertext, but it must be integrity protected together with the ciphertext;
// see CBCCipher.
//
// The name is deliberately distinct from the GCM nonce that Cipher generates
// internally: the two are not interchangeable.
func GenerateCBCIV() ([]byte, error) {
	iv, err := uuid.GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		return nil, errors.New("fail to generate IV")
	}
	return iv, nil
}
