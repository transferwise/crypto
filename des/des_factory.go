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
// Package des provides wrapper methods on top of the DES cipher for our own usage
package des

import (
	"crypto/des"
	"encoding/hex"
	"errors"
)

func CreateFromDESKeyBytes(keyBytes []byte) (Cipher, error) {
	if len(keyBytes) != 8 {
		return Cipher{}, errors.New("DES key must be 8 bytes")
	}

	keyBlock, err := des.NewCipher(keyBytes)
	if err != nil {
		return Cipher{}, errors.New("invalid DES keyBlock")
	}
	return Cipher{keyBlock, keyBytes}, nil
}

func CreateFromDESKeyString(key string) (Cipher, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return Cipher{}, errors.New("DES key is not in correct hex format")
	}
	return CreateFromDESKeyBytes(keyBytes)
}

func CreateFromTripleDESKeyBytes(keyBytes []byte) (Cipher, error) {
	if len(keyBytes) != 16 && len(keyBytes) != 24 {
		return Cipher{}, errors.New("3DES key must be either 16 or 24 bytes")
	}

	if len(keyBytes) == 16 {
		keyBytes = append(keyBytes[0:16], keyBytes[0:8]...)
	}

	keyBlock, err := des.NewTripleDESCipher(keyBytes)
	if err != nil {
		return Cipher{}, errors.New("invalid 3DES keyBlock")
	}
	return Cipher{keyBlock, keyBytes}, nil
}

func CreateFromTripleDESKeyString(key string) (Cipher, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return Cipher{}, errors.New("3DES key is not in correct hex format")
	}
	return CreateFromTripleDESKeyBytes(keyBytes)
}
