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
	stdaes "crypto/aes"
	"encoding/hex"
	"errors"
)

func CreateKeyFromBytes(keyBytes []byte, kcvMethod KCVMethod) (Key, error) {
	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		return Key{}, errors.New("AES key must be 16, 24, or 32 bytes")
	}

	keyBlock, err := stdaes.NewCipher(keyBytes)
	if err != nil {
		return Key{}, errors.New("invalid AES key")
	}
	return Key{keyBlock, keyBytes, kcvMethod}, nil
}

func CreateKeyFromString(key string, kcvMethod KCVMethod) (Key, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return Key{}, errors.New("AES key is not in correct hex format")
	}
	return CreateKeyFromBytes(keyBytes, kcvMethod)
}
