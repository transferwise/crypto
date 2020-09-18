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
	"encoding/hex"
	"testing"

	"github.com/hashicorp/go-uuid"
)

func TestNewAESCipher_UseExistingKey(t *testing.T) {
	keyBytes, _ := uuid.GenerateRandomBytes(32)

	cipher, err := New(keyBytes)
	if err != nil {
		t.Errorf("Did not expect an error but got %q", err)
	}

	if hex.EncodeToString(cipher.KeyBytes) != hex.EncodeToString(keyBytes) {
		t.Errorf("Expected key %s but get %s", hex.EncodeToString(keyBytes), hex.EncodeToString(cipher.KeyBytes))
	}
}

func TestAESCipher_EncryptAndDecryptNotPrefixNonce(t *testing.T) {
	keyBytes, _ := uuid.GenerateRandomBytes(32)
	cipher, _ := New(keyBytes)

	testDatas := []string{
		"my secret 1234",
		"123456789",
	}

	for _, testData := range testDatas {
		cipherBytes, nonce, err := cipher.Encrypt([]byte(testData), false)
		if err != nil {
			t.Errorf("Did not expect an encryption error but got %q", err)
		}

		plainBytes, err := cipher.Decrypt(cipherBytes, nonce)
		if err != nil {
			t.Errorf("Did not expect a decryption error but got %q", err)
		}

		if testData != string(plainBytes) {
			t.Errorf("Expected %s but get %s", testData, string(plainBytes))
		}
	}
}

func TestAESCipher_EncryptAndDecryptPrefixNonce(t *testing.T) {
	keyBytes, _ := uuid.GenerateRandomBytes(32)
	cipher, _ := New(keyBytes)

	testDatas := []string{
		"my secret 1234",
		"123456789",
	}

	for _, testData := range testDatas {
		cipherBytes, _, err := cipher.Encrypt([]byte(testData), true)
		if err != nil {
			t.Errorf("Did not expect an encryption error but got %q", err)
		}

		plainBytes, err := cipher.Decrypt(cipherBytes, nil)
		if err != nil {
			t.Errorf("Did not expect a decryption error but got %q", err)
		}

		if testData != string(plainBytes) {
			t.Errorf("Expected %s but get %s", testData, string(plainBytes))
		}
	}
}
