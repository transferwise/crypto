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
	"bytes"
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

func TestAESCheckValue(t *testing.T) {
	keyBytes, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	cipher, _ := New(keyBytes)

	checkValue := cipher.CheckValue()
	if checkValue != "7df76b" {
		t.Errorf("Expected check value 7df76b but got %s", checkValue)
	}
}

func TestAESVerifyCheckValue(t *testing.T) {
	keyBytes, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	cipher, _ := New(keyBytes)

	if !cipher.VerifyCheckValue("7df76b") {
		t.Error("Expected check value to verify successfully")
	}
	if !cipher.VerifyCheckValue("7DF76B") {
		t.Error("Expected check value verification to be case insensitive")
	}
	if cipher.VerifyCheckValue("abcdef") {
		t.Error("Expected wrong check value to fail verification")
	}
	if cipher.VerifyCheckValue("") {
		t.Error("Expected empty check value to fail verification")
	}
}

func TestAESCipher_KeyWrapAndUnwrap(t *testing.T) {
	kekBytes, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	cipher, _ := New(kekBytes)

	plainKeyBytes, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")

	wrapped, err := cipher.KeyWrap(plainKeyBytes)
	if err != nil {
		t.Fatalf("Did not expect a KeyWrap error but got %q", err)
	}

	unwrapped, err := cipher.KeyUnwrap(wrapped)
	if err != nil {
		t.Fatalf("Did not expect a KeyUnwrap error but got %q", err)
	}

	if !bytes.Equal(plainKeyBytes, unwrapped) {
		t.Errorf("Expected %s but got %s", hex.EncodeToString(plainKeyBytes), hex.EncodeToString(unwrapped))
	}
}

func TestAESCipher_KeyWrapRFC3394Vector(t *testing.T) {
	// RFC 3394 test vector: 256-bit KEK, 128-bit key data
	kekBytes, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	cipher, _ := New(kekBytes)

	plainKeyBytes, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	expectedWrapped, _ := hex.DecodeString("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")

	wrapped, err := cipher.KeyWrap(plainKeyBytes)
	if err != nil {
		t.Fatalf("Did not expect a KeyWrap error but got %q", err)
	}

	if !bytes.Equal(wrapped, expectedWrapped) {
		t.Errorf("Expected wrapped %s but got %s", hex.EncodeToString(expectedWrapped), hex.EncodeToString(wrapped))
	}
}

func TestAESCipher_KeyUnwrapInvalidData(t *testing.T) {
	kekBytes, _ := uuid.GenerateRandomBytes(32)
	cipher, _ := New(kekBytes)

	badData := make([]byte, 24)
	_, err := cipher.KeyUnwrap(badData)
	if err == nil {
		t.Error("Expected an error for invalid wrapped data")
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
